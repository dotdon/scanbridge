//! ClamAV scanning backend.
//!
//! This module provides a scanner implementation that communicates with
//! ClamAV via its socket protocol (clamd).
//!
//! # Requirements
//!
//! - ClamAV daemon (clamd) must be running
//! - Access to the clamd socket (Unix socket or TCP)
//!
//! # Protocol
//!
//! Uses the INSTREAM command to send file data for scanning.

use crate::core::{
    FileHash, FileHasher, FileInput, FileMetadata, ScanContext, ScanError, ScanOutcome,
    ScanResult, Scanner, ThreatInfo, ThreatSeverity,
};

use async_trait::async_trait;
use std::path::PathBuf;
use std::time::Duration;

/// ClamAV scanner configuration.
#[derive(Debug, Clone)]
pub struct ClamAvConfig {
    /// Path to the Unix socket.
    pub socket_path: Option<PathBuf>,

    /// TCP host and port (alternative to socket).
    pub tcp_address: Option<String>,

    /// Connection timeout.
    pub connection_timeout: Duration,

    /// Scan timeout.
    pub scan_timeout: Duration,

    /// Maximum file size to send.
    pub max_file_size: u64,
}

impl Default for ClamAvConfig {
    fn default() -> Self {
        Self {
            socket_path: Some(PathBuf::from("/var/run/clamav/clamd.sock")),
            tcp_address: None,
            connection_timeout: Duration::from_secs(10),
            scan_timeout: Duration::from_secs(300),
            max_file_size: 100 * 1024 * 1024, // 100 MB
        }
    }
}

impl ClamAvConfig {
    /// Creates a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Uses a Unix socket.
    pub fn with_socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.socket_path = Some(path.into());
        self.tcp_address = None;
        self
    }

    /// Uses a TCP connection.
    pub fn with_tcp(mut self, address: impl Into<String>) -> Self {
        self.tcp_address = Some(address.into());
        self.socket_path = None;
        self
    }

    /// Sets the connection timeout.
    pub fn with_connection_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Sets the scan timeout.
    pub fn with_scan_timeout(mut self, timeout: Duration) -> Self {
        self.scan_timeout = timeout;
        self
    }

    /// Sets the maximum file size.
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }
}

/// ClamAV scanner implementation.
///
/// Communicates with the ClamAV daemon using the INSTREAM protocol.
///
/// # Example
///
/// ```rust,ignore
/// use scanbridge::backends::ClamAvScanner;
/// use scanbridge::backends::clamav::ClamAvConfig;
///
/// let config = ClamAvConfig::new()
///     .with_socket("/var/run/clamav/clamd.sock");
///
/// let scanner = ClamAvScanner::new(config)?;
/// ```
#[derive(Debug)]
pub struct ClamAvScanner {
    config: ClamAvConfig,
    hasher: FileHasher,
}

impl ClamAvScanner {
    /// Creates a new ClamAV scanner with the given configuration.
    pub fn new(config: ClamAvConfig) -> Result<Self, ScanError> {
        if config.socket_path.is_none() && config.tcp_address.is_none() {
            return Err(ScanError::configuration(
                "Either socket_path or tcp_address must be specified",
            ));
        }

        Ok(Self {
            config,
            hasher: FileHasher::new(),
        })
    }

    /// Creates a ClamAV scanner with default configuration.
    pub fn with_defaults() -> Result<Self, ScanError> {
        Self::new(ClamAvConfig::default())
    }

    /// Parses a ClamAV response into a scan outcome.
    fn parse_response(&self, response: &str) -> ScanOutcome {
        let response = response.trim();

        if response.ends_with("OK") {
            ScanOutcome::Clean
        } else if response.contains("FOUND") {
            // Parse threat name from response like "stream: Eicar-Test-Signature FOUND"
            let threat_name = response
                .split(':')
                .nth(1)
                .and_then(|s| s.strip_suffix("FOUND"))
                .map(|s| s.trim())
                .unwrap_or("Unknown")
                .to_string();

            ScanOutcome::Infected {
                threats: vec![ThreatInfo::new(threat_name, ThreatSeverity::High, "clamav")],
            }
        } else if response.contains("ERROR") {
            ScanOutcome::Error { recoverable: true }
        } else {
            ScanOutcome::Suspicious {
                reason: format!("Unexpected response: {}", response),
                confidence: 0.5,
            }
        }
    }

    /// Reads file data from input.
    async fn read_file_data(&self, input: &FileInput) -> Result<Vec<u8>, ScanError> {
        match input {
            FileInput::Path(path) => {
                #[cfg(feature = "tokio-runtime")]
                {
                    tokio::fs::read(path).await.map_err(ScanError::Io)
                }
                #[cfg(not(feature = "tokio-runtime"))]
                {
                    std::fs::read(path).map_err(ScanError::Io)
                }
            }
            FileInput::Bytes { data, .. } => Ok(data.clone()),
            FileInput::Stream { .. } => Err(ScanError::internal(
                "ClamAV scanner does not yet support streaming input",
            )),
        }
    }

    /// Sends data to ClamAV using INSTREAM protocol.
    #[cfg(feature = "tokio-runtime")]
    async fn scan_data(&self, data: &[u8]) -> Result<String, ScanError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Connect to ClamAV
        let mut stream = if let Some(ref socket_path) = self.config.socket_path {
            #[cfg(unix)]
            {
                tokio::net::UnixStream::connect(socket_path)
                    .await
                    .map_err(|e| ScanError::connection_failed("clamav", e.to_string()))?
            }
            #[cfg(not(unix))]
            {
                return Err(ScanError::configuration(
                    "Unix sockets not supported on this platform",
                ));
            }
        } else if let Some(ref tcp_addr) = self.config.tcp_address {
            return Err(ScanError::internal("TCP connection not yet implemented"));
        } else {
            return Err(ScanError::configuration("No connection method configured"));
        };

        // Send INSTREAM command
        #[cfg(unix)]
        {
            stream
                .write_all(b"zINSTREAM\0")
                .await
                .map_err(|e| ScanError::connection_failed("clamav", e.to_string()))?;

            // Send data in chunks
            let chunk_size = 2048;
            for chunk in data.chunks(chunk_size) {
                let len = chunk.len() as u32;
                stream
                    .write_all(&len.to_be_bytes())
                    .await
                    .map_err(|e| ScanError::connection_failed("clamav", e.to_string()))?;
                stream
                    .write_all(chunk)
                    .await
                    .map_err(|e| ScanError::connection_failed("clamav", e.to_string()))?;
            }

            // Send zero-length chunk to end stream
            stream
                .write_all(&0u32.to_be_bytes())
                .await
                .map_err(|e| ScanError::connection_failed("clamav", e.to_string()))?;

            // Read response
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .map_err(|e| ScanError::connection_failed("clamav", e.to_string()))?;

            Ok(response)
        }
    }

    #[cfg(not(feature = "tokio-runtime"))]
    async fn scan_data(&self, _data: &[u8]) -> Result<String, ScanError> {
        Err(ScanError::internal(
            "ClamAV scanner requires tokio-runtime feature",
        ))
    }
}

#[async_trait]
impl Scanner for ClamAvScanner {
    fn name(&self) -> &str {
        "clamav"
    }

    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
        let start = std::time::Instant::now();

        // Read file data
        let data = self.read_file_data(input).await?;

        // Check file size
        if data.len() as u64 > self.config.max_file_size {
            return Err(ScanError::FileTooLarge {
                size: data.len() as u64,
                max: self.config.max_file_size,
            });
        }

        // Compute hash
        let hash = self.hasher.hash_bytes(&data);

        // Scan with ClamAV
        let response = self.scan_data(&data).await?;

        // Parse response
        let outcome = self.parse_response(&response);

        let duration = start.elapsed();
        let metadata = FileMetadata::new(data.len() as u64, hash)
            .with_filename(input.filename().unwrap_or("unknown").to_string());

        Ok(ScanResult::new(
            outcome,
            metadata,
            "clamav",
            duration,
            ScanContext::new(),
        ))
    }

    async fn health_check(&self) -> Result<(), ScanError> {
        // Send PING command
        #[cfg(all(feature = "tokio-runtime", unix))]
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};

            if let Some(ref socket_path) = self.config.socket_path {
                let mut stream = tokio::net::UnixStream::connect(socket_path)
                    .await
                    .map_err(|e| ScanError::connection_failed("clamav", e.to_string()))?;

                stream
                    .write_all(b"zPING\0")
                    .await
                    .map_err(|e| ScanError::connection_failed("clamav", e.to_string()))?;

                let mut response = String::new();
                stream
                    .read_to_string(&mut response)
                    .await
                    .map_err(|e| ScanError::connection_failed("clamav", e.to_string()))?;

                if response.trim() == "PONG" {
                    return Ok(());
                } else {
                    return Err(ScanError::engine_unavailable(
                        "clamav",
                        format!("Unexpected response: {}", response),
                    ));
                }
            }
        }

        Err(ScanError::engine_unavailable(
            "clamav",
            "Health check not available",
        ))
    }

    fn max_file_size(&self) -> Option<u64> {
        Some(self.config.max_file_size)
    }

    async fn signature_version(&self) -> Option<String> {
        // Could implement VERSION command
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_response_clean() {
        let config = ClamAvConfig::new();
        let scanner = ClamAvScanner { config, hasher: FileHasher::new() };

        let outcome = scanner.parse_response("stream: OK");
        assert!(outcome.is_clean());
    }

    #[test]
    fn test_parse_response_infected() {
        let config = ClamAvConfig::new();
        let scanner = ClamAvScanner { config, hasher: FileHasher::new() };

        let outcome = scanner.parse_response("stream: Eicar-Test-Signature FOUND");
        assert!(outcome.is_infected());
    }

    #[test]
    fn test_config_builder() {
        let config = ClamAvConfig::new()
            .with_socket("/custom/path.sock")
            .with_scan_timeout(Duration::from_secs(60));

        assert_eq!(
            config.socket_path,
            Some(PathBuf::from("/custom/path.sock"))
        );
        assert_eq!(config.scan_timeout, Duration::from_secs(60));
    }
}

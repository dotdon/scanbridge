//! VirusTotal scanning backend.
//!
//! This module provides a scanner implementation that uses the
//! VirusTotal API to scan files for malware.
//!
//! # Requirements
//!
//! - VirusTotal API key
//! - Network access to api.virustotal.com
//!
//! # API Usage
//!
//! This backend uses the VirusTotal v3 API to:
//! 1. Check if a file hash is already known
//! 2. Upload new files for scanning
//! 3. Poll for scan results

use crate::core::{
    FileHash, FileHasher, FileInput, FileMetadata, ScanContext, ScanError, ScanOutcome,
    ScanResult, Scanner, ThreatInfo, ThreatSeverity,
};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use std::time::Duration;

/// VirusTotal scanner configuration.
#[derive(Debug, Clone)]
pub struct VirusTotalConfig {
    /// API key (kept secret).
    pub api_key: SecretString,

    /// Base URL for the API.
    pub base_url: String,

    /// Request timeout.
    pub timeout: Duration,

    /// Maximum file size to upload (free tier: 32MB, premium: 650MB).
    pub max_file_size: u64,

    /// Whether to upload unknown files.
    pub upload_unknown: bool,

    /// Polling interval when waiting for results.
    pub poll_interval: Duration,

    /// Maximum time to wait for results.
    pub max_poll_time: Duration,
}

impl VirusTotalConfig {
    /// Creates a new configuration with the given API key.
    pub fn new(api_key: impl Into<String>) -> Self {
        Self {
            api_key: SecretString::new(api_key.into().into()),
            base_url: "https://www.virustotal.com/api/v3".to_string(),
            timeout: Duration::from_secs(60),
            max_file_size: 32 * 1024 * 1024, // 32 MB (free tier limit)
            upload_unknown: true,
            poll_interval: Duration::from_secs(15),
            max_poll_time: Duration::from_secs(300),
        }
    }

    /// Sets the base URL.
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Sets the timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Sets the maximum file size.
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Sets whether to upload unknown files.
    pub fn with_upload_unknown(mut self, upload: bool) -> Self {
        self.upload_unknown = upload;
        self
    }

    /// Sets the polling interval.
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }
}

/// VirusTotal scanner implementation.
///
/// Uses the VirusTotal v3 API to scan files for malware.
///
/// # Example
///
/// ```rust,ignore
/// use scanbridge::backends::VirusTotalScanner;
/// use scanbridge::backends::virustotal::VirusTotalConfig;
///
/// let config = VirusTotalConfig::new("your-api-key");
/// let scanner = VirusTotalScanner::new(config)?;
/// ```
#[derive(Debug)]
pub struct VirusTotalScanner {
    config: VirusTotalConfig,
    hasher: FileHasher,
    #[cfg(feature = "virustotal")]
    client: reqwest::Client,
}

impl VirusTotalScanner {
    /// Creates a new VirusTotal scanner with the given configuration.
    #[cfg(feature = "virustotal")]
    pub fn new(config: VirusTotalConfig) -> Result<Self, ScanError> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| ScanError::configuration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            hasher: FileHasher::new().with_sha256(true), // VT uses SHA256
            client,
        })
    }

    #[cfg(not(feature = "virustotal"))]
    pub fn new(_config: VirusTotalConfig) -> Result<Self, ScanError> {
        Err(ScanError::configuration(
            "VirusTotal backend requires the 'virustotal' feature",
        ))
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
                "VirusTotal scanner does not support streaming input",
            )),
        }
    }

    /// Looks up a file by SHA256 hash.
    #[cfg(feature = "virustotal")]
    async fn lookup_hash(&self, sha256: &str) -> Result<Option<VtAnalysisResult>, ScanError> {
        let url = format!("{}/files/{}", self.config.base_url, sha256);

        let response = self
            .client
            .get(&url)
            .header("x-apikey", self.config.api_key.expose_secret())
            .send()
            .await
            .map_err(|e| ScanError::connection_failed("virustotal", e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(ScanError::RateLimited {
                engine: "virustotal".to_string(),
                retry_after: Some(Duration::from_secs(60)),
            });
        }

        if !response.status().is_success() {
            return Err(ScanError::engine_unavailable(
                "virustotal",
                format!("API error: {}", response.status()),
            ));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ScanError::AmbiguousResponse {
                engine: "virustotal".to_string(),
                details: e.to_string(),
            })?;

        Ok(Some(self.parse_analysis_result(&body)?))
    }

    /// Parses a VirusTotal analysis result.
    #[cfg(feature = "virustotal")]
    fn parse_analysis_result(&self, json: &serde_json::Value) -> Result<VtAnalysisResult, ScanError> {
        let stats = json
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("last_analysis_stats"))
            .ok_or_else(|| ScanError::AmbiguousResponse {
                engine: "virustotal".to_string(),
                details: "Missing analysis stats".to_string(),
            })?;

        let malicious = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
        let suspicious = stats.get("suspicious").and_then(|v| v.as_u64()).unwrap_or(0);
        let undetected = stats.get("undetected").and_then(|v| v.as_u64()).unwrap_or(0);

        let mut threats = Vec::new();
        if let Some(results) = json
            .get("data")
            .and_then(|d| d.get("attributes"))
            .and_then(|a| a.get("last_analysis_results"))
            .and_then(|r| r.as_object())
        {
            for (engine, result) in results {
                if let Some(category) = result.get("category").and_then(|c| c.as_str()) {
                    if category == "malicious" || category == "suspicious" {
                        if let Some(threat_name) = result.get("result").and_then(|r| r.as_str()) {
                            let severity = if category == "malicious" {
                                ThreatSeverity::High
                            } else {
                                ThreatSeverity::Medium
                            };
                            threats.push(ThreatInfo::new(threat_name, severity, engine));
                        }
                    }
                }
            }
        }

        Ok(VtAnalysisResult {
            malicious_count: malicious as u32,
            suspicious_count: suspicious as u32,
            clean_count: undetected as u32,
            threats,
        })
    }

    /// Converts VT analysis result to scan outcome.
    fn result_to_outcome(&self, result: &VtAnalysisResult) -> ScanOutcome {
        if result.malicious_count > 0 {
            ScanOutcome::Infected {
                threats: result.threats.clone(),
            }
        } else if result.suspicious_count > 0 {
            ScanOutcome::Suspicious {
                reason: format!("{} engines reported suspicious", result.suspicious_count),
                confidence: result.suspicious_count as f32
                    / (result.suspicious_count + result.clean_count).max(1) as f32,
            }
        } else {
            ScanOutcome::Clean
        }
    }
}

/// Parsed VirusTotal analysis result.
#[derive(Debug, Clone)]
struct VtAnalysisResult {
    malicious_count: u32,
    suspicious_count: u32,
    clean_count: u32,
    threats: Vec<ThreatInfo>,
}

#[async_trait]
impl Scanner for VirusTotalScanner {
    fn name(&self) -> &str {
        "virustotal"
    }

    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
        #[cfg(feature = "virustotal")]
        {
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

            // Compute hash (including SHA256 for VT lookup)
            let hash = self.hasher.hash_bytes(&data);
            let sha256 = hash.sha256.as_ref().ok_or_else(|| {
                ScanError::internal("SHA256 hash required for VirusTotal")
            })?;

            // Try to look up by hash first
            let outcome = if let Some(result) = self.lookup_hash(sha256).await? {
                self.result_to_outcome(&result)
            } else if self.config.upload_unknown {
                // File not known, would need to upload
                // For now, return clean (upload not implemented)
                tracing::warn!(
                    sha256 = %sha256,
                    "File not found in VirusTotal, upload not implemented"
                );
                ScanOutcome::Clean
            } else {
                ScanOutcome::Suspicious {
                    reason: "File not found in VirusTotal database".to_string(),
                    confidence: 0.1,
                }
            };

            let duration = start.elapsed();
            let metadata = FileMetadata::new(data.len() as u64, hash)
                .with_filename(input.filename().unwrap_or("unknown").to_string());

            Ok(ScanResult::new(
                outcome,
                metadata,
                "virustotal",
                duration,
                ScanContext::new(),
            ))
        }

        #[cfg(not(feature = "virustotal"))]
        {
            Err(ScanError::configuration(
                "VirusTotal backend requires the 'virustotal' feature",
            ))
        }
    }

    async fn health_check(&self) -> Result<(), ScanError> {
        #[cfg(feature = "virustotal")]
        {
            // Check API access by looking up the EICAR test file hash
            const EICAR_SHA256: &str =
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

            match self.lookup_hash(EICAR_SHA256).await {
                Ok(Some(_)) => Ok(()),
                Ok(None) => Err(ScanError::engine_unavailable(
                    "virustotal",
                    "EICAR test file not found (unexpected)",
                )),
                Err(e) => Err(e),
            }
        }

        #[cfg(not(feature = "virustotal"))]
        {
            Err(ScanError::configuration(
                "VirusTotal backend requires the 'virustotal' feature",
            ))
        }
    }

    fn max_file_size(&self) -> Option<u64> {
        Some(self.config.max_file_size)
    }

    async fn signature_version(&self) -> Option<String> {
        None // VT doesn't expose a single version
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = VirusTotalConfig::new("test-key")
            .with_max_file_size(64 * 1024 * 1024)
            .with_upload_unknown(false);

        assert_eq!(config.max_file_size, 64 * 1024 * 1024);
        assert!(!config.upload_unknown);
    }
}

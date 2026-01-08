# Adding a New Backend

This guide walks through implementing a custom scanning backend for Scanbridge.

## Overview

To add a new scanning engine, you need to:

1. Create a struct to hold configuration and state
2. Implement the `Scanner` trait
3. Handle errors appropriately
4. (Optional) Add circuit breaker support
5. (Optional) Add to the library as a feature

## The Scanner Trait

```rust
#[async_trait]
pub trait Scanner: Send + Sync + Debug {
    /// Returns the unique name of this scanner.
    fn name(&self) -> &str;

    /// Scans a file and returns the result.
    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError>;

    /// Performs a lightweight health check.
    async fn health_check(&self) -> Result<(), ScanError>;

    /// Optional: maximum file size this scanner accepts.
    fn max_file_size(&self) -> Option<u64> { None }

    /// Optional: signature database version.
    async fn signature_version(&self) -> Option<String> { None }

    /// Optional: whether streaming input is supported.
    fn supports_streaming(&self) -> bool { false }
}
```

## Step-by-Step Example

Let's implement a scanner that checks files against a threat intelligence feed.

### Step 1: Define the Struct

```rust
use scanbridge::prelude::*;
use async_trait::async_trait;

/// Configuration for the threat intel scanner.
#[derive(Debug, Clone)]
pub struct ThreatIntelConfig {
    pub api_url: String,
    pub api_key: secrecy::SecretString,
    pub timeout: std::time::Duration,
    pub max_file_size: u64,
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            api_url: "https://api.threatintel.example.com/v1".into(),
            api_key: secrecy::SecretString::new("".into()),
            timeout: std::time::Duration::from_secs(30),
            max_file_size: 100 * 1024 * 1024, // 100 MB
        }
    }
}

/// A scanner that checks file hashes against a threat intelligence API.
#[derive(Debug)]
pub struct ThreatIntelScanner {
    config: ThreatIntelConfig,
    client: reqwest::Client,
    hasher: FileHasher,
}
```

### Step 2: Implement Constructor

```rust
impl ThreatIntelScanner {
    pub fn new(config: ThreatIntelConfig) -> Result<Self, ScanError> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| ScanError::configuration(format!(
                "Failed to create HTTP client: {}", e
            )))?;

        Ok(Self {
            config,
            client,
            // Enable SHA256 for API compatibility
            hasher: FileHasher::new().with_sha256(true),
        })
    }
}
```

### Step 3: Implement the Scanner Trait

```rust
#[async_trait]
impl Scanner for ThreatIntelScanner {
    fn name(&self) -> &str {
        "threat-intel"
    }

    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
        use std::time::Instant;
        let start = Instant::now();

        // 1. Read and hash the file
        let data = self.read_file(input).await?;
        
        if data.len() as u64 > self.config.max_file_size {
            return Err(ScanError::FileTooLarge {
                size: data.len() as u64,
                max: self.config.max_file_size,
            });
        }

        let hash = self.hasher.hash_bytes(&data);

        // 2. Query the threat intel API
        let outcome = self.query_api(&hash).await?;

        // 3. Build the result
        let duration = start.elapsed();
        let metadata = FileMetadata::new(data.len() as u64, hash)
            .with_filename(input.filename().unwrap_or("unknown").to_string());

        Ok(ScanResult::new(
            outcome,
            metadata,
            self.name(),
            duration,
            ScanContext::new(),
        ))
    }

    async fn health_check(&self) -> Result<(), ScanError> {
        // Check API is reachable with a simple request
        let url = format!("{}/health", self.config.api_url);
        
        let response = self.client
            .get(&url)
            .header("X-API-Key", self.config.api_key.expose_secret())
            .send()
            .await
            .map_err(|e| ScanError::connection_failed(self.name(), e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(ScanError::engine_unavailable(
                self.name(),
                format!("Health check failed: {}", response.status()),
            ))
        }
    }

    fn max_file_size(&self) -> Option<u64> {
        Some(self.config.max_file_size)
    }
}
```

### Step 4: Implement Helper Methods

```rust
impl ThreatIntelScanner {
    async fn read_file(&self, input: &FileInput) -> Result<Vec<u8>, ScanError> {
        match input {
            FileInput::Path(path) => {
                tokio::fs::read(path)
                    .await
                    .map_err(ScanError::Io)
            }
            FileInput::Bytes { data, .. } => Ok(data.clone()),
            FileInput::Stream { .. } => {
                Err(ScanError::internal("Streaming not supported"))
            }
        }
    }

    async fn query_api(&self, hash: &FileHash) -> Result<ScanOutcome, ScanError> {
        use secrecy::ExposeSecret;

        let sha256 = hash.sha256.as_ref().ok_or_else(|| {
            ScanError::internal("SHA256 required for threat intel API")
        })?;

        let url = format!("{}/lookup/{}", self.config.api_url, sha256);

        let response = self.client
            .get(&url)
            .header("X-API-Key", self.config.api_key.expose_secret())
            .send()
            .await
            .map_err(|e| ScanError::connection_failed(self.name(), e.to_string()))?;

        match response.status() {
            s if s.is_success() => {
                let body: serde_json::Value = response.json().await
                    .map_err(|e| ScanError::AmbiguousResponse {
                        engine: self.name().into(),
                        details: e.to_string(),
                    })?;

                self.parse_response(&body)
            }
            reqwest::StatusCode::NOT_FOUND => {
                // Hash not in database = clean
                Ok(ScanOutcome::Clean)
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                Err(ScanError::RateLimited {
                    engine: self.name().into(),
                    retry_after: Some(std::time::Duration::from_secs(60)),
                })
            }
            s => {
                Err(ScanError::engine_unavailable(
                    self.name(),
                    format!("API returned {}", s),
                ))
            }
        }
    }

    fn parse_response(&self, json: &serde_json::Value) -> Result<ScanOutcome, ScanError> {
        let is_malicious = json.get("malicious")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if is_malicious {
            let threat_name = json.get("threat_name")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown");

            let severity = match json.get("severity").and_then(|v| v.as_str()) {
                Some("critical") => ThreatSeverity::Critical,
                Some("high") => ThreatSeverity::High,
                Some("medium") => ThreatSeverity::Medium,
                _ => ThreatSeverity::Low,
            };

            Ok(ScanOutcome::Infected {
                threats: vec![
                    ThreatInfo::new(threat_name, severity, self.name())
                ],
            })
        } else {
            Ok(ScanOutcome::Clean)
        }
    }
}
```

### Step 5: Handle Errors Properly

Map all external errors to `ScanError` variants:

| External Error | ScanError Variant |
|---------------|-------------------|
| Network timeout | `Timeout` |
| Connection refused | `ConnectionFailed` |
| HTTP 401/403 | `AuthenticationFailed` |
| HTTP 429 | `RateLimited` |
| HTTP 5xx | `EngineUnavailable` |
| Invalid response | `AmbiguousResponse` |
| File too large | `FileTooLarge` |
| I/O errors | `Io` |

### Step 6: Use with Circuit Breaker

```rust
use scanbridge::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};

let scanner = ThreatIntelScanner::new(config)?;
let protected = CircuitBreaker::new(
    scanner,
    CircuitBreakerConfig::default(),
);

// Now protected can be used with ScanManager
let manager = ScanManager::builder()
    .add_scanner(protected)
    .build()?;
```

## Testing Your Scanner

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check_success() {
        // Set up mock server
        let mock_server = mockito::Server::new();
        let _m = mock_server.mock("GET", "/health")
            .with_status(200)
            .create();

        let config = ThreatIntelConfig {
            api_url: mock_server.url(),
            ..Default::default()
        };

        let scanner = ThreatIntelScanner::new(config).unwrap();
        assert!(scanner.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_scan_clean_file() {
        // Test scanning returns Clean for unknown hash
    }

    #[tokio::test]
    async fn test_scan_malicious_file() {
        // Test scanning returns Infected for known-bad hash
    }
}
```

### Integration Tests

```rust
#[tokio::test]
#[ignore] // Run with: cargo test -- --ignored
async fn test_real_api() {
    let config = ThreatIntelConfig {
        api_key: std::env::var("THREAT_INTEL_API_KEY")
            .expect("Set THREAT_INTEL_API_KEY")
            .into(),
        ..Default::default()
    };

    let scanner = ThreatIntelScanner::new(config).unwrap();
    
    // Test with EICAR test file
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let input = FileInput::from_bytes(eicar.to_vec());
    
    let result = scanner.scan(&input).await.unwrap();
    assert!(result.is_infected());
}
```

## Adding as a Library Feature

If contributing to the main library:

### 1. Add Feature Flag

In `Cargo.toml`:

```toml
[features]
threat-intel = ["reqwest"]
```

### 2. Create Module

Create `src/backends/threat_intel.rs`

### 3. Update mod.rs

```rust
#[cfg(feature = "threat-intel")]
pub mod threat_intel;

#[cfg(feature = "threat-intel")]
pub use threat_intel::ThreatIntelScanner;
```

### 4. Document

- Add to README.md feature table
- Add usage example
- Document configuration options

## Checklist

Before considering your backend complete:

- [ ] Implements all required `Scanner` trait methods
- [ ] Returns appropriate `ScanError` variants
- [ ] Has configurable timeouts
- [ ] Respects max file size
- [ ] Handles rate limiting gracefully
- [ ] Has a working health check
- [ ] Has unit tests
- [ ] Has integration tests (can be `#[ignore]`)
- [ ] Documented configuration options
- [ ] No panics in normal operation
- [ ] Secrets handled securely (use `secrecy` crate)

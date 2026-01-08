# Scanbridge

A unified, pluggable API for malware scanning in Rust.

Scanbridge provides an abstraction layer over multiple malware scanning engines, with built-in resilience patterns, policy enforcement, quarantine support, and compliance-ready audit logging.

## Features

- **Pluggable Architecture**: Easily swap or combine scanning backends (ClamAV, VirusTotal, custom implementations)
- **Circuit Breakers**: Prevent cascading failures when backends become unhealthy
- **Policy Engine**: Configurable rules for handling scan results (block, quarantine, allow with warning)
- **Quarantine Storage**: Safely store and track infected files
- **Audit Logging**: Structured events via `tracing` for compliance environments
- **BLAKE3 Hashing**: Fast deduplication with cryptographic security
- **Runtime Agnostic**: Works with any async runtime (designed for tokio)

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
scanbridge = "0.1"
tokio = { version = "1", features = ["full"] }
```

Basic usage:

```rust
use scanbridge::prelude::*;
use scanbridge::backends::MockScanner;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a scanner
    let scanner = MockScanner::new_clean();
    
    // Build the scan manager
    let manager = ScanManager::builder()
        .add_scanner(scanner)
        .build()?;
    
    // Scan a file
    let input = FileInput::from_bytes(b"file content".to_vec());
    let context = ScanContext::new().with_tenant_id("my-tenant");
    let report = manager.scan(input, context).await?;
    
    if report.is_clean() {
        println!("File is clean!");
    } else if report.is_infected() {
        println!("Threats detected: {:?}", report.all_threats());
    }
    
    Ok(())
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ScanManager                               │
│  Orchestrates scans, handles retries, manages multiple engines  │
└────────────────────────────┬────────────────────────────────────┘
                             │
         ┌───────────────────┼───────────────────┐
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ CircuitBreaker  │ │ CircuitBreaker  │ │ CircuitBreaker  │
│   (optional)    │ │   (optional)    │ │   (optional)    │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
         │                   │                   │
         ▼                   ▼                   ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│    ClamAV       │ │   VirusTotal    │ │  CustomScanner  │
│    Backend      │ │    Backend      │ │     Backend     │
└─────────────────┘ └─────────────────┘ └─────────────────┘
```

## Scan Outcomes

Every scan returns one of four outcomes:

| Outcome | Description |
|---------|-------------|
| `Clean` | No threats detected |
| `Infected` | One or more threats found |
| `Suspicious` | Potentially harmful but not definitive |
| `Error` | Scan could not complete |

## Circuit Breaker

The circuit breaker prevents cascading failures when a scanner becomes unhealthy:

```rust
use scanbridge::circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use std::time::Duration;

let config = CircuitBreakerConfig::default()
    .with_failure_threshold(5)           // Open after 5 failures
    .with_open_duration(Duration::from_secs(30))  // Stay open 30s
    .with_success_threshold(3);          // Close after 3 successes

let protected = CircuitBreaker::new(scanner, config);
```

### States

- **Closed**: Normal operation, requests pass through
- **Open**: Backend failing, requests rejected immediately
- **Half-Open**: Probing with limited requests to check recovery

### Fallback Behaviors

- `FailClosed`: Reject scans when circuit is open (safest)
- `FailOpen`: Allow files through with warning (most available)
- `Fallback(scanner)`: Use alternate scanner when primary fails

## Policy Engine

Define rules for handling scan results:

```rust
use scanbridge::policy::{PolicyEngine, PolicyRule, Condition, PolicyAction};

let policy = PolicyEngine::new()
    .with_rule(
        PolicyRule::new("block-infected", PolicyAction::block("Malware detected"))
            .with_condition(Condition::is_infected())
            .with_priority(100)
    )
    .with_rule(
        PolicyRule::new("quarantine-suspicious", PolicyAction::quarantine("Review needed"))
            .with_condition(Condition::is_suspicious())
            .with_priority(90)
    );
```

## Quarantine

Safely store infected files:

```rust
use scanbridge::quarantine::FilesystemQuarantine;

let quarantine = FilesystemQuarantine::new("/var/quarantine")?;

// Files are stored with integrity verification
// and can be retrieved, listed, or deleted
```

## Audit Logging

All scan events are emitted via `tracing` at the `scanbridge::audit` target:

```rust
use tracing_subscriber::fmt::format::FmtSpan;

// Configure a JSON subscriber for compliance logging
tracing_subscriber::fmt()
    .json()
    .with_target(true)
    .init();
```

Events include:
- `scan_started` / `scan_completed`
- `policy_decision`
- `quarantine_operation`

## Adding a Custom Backend

Implement the `Scanner` trait:

```rust
use scanbridge::prelude::*;
use async_trait::async_trait;

#[derive(Debug)]
struct MyScanner { /* ... */ }

#[async_trait]
impl Scanner for MyScanner {
    fn name(&self) -> &str { "my-scanner" }

    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError> {
        // Your scanning logic here
        todo!()
    }

    async fn health_check(&self) -> Result<(), ScanError> {
        // Verify scanner is operational
        Ok(())
    }
}
```

See `examples/custom_backend.rs` for a complete example.

## Feature Flags

| Feature | Description | Default |
|---------|-------------|---------|
| `tokio-runtime` | Tokio async runtime support | ✓ |
| `clamav` | ClamAV backend | ✗ |
| `virustotal` | VirusTotal API backend | ✗ |

## Examples

```bash
# Basic scanning
cargo run --example basic_scan

# Circuit breaker demonstration
cargo run --example with_circuit_breaker

# Custom backend implementation
cargo run --example custom_backend
```

## Error Handling

Scanbridge never panics. All errors are returned as typed `ScanError` variants:

- `EngineUnavailable`: Scanner not responding
- `Timeout`: Scan took too long
- `ConnectionFailed`: Network/socket failure
- `FileTooLarge`: File exceeds size limit
- `CircuitOpen`: Circuit breaker is open
- `RateLimited`: API rate limit exceeded

All errors include context about which engine failed and why.

## Performance

- BLAKE3 hashing: ~10x faster than SHA256
- Parallel scanning across multiple engines
- Stream processing for large files
- Connection pooling for network-based scanners

## License

- MIT license ([LICENSE-MIT](LICENSE-MIT))



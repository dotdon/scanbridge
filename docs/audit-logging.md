# Audit Logging Guide

Scanbridge provides structured audit logging via the `tracing` crate, enabling flexible integration with various logging backends for compliance and monitoring.

## Overview

All significant operations emit structured events that include:

- Timestamps
- File hashes (BLAKE3, optional SHA256)
- Operation outcomes
- Tenant/user context
- Duration metrics

Events are emitted to the `scanbridge::audit` target, allowing selective capture.

## Event Types

### scan_started

Emitted when a scan begins.

```json
{
  "event_type": "scan_started",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "file_hash_blake3": "abc123...",
  "tenant_id": "customer-123",
  "user_id": "user-456",
  "source": "upload"
}
```

### scan_completed

Emitted when a single engine completes scanning.

```json
{
  "event_type": "scan_completed",
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "file_hash_blake3": "abc123...",
  "file_hash_sha256": "def456...",
  "outcome": "clean",
  "engine": "clamav",
  "duration_ms": 150,
  "tenant_id": "customer-123",
  "cached": false
}
```

### scan_report

Emitted when a complete scan report is generated (aggregating all engines).

```json
{
  "event_type": "scan_report",
  "report_id": "660e8400-e29b-41d4-a716-446655440001",
  "file_hash_blake3": "abc123...",
  "aggregated_outcome": "infected",
  "engines": ["clamav", "virustotal"],
  "engine_count": 2,
  "total_duration_ms": 1250,
  "tenant_id": "customer-123",
  "threat_count": 1,
  "threats": [
    {"name": "Trojan.GenericKD", "severity": "high", "engine": "clamav"}
  ]
}
```

### policy_decision

Emitted when a policy decision is made.

```json
{
  "event_type": "policy_decision",
  "file_hash_blake3": "abc123...",
  "action": "block",
  "matched_rule_id": "block-infected",
  "matched_rule_name": "Block Infected Files",
  "reason": "Matched rule: Block Infected Files",
  "tenant_id": "customer-123"
}
```

### quarantine_operation

Emitted for quarantine actions.

```json
{
  "event_type": "quarantine_operation",
  "quarantine_id": "770e8400-e29b-41d4-a716-446655440002",
  "file_hash_blake3": "abc123...",
  "operation": "store",
  "reason": "Malware detected",
  "tenant_id": "customer-123",
  "file_size": 15234
}
```

## Configuration

### Basic Setup

```rust
use tracing_subscriber::fmt;

// Simple stdout logging
tracing_subscriber::fmt()
    .with_max_level(tracing::Level::INFO)
    .init();
```

### JSON Output

For machine-readable logs:

```rust
use tracing_subscriber::fmt::format::FmtSpan;

tracing_subscriber::fmt()
    .json()
    .with_target(true)
    .with_current_span(false)
    .init();
```

### Filtering to Audit Events Only

```rust
use tracing_subscriber::EnvFilter;

tracing_subscriber::fmt()
    .json()
    .with_env_filter(
        EnvFilter::new("scanbridge::audit=info")
    )
    .init();
```

### Multiple Outputs

Using `tracing-subscriber` layers:

```rust
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tracing_subscriber::fmt;

// File output for audit logs
let audit_file = std::fs::File::create("/var/log/scanbridge/audit.json")?;
let audit_layer = fmt::layer()
    .json()
    .with_writer(audit_file)
    .with_filter(tracing_subscriber::filter::filter_fn(|meta| {
        meta.target().starts_with("scanbridge::audit")
    }));

// Console output for everything
let console_layer = fmt::layer()
    .with_filter(tracing::Level::INFO);

tracing_subscriber::registry()
    .with(audit_layer)
    .with(console_layer)
    .init();
```

## Integration Examples

### Elasticsearch / OpenSearch

Using `tracing-bunyan-formatter` or similar:

```rust
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_subscriber::Registry;

let app_name = "scanbridge-service";
let (non_blocking, _guard) = tracing_appender::non_blocking(
    tracing_appender::rolling::daily("/var/log/scanbridge", "audit")
);

let bunyan_layer = BunyanFormattingLayer::new(app_name.into(), non_blocking);

Registry::default()
    .with(JsonStorageLayer)
    .with(bunyan_layer)
    .init();
```

### OpenTelemetry

```rust
use tracing_opentelemetry::OpenTelemetryLayer;
use opentelemetry::global;

let tracer = opentelemetry_jaeger::new_pipeline()
    .with_service_name("scanbridge")
    .install_simple()?;

tracing_subscriber::registry()
    .with(tracing_subscriber::fmt::layer())
    .with(OpenTelemetryLayer::new(tracer))
    .init();
```

### CloudWatch Logs

```rust
// Use tracing-subscriber with JSON formatting
// Forward stdout/stderr to CloudWatch via container logging driver
tracing_subscriber::fmt()
    .json()
    .with_target(true)
    .with_ansi(false)  // No color codes
    .init();
```

### Datadog

```rust
// Datadog expects specific JSON format
// Use custom formatting or datadog-tracing crate
tracing_subscriber::fmt()
    .json()
    .with_target(true)
    .with_current_span(true)
    .init();

// Or use datadog-tracing for native integration
```

## Compliance Mapping

### SOC 2

| Control | Audit Event | Fields |
|---------|-------------|--------|
| CC6.1 Logical Access | policy_decision | user_id, tenant_id, action |
| CC6.6 System Operations | scan_completed | engine, duration_ms, outcome |
| CC7.2 System Monitoring | scan_report | threat_count, engines |
| CC7.3 Incident Response | quarantine_operation | quarantine_id, reason |

### PCI-DSS

| Requirement | Audit Event | Notes |
|-------------|-------------|-------|
| 10.2.1 User access | scan_started | With user_id |
| 10.2.4 Invalid access | policy_decision | When action=block |
| 10.2.5 System components | scan_completed | With engine |
| 10.3 Audit trail content | All events | Includes timestamp, user, outcome |

### HIPAA

| Standard | Implementation |
|----------|----------------|
| § 164.312(b) Audit controls | Enable all audit events |
| § 164.312(c)(1) Integrity | Include file hashes |
| § 164.312(d) Person authentication | Include user_id in context |

## Best Practices

### 1. Include Context in Every Scan

```rust
let context = ScanContext::new()
    .with_tenant_id(&tenant_id)
    .with_user_id(&user_id)
    .with_request_id(&request_id)
    .with_source("api-upload");
```

### 2. Don't Log Sensitive Content

File contents are never included in audit logs. Only:
- File hashes
- File names (optional, can be omitted)
- File sizes
- Scan outcomes

### 3. Protect Audit Logs

- Store separately from application logs
- Use append-only storage if possible
- Replicate to immutable backup
- Restrict access

### 4. Set Retention Periods

```bash
# Example log rotation config
/var/log/scanbridge/audit.json {
    daily
    rotate 365
    compress
    notifempty
    missingok
}
```

### 5. Monitor for Anomalies

Set up alerts for:
- Unusual scan volume
- High infection rates
- Repeated policy blocks for same user
- Circuit breaker activations

### 6. Test Audit Trail

Regularly verify:
- Events are being captured
- All required fields are present
- Timestamps are accurate
- Logs can be queried/searched

## Custom Events

Extend audit logging for application-specific events:

```rust
use tracing::info;

// After processing a scan result
info!(
    target: "scanbridge::audit",
    event_type = "file_processed",
    file_hash_blake3 = %report.file_hash.blake3,
    outcome = ?report.aggregated_outcome,
    storage_path = %final_path,
    processing_duration_ms = processing_time.as_millis(),
    "File processing completed"
);
```

## Troubleshooting

### Events Not Appearing

1. Check filter level: `RUST_LOG=scanbridge::audit=info`
2. Verify tracing subscriber is initialized before scanning
3. Check target filter includes `scanbridge::audit`

### Missing Fields

Some fields are optional and may appear as `null`:
- `file_hash_sha256` - only if SHA256 was computed
- `tenant_id`, `user_id` - only if provided in context
- `threats` - empty array if clean

### Performance Impact

Audit logging is designed to be low-overhead:
- Events are queued asynchronously
- No blocking I/O on critical path
- Consider async writer for high-volume scenarios

```rust
use tracing_appender::non_blocking;

let (non_blocking_writer, _guard) = non_blocking(file);
tracing_subscriber::fmt()
    .with_writer(non_blocking_writer)
    .init();
```

# Scanbridge Architecture

This document explains the architecture and design decisions behind Scanbridge.

## Overview

Scanbridge is designed as a layered architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────────────┐
│                         Application                              │
│              (Your web server, CLI tool, etc.)                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                      Public API Layer                            │
│           ScanManager, ScanReport, PolicyDecision               │
└────────────────────────────┬────────────────────────────────────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     │                       │                       │
┌────▼────┐           ┌──────▼──────┐         ┌──────▼──────┐
│ Policy  │           │  Quarantine │         │    Audit    │
│ Engine  │           │   Storage   │         │   Logger    │
└─────────┘           └─────────────┘         └─────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                     Resilience Layer                             │
│              CircuitBreaker, RetryPolicy, Timeout               │
└────────────────────────────┬────────────────────────────────────┘
                             │
     ┌───────────────────────┼───────────────────────┐
     │                       │                       │
┌────▼────────┐       ┌──────▼──────┐       ┌────────▼───────┐
│   ClamAV    │       │ VirusTotal  │       │ Custom Scanner │
│   Backend   │       │   Backend   │       │    Backend     │
└─────────────┘       └─────────────┘       └────────────────┘
```

## Core Module

The core module (`src/core/`) provides fundamental types used throughout the library.

### Types

- **ScanOutcome**: The four possible states after scanning (Clean, Infected, Suspicious, Error)
- **ThreatInfo**: Details about a detected threat (name, severity, signature)
- **FileHash**: Multi-algorithm hash container (BLAKE3 primary, optional SHA256/MD5)
- **FileMetadata**: Information about the scanned file
- **ScanContext**: Contextual information (tenant, user, request ID)

### Traits

- **Scanner**: The core trait that all backends implement
- **ScannerConfig**: Configuration interface for scanners

### Errors

Typed errors for every failure scenario, never panics:

- `ScanError`: Scanning operation failures
- `QuarantineError`: File storage failures
- `PolicyError`: Rule evaluation failures

### FileInput

Flexible file input abstraction supporting:

- File paths (reads from disk)
- In-memory bytes
- Async streams (for large files)

## Backend Layer

Each scanning engine is implemented as a separate module conforming to the `Scanner` trait.

### Scanner Trait

```rust
#[async_trait]
pub trait Scanner: Send + Sync + Debug {
    fn name(&self) -> &str;
    async fn scan(&self, input: &FileInput) -> Result<ScanResult, ScanError>;
    async fn health_check(&self) -> Result<(), ScanError>;
}
```

### Implemented Backends

1. **MockScanner**: Configurable test scanner
2. **ClamAvScanner**: ClamAV via socket protocol
3. **VirusTotalScanner**: VirusTotal REST API

### Adding New Backends

New backends can be added without modifying core library code:

1. Create a struct implementing `Scanner`
2. Handle connection/authentication in the constructor
3. Implement `scan()` to send data and parse results
4. Implement `health_check()` for circuit breaker probing

## Circuit Breaker

The circuit breaker prevents cascading failures by temporarily disabling unhealthy backends.

### State Machine

```
         ┌─────────────────────────────────────────┐
         │                                         │
         │ ┌───────────┐   failures   ┌───────────┐
         │ │  CLOSED   │─────────────>│   OPEN    │
         │ │ (normal)  │              │ (failing) │
         │ └───────────┘              └───────────┘
         │       ▲                          │
         │       │                          │ timeout
         │       │                          │ expires
         │       │                          ▼
         │       │  successes   ┌───────────────────┐
         │       └──────────────│    HALF-OPEN     │
         │                      │   (probing)       │
         │                      └───────────────────┘
         │                              │
         │       failure                │
         └──────────────────────────────┘
```

### Configuration

- `failure_threshold`: Failures before opening (default: 5)
- `success_threshold`: Successes needed to close (default: 3)
- `open_duration`: How long to stay open (default: 30s)
- `fallback_behavior`: What to do when open

### Fallback Behaviors

1. **FailClosed**: Reject scans when circuit is open (recommended for security)
2. **FailOpen**: Allow files through with warning (for high availability)
3. **Fallback(scanner)**: Use alternate scanner

## Policy Engine

The policy engine evaluates scan results against configurable rules.

### Rule Structure

```rust
PolicyRule {
    id: "block-infected",
    name: "Block Infected Files",
    conditions: [Condition::is_infected()],
    action: PolicyAction::Block { reason: "Malware detected" },
    priority: 100,  // Higher = evaluated first
}
```

### Available Conditions

- `OutcomeIs`: Match scan outcome type
- `TenantEquals` / `TenantIn`: Match tenant
- `FileTypeIn`: Match file extension/type
- `SeverityAtLeast`: Minimum threat severity
- `FileSizeExceeds`: Size threshold
- `ThreatNameContains`: Pattern in threat name
- `And` / `Or` / `Not`: Logical combinations

### Available Actions

- `Allow`: Let file through
- `AllowWithWarning`: Pass with logged warning
- `Quarantine`: Store in quarantine
- `Block`: Reject the file
- `RequireManualReview`: Flag for human review

## Quarantine Storage

The quarantine system safely stores infected files with metadata.

### Trait Interface

```rust
#[async_trait]
pub trait QuarantineStore: Send + Sync {
    async fn store(&self, input: &FileInput, record: QuarantineRecord) -> Result<QuarantineId, QuarantineError>;
    async fn retrieve(&self, id: &QuarantineId) -> Result<(Vec<u8>, QuarantineRecord), QuarantineError>;
    async fn delete(&self, id: &QuarantineId) -> Result<(), QuarantineError>;
    async fn list(&self, filter: QuarantineFilter) -> Result<Vec<QuarantineRecord>, QuarantineError>;
}
```

### Filesystem Implementation

- Files stored with obfuscated names (.qdata)
- Metadata stored as JSON
- Integrity verification via BLAKE3 hash
- Support for expiration and cleanup

### Custom Implementations

Implement `QuarantineStore` for cloud storage, databases, or other backends.

## Audit Logging

Audit events are emitted via the `tracing` crate for maximum flexibility.

### Event Types

- `scan_started`: When a scan begins
- `scan_completed`: Individual engine result
- `scan_report`: Aggregated report
- `policy_decision`: Policy evaluation result
- `quarantine_operation`: Quarantine actions

### Integration

Attach any `tracing` subscriber:

- JSON files for SIEM ingestion
- OpenTelemetry for distributed tracing
- stdout for development

### Compliance Considerations

- All events include timestamps
- File hashes (BLAKE3, SHA256) for correlation
- Tenant/user context for multi-tenant systems
- No sensitive file content in logs

## Design Principles

### 1. Never Panic

All errors are returned as `Result` types. No `unwrap()` on fallible operations in library code.

### 2. Minimal Dependencies

Core functionality uses only essential crates:
- `async-trait` for trait support
- `thiserror` for error handling
- `tracing` for logging
- `blake3` for hashing
- `chrono`, `serde`, `uuid` for data types

### 3. Extensibility Over Completeness

The library provides hooks for customization:
- Implement `Scanner` for new backends
- Implement `QuarantineStore` for custom storage
- Configure policy rules for business logic

### 4. Fail-Safe Defaults

- Circuit breakers fail closed by default
- Policy engine blocks infected files by default
- All operations have configurable timeouts

### 5. Structured Everything

- Typed errors with context
- Structured logging via tracing
- Serializable results for persistence

# Quarantine Guide

Quarantine storage provides a secure way to isolate and track potentially malicious files. This is essential for compliance, forensic analysis, and false-positive recovery.

## Overview

When a file is quarantined:

1. Original file is moved/copied to secure storage
2. Metadata is recorded (hash, source, reason, scan results)
3. Original file can optionally be deleted
4. Files can be retrieved, listed, or permanently deleted

## Built-in Implementation

### Filesystem Quarantine

```rust
use scanbridge::quarantine::FilesystemQuarantine;

// Create quarantine storage
let quarantine = FilesystemQuarantine::new("/var/lib/scanbridge/quarantine")?;
```

Directory structure:
```
/var/lib/scanbridge/quarantine/
├── data/
│   ├── abc123-456.qdata    # Quarantined file (obfuscated)
│   └── def789-012.qdata
└── meta/
    ├── abc123-456.json     # Metadata
    └── def789-012.json
```

### Storage Features

- **Obfuscated Names**: Files renamed to prevent accidental execution
- **Integrity Verification**: BLAKE3 hash checked on store/retrieve
- **Metadata Tracking**: Full scan context preserved
- **Expiration Support**: Automatic cleanup of old records
- **Multi-tenant**: Filterable by tenant ID

## Integration with ScanManager

```rust
use scanbridge::quarantine::FilesystemQuarantine;

let quarantine = FilesystemQuarantine::new("/var/quarantine")?;

let manager = ScanManager::builder()
    .add_scanner(scanner)
    .with_quarantine(quarantine)
    .build()?;
```

When using `scan_with_policy()` and the policy returns `Quarantine`:
- The file is automatically stored
- Audit event is emitted
- QuarantineId is available in the result

## Manual Quarantine Operations

### Storing a File

```rust
use scanbridge::quarantine::{QuarantineRecord, FilesystemQuarantine};

// After a scan with infected result...
let record = QuarantineRecord::new(
    result.file_hash().clone(),
    result.file_metadata.size,
    "Malware detected: Trojan.GenericKD",
    result.clone(),
)
.with_original_filename("suspicious.exe")
.with_tenant_id("customer-123")
.with_metadata("source", "email-attachment");

let id = quarantine.store(&input, record).await?;
println!("File quarantined with ID: {}", id);
```

### Retrieving a File

```rust
let (file_data, record) = quarantine.retrieve(&id).await?;

println!("Original filename: {:?}", record.original_filename);
println!("Quarantined at: {}", record.quarantined_at);
println!("Reason: {}", record.reason);
println!("File size: {} bytes", file_data.len());
```

**Warning**: Retrieved files may be malicious. Handle with care:
- Don't execute retrieved files
- Scan before releasing
- Log all retrievals

### Listing Records

```rust
use scanbridge::quarantine::QuarantineFilter;

// List all records for a tenant
let filter = QuarantineFilter::new()
    .with_tenant_id("customer-123");

let records = quarantine.list(filter).await?;
for record in records {
    println!("{}: {} ({})", 
        record.id, 
        record.original_filename.unwrap_or_default(),
        record.quarantined_at);
}
```

### Filtering Options

```rust
let filter = QuarantineFilter::new()
    // By tenant
    .with_tenant_id("tenant-123")
    
    // By file hash
    .with_file_hash("abc123...")
    
    // By date range
    .with_date_range(
        Some(Utc::now() - chrono::Duration::days(7)),
        None,
    )
    
    // Pagination
    .with_pagination(20, 0)  // limit, offset
    
    // Include expired records
    .with_include_expired(true);
```

### Deleting Records

```rust
// Delete a specific record
quarantine.delete(&id).await?;

// Clean up expired records
let deleted_count = quarantine.cleanup_expired().await?;
println!("Cleaned up {} expired records", deleted_count);
```

## Expiration

Set expiration when quarantining:

```rust
use chrono::{Utc, Duration};

let record = QuarantineRecord::new(...)
    .with_expires_at(Utc::now() + Duration::days(90));
```

Periodic cleanup:

```rust
// Run periodically (e.g., daily cron job)
let deleted = quarantine.cleanup_expired().await?;
tracing::info!(deleted = deleted, "Quarantine cleanup complete");
```

## Custom Storage Backends

Implement `QuarantineStore` for custom backends:

```rust
use scanbridge::quarantine::{QuarantineStore, QuarantineRecord, QuarantineId, QuarantineFilter};
use scanbridge::core::{FileInput, QuarantineError};
use async_trait::async_trait;

#[derive(Debug)]
pub struct S3QuarantineStore {
    bucket: String,
    client: aws_sdk_s3::Client,
}

#[async_trait]
impl QuarantineStore for S3QuarantineStore {
    async fn store(
        &self,
        input: &FileInput,
        record: QuarantineRecord,
    ) -> Result<QuarantineId, QuarantineError> {
        // Upload to S3 with metadata
        todo!()
    }

    async fn retrieve(
        &self,
        id: &QuarantineId,
    ) -> Result<(Vec<u8>, QuarantineRecord), QuarantineError> {
        // Download from S3
        todo!()
    }

    async fn delete(&self, id: &QuarantineId) -> Result<(), QuarantineError> {
        // Delete from S3
        todo!()
    }

    async fn list(
        &self,
        filter: QuarantineFilter,
    ) -> Result<Vec<QuarantineRecord>, QuarantineError> {
        // Query DynamoDB/metadata store
        todo!()
    }
}
```

## Compliance Considerations

### HIPAA / Healthcare

- Encrypt quarantined files at rest
- Log all access to quarantine
- Maintain audit trail for 6+ years
- Ensure PHI in quarantined files is protected

### PCI-DSS / Financial

- Isolate quarantine storage from cardholder data
- Monitor quarantine access
- Include in vulnerability management program

### GDPR / Privacy

- Consider data retention limits
- Handle deletion requests that include quarantined files
- Document quarantine in privacy policy

### General Best Practices

1. **Encrypt at rest**: Use encrypted filesystem or object storage
2. **Access control**: Limit who can retrieve quarantined files
3. **Audit all operations**: Log store, retrieve, delete actions
4. **Retain appropriately**: Balance forensics needs vs storage costs
5. **Secure transfer**: Encrypt when moving quarantined files
6. **Test recovery**: Periodically verify files can be retrieved

## Monitoring

Track these metrics:

- `quarantine_storage_used_bytes`: Total storage consumed
- `quarantine_files_total`: Number of quarantined files
- `quarantine_files_by_tenant`: Per-tenant breakdown
- `quarantine_retrievals_total`: How often files are retrieved
- `quarantine_age_days`: Age distribution of quarantined files

Example with Prometheus:

```rust
// After quarantine operations
metrics.quarantine_files_total.inc();
metrics.quarantine_storage_bytes.add(record.file_size as f64);
```

## Recovery Workflow

When a file is determined to be a false positive:

```rust
// 1. Retrieve the file
let (data, record) = quarantine.retrieve(&id).await?;

// 2. Re-scan with updated signatures (optional)
let input = FileInput::from_bytes(data.clone());
let new_result = manager.scan(input, context).await?;

if new_result.is_clean() {
    // 3. Return to user/original location
    tokio::fs::write(&original_path, &data).await?;
    
    // 4. Delete from quarantine
    quarantine.delete(&id).await?;
    
    // 5. Log the recovery
    tracing::info!(
        quarantine_id = %id,
        file_hash = %record.file_hash.blake3,
        "False positive recovered from quarantine"
    );
}
```

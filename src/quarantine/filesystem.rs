//! Filesystem-based quarantine storage implementation.

use crate::core::error::QuarantineError;
use crate::core::FileInput;
use crate::quarantine::record::{QuarantineFilter, QuarantineId, QuarantineRecord};
use crate::quarantine::traits::QuarantineStore;

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

/// Filesystem-based quarantine storage.
///
/// Stores quarantined files in a designated directory with their metadata.
/// Files are stored with obfuscated names to prevent accidental execution.
///
/// # Directory Structure
///
/// ```text
/// quarantine/
/// ├── data/
/// │   └── {id}.qdata          # Quarantined file (obfuscated)
/// └── meta/
///     └── {id}.json           # Metadata
/// ```
#[derive(Debug)]
pub struct FilesystemQuarantine {
    /// Base directory for quarantine storage.
    base_path: PathBuf,
    /// In-memory index of records (for fast lookups).
    index: RwLock<HashMap<String, QuarantineRecord>>,
}

impl FilesystemQuarantine {
    /// Creates a new filesystem quarantine at the given path.
    ///
    /// Creates the directory structure if it doesn't exist.
    pub fn new(base_path: impl Into<PathBuf>) -> Result<Self, QuarantineError> {
        let base_path = base_path.into();

        // Create directory structure
        let data_dir = base_path.join("data");
        let meta_dir = base_path.join("meta");

        std::fs::create_dir_all(&data_dir).map_err(|e| QuarantineError::StoreFailed {
            reason: format!("Failed to create data directory: {}", e),
        })?;

        std::fs::create_dir_all(&meta_dir).map_err(|e| QuarantineError::StoreFailed {
            reason: format!("Failed to create meta directory: {}", e),
        })?;

        let store = Self {
            base_path,
            index: RwLock::new(HashMap::new()),
        };

        // Load existing records into index
        store.load_index()?;

        Ok(store)
    }

    /// Returns the path to the quarantine data directory.
    pub fn data_dir(&self) -> PathBuf {
        self.base_path.join("data")
    }

    /// Returns the path to the quarantine metadata directory.
    pub fn meta_dir(&self) -> PathBuf {
        self.base_path.join("meta")
    }

    /// Returns the data file path for a given ID.
    fn data_path(&self, id: &QuarantineId) -> PathBuf {
        self.data_dir().join(format!("{}.qdata", id.as_str()))
    }

    /// Returns the metadata file path for a given ID.
    fn meta_path(&self, id: &QuarantineId) -> PathBuf {
        self.meta_dir().join(format!("{}.json", id.as_str()))
    }

    /// Loads existing records into the in-memory index.
    fn load_index(&self) -> Result<(), QuarantineError> {
        let meta_dir = self.meta_dir();
        if !meta_dir.exists() {
            return Ok(());
        }

        let entries = std::fs::read_dir(&meta_dir).map_err(|e| QuarantineError::RetrieveFailed {
            reason: format!("Failed to read meta directory: {}", e),
        })?;

        let mut index = self.index.write().unwrap();
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    if let Ok(record) = serde_json::from_str::<QuarantineRecord>(&content) {
                        index.insert(record.id.0.clone(), record);
                    }
                }
            }
        }

        tracing::debug!(count = index.len(), "Loaded quarantine index");
        Ok(())
    }

    /// Saves a record's metadata to disk.
    fn save_metadata(&self, record: &QuarantineRecord) -> Result<(), QuarantineError> {
        let path = self.meta_path(&record.id);
        let content = serde_json::to_string_pretty(record).map_err(|e| {
            QuarantineError::StoreFailed {
                reason: format!("Failed to serialize metadata: {}", e),
            }
        })?;

        std::fs::write(&path, content).map_err(|e| QuarantineError::StoreFailed {
            reason: format!("Failed to write metadata: {}", e),
        })?;

        Ok(())
    }

    /// Reads file data from a FileInput.
    async fn read_input_data(&self, input: &FileInput) -> Result<Vec<u8>, QuarantineError> {
        match input {
            FileInput::Path(path) => {
                #[cfg(feature = "tokio-runtime")]
                {
                    tokio::fs::read(path)
                        .await
                        .map_err(|e| QuarantineError::StoreFailed {
                            reason: format!("Failed to read file: {}", e),
                        })
                }
                #[cfg(not(feature = "tokio-runtime"))]
                {
                    std::fs::read(path).map_err(|e| QuarantineError::StoreFailed {
                        reason: format!("Failed to read file: {}", e),
                    })
                }
            }
            FileInput::Bytes { data, .. } => Ok(data.clone()),
            FileInput::Stream { .. } => Err(QuarantineError::StoreFailed {
                reason: "Stream input not supported for filesystem quarantine".into(),
            }),
        }
    }
}

#[async_trait]
impl QuarantineStore for FilesystemQuarantine {
    async fn store(
        &self,
        input: &FileInput,
        record: QuarantineRecord,
    ) -> Result<QuarantineId, QuarantineError> {
        let id = record.id.clone();

        // Read the file data
        let data = self.read_input_data(input).await?;

        // Verify hash matches
        let hasher = crate::core::FileHasher::new();
        let computed_hash = hasher.hash_bytes(&data);
        if computed_hash.blake3 != record.file_hash.blake3 {
            return Err(QuarantineError::IntegrityCheckFailed {
                expected: record.file_hash.blake3.clone(),
                actual: computed_hash.blake3,
            });
        }

        // Write data file
        let data_path = self.data_path(&id);
        #[cfg(feature = "tokio-runtime")]
        {
            tokio::fs::write(&data_path, &data)
                .await
                .map_err(|e| QuarantineError::StoreFailed {
                    reason: format!("Failed to write data file: {}", e),
                })?;
        }
        #[cfg(not(feature = "tokio-runtime"))]
        {
            std::fs::write(&data_path, &data).map_err(|e| QuarantineError::StoreFailed {
                reason: format!("Failed to write data file: {}", e),
            })?;
        }

        // Save metadata
        self.save_metadata(&record)?;

        // Update index
        self.index.write().unwrap().insert(id.0.clone(), record);

        tracing::info!(
            quarantine_id = %id,
            file_hash = %computed_hash.blake3,
            "File quarantined"
        );

        Ok(id)
    }

    async fn retrieve(
        &self,
        id: &QuarantineId,
    ) -> Result<(Vec<u8>, QuarantineRecord), QuarantineError> {
        // Get record from index
        let record = self
            .index
            .read()
            .unwrap()
            .get(&id.0)
            .cloned()
            .ok_or_else(|| QuarantineError::NotFound { id: id.to_string() })?;

        // Read data file
        let data_path = self.data_path(id);
        #[cfg(feature = "tokio-runtime")]
        let data = tokio::fs::read(&data_path)
            .await
            .map_err(|e| QuarantineError::RetrieveFailed {
                reason: format!("Failed to read data file: {}", e),
            })?;
        #[cfg(not(feature = "tokio-runtime"))]
        let data = std::fs::read(&data_path).map_err(|e| QuarantineError::RetrieveFailed {
            reason: format!("Failed to read data file: {}", e),
        })?;

        // Verify integrity
        let hasher = crate::core::FileHasher::new();
        let computed_hash = hasher.hash_bytes(&data);
        if computed_hash.blake3 != record.file_hash.blake3 {
            return Err(QuarantineError::IntegrityCheckFailed {
                expected: record.file_hash.blake3.clone(),
                actual: computed_hash.blake3,
            });
        }

        Ok((data, record))
    }

    async fn delete(&self, id: &QuarantineId) -> Result<(), QuarantineError> {
        // Remove from index
        self.index.write().unwrap().remove(&id.0);

        // Delete files
        let data_path = self.data_path(id);
        let meta_path = self.meta_path(id);

        #[cfg(feature = "tokio-runtime")]
        {
            let _ = tokio::fs::remove_file(&data_path).await;
            let _ = tokio::fs::remove_file(&meta_path).await;
        }
        #[cfg(not(feature = "tokio-runtime"))]
        {
            let _ = std::fs::remove_file(&data_path);
            let _ = std::fs::remove_file(&meta_path);
        }

        tracing::info!(quarantine_id = %id, "Quarantine record deleted");

        Ok(())
    }

    async fn list(
        &self,
        filter: QuarantineFilter,
    ) -> Result<Vec<QuarantineRecord>, QuarantineError> {
        let index = self.index.read().unwrap();
        let mut records: Vec<_> = index
            .values()
            .filter(|r| filter.matches(r))
            .cloned()
            .collect();

        // Sort by quarantine date (newest first)
        records.sort_by(|a, b| b.quarantined_at.cmp(&a.quarantined_at));

        // Apply pagination
        if let Some(offset) = filter.offset {
            if offset < records.len() {
                records = records.into_iter().skip(offset).collect();
            } else {
                records.clear();
            }
        }

        if let Some(limit) = filter.limit {
            records.truncate(limit);
        }

        Ok(records)
    }

    async fn count(&self) -> Result<usize, QuarantineError> {
        Ok(self.index.read().unwrap().len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FileHash, FileMetadata, ScanContext, ScanOutcome, ScanResult};
    use std::time::Duration;
    use tempfile::TempDir;

    fn make_test_record(hash: FileHash) -> QuarantineRecord {
        let metadata = FileMetadata::new(4, hash.clone());
        let result = ScanResult::new(
            ScanOutcome::Infected { threats: vec![] },
            metadata,
            "test",
            Duration::from_millis(10),
            ScanContext::new(),
        );
        QuarantineRecord::new(hash, 4, "test", result)
    }

    #[tokio::test]
    async fn test_filesystem_quarantine_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let store = FilesystemQuarantine::new(temp_dir.path()).unwrap();

        // Create test data
        let data = b"test";
        let hasher = crate::core::FileHasher::new();
        let hash = hasher.hash_bytes(data);
        let record = make_test_record(hash);

        let input = FileInput::from_bytes(data.to_vec());

        // Store
        let id = store.store(&input, record.clone()).await.unwrap();

        // Retrieve
        let (retrieved_data, retrieved_record) = store.retrieve(&id).await.unwrap();
        assert_eq!(retrieved_data, data);
        assert_eq!(retrieved_record.file_hash.blake3, record.file_hash.blake3);

        // Count
        assert_eq!(store.count().await.unwrap(), 1);

        // Delete
        store.delete(&id).await.unwrap();
        assert_eq!(store.count().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_filesystem_quarantine_list() {
        let temp_dir = TempDir::new().unwrap();
        let store = FilesystemQuarantine::new(temp_dir.path()).unwrap();

        // Store multiple files
        for i in 0..5 {
            let data = format!("test{}", i);
            let hasher = crate::core::FileHasher::new();
            let hash = hasher.hash_bytes(data.as_bytes());
            let mut record = make_test_record(hash);
            record.file_size = data.len() as u64;
            record = record.with_tenant_id(format!("tenant-{}", i % 2));

            let input = FileInput::from_bytes(data.into_bytes());
            store.store(&input, record).await.unwrap();
        }

        // List all
        let all = store.list(QuarantineFilter::new()).await.unwrap();
        assert_eq!(all.len(), 5);

        // List with filter
        let filtered = store
            .list(QuarantineFilter::new().with_tenant_id("tenant-0"))
            .await
            .unwrap();
        assert_eq!(filtered.len(), 3); // 0, 2, 4

        // List with pagination
        let paginated = store
            .list(QuarantineFilter::new().with_pagination(2, 1))
            .await
            .unwrap();
        assert_eq!(paginated.len(), 2);
    }
}

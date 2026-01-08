//! Quarantine store trait definition.

use crate::core::error::QuarantineError;
use crate::core::FileInput;
use crate::quarantine::record::{QuarantineFilter, QuarantineId, QuarantineRecord};

use async_trait::async_trait;
use std::fmt::Debug;

/// Trait for quarantine storage implementations.
///
/// Implementations of this trait provide storage for quarantined files,
/// allowing them to be safely stored, retrieved, and managed.
///
/// # Example Implementation
///
/// ```rust,ignore
/// use scanbridge::quarantine::{QuarantineStore, QuarantineRecord, QuarantineId, QuarantineFilter};
/// use scanbridge::core::{FileInput, QuarantineError};
/// use async_trait::async_trait;
///
/// #[derive(Debug)]
/// struct MyQuarantineStore {
///     // Your storage implementation
/// }
///
/// #[async_trait]
/// impl QuarantineStore for MyQuarantineStore {
///     async fn store(
///         &self,
///         input: &FileInput,
///         record: QuarantineRecord,
///     ) -> Result<QuarantineId, QuarantineError> {
///         // Store the file and record
///         todo!()
///     }
///
///     async fn retrieve(
///         &self,
///         id: &QuarantineId,
///     ) -> Result<(Vec<u8>, QuarantineRecord), QuarantineError> {
///         // Retrieve the file and record
///         todo!()
///     }
///
///     async fn delete(&self, id: &QuarantineId) -> Result<(), QuarantineError> {
///         // Delete the file and record
///         todo!()
///     }
///
///     async fn list(
///         &self,
///         filter: QuarantineFilter,
///     ) -> Result<Vec<QuarantineRecord>, QuarantineError> {
///         // List records matching the filter
///         todo!()
///     }
/// }
/// ```
#[async_trait]
pub trait QuarantineStore: Send + Sync + Debug {
    /// Stores a file in quarantine.
    ///
    /// # Arguments
    ///
    /// * `input` - The file to quarantine
    /// * `record` - Metadata about the quarantined file
    ///
    /// # Returns
    ///
    /// The unique ID assigned to this quarantine entry.
    async fn store(
        &self,
        input: &FileInput,
        record: QuarantineRecord,
    ) -> Result<QuarantineId, QuarantineError>;

    /// Retrieves a file from quarantine.
    ///
    /// # Arguments
    ///
    /// * `id` - The quarantine ID of the file to retrieve
    ///
    /// # Returns
    ///
    /// The file contents and metadata.
    async fn retrieve(
        &self,
        id: &QuarantineId,
    ) -> Result<(Vec<u8>, QuarantineRecord), QuarantineError>;

    /// Deletes a file from quarantine.
    ///
    /// # Arguments
    ///
    /// * `id` - The quarantine ID of the file to delete
    async fn delete(&self, id: &QuarantineId) -> Result<(), QuarantineError>;

    /// Lists quarantine records matching the filter.
    ///
    /// # Arguments
    ///
    /// * `filter` - Criteria for filtering records
    ///
    /// # Returns
    ///
    /// Matching quarantine records (without file contents).
    async fn list(
        &self,
        filter: QuarantineFilter,
    ) -> Result<Vec<QuarantineRecord>, QuarantineError>;

    /// Returns the number of quarantined files.
    async fn count(&self) -> Result<usize, QuarantineError> {
        let records = self.list(QuarantineFilter::new()).await?;
        Ok(records.len())
    }

    /// Checks if a file with the given hash is already quarantined.
    async fn contains_hash(&self, hash: &str) -> Result<bool, QuarantineError> {
        let filter = QuarantineFilter::new().with_file_hash(hash);
        let records = self.list(filter).await?;
        Ok(!records.is_empty())
    }

    /// Gets a record by ID without retrieving the file contents.
    async fn get_record(&self, id: &QuarantineId) -> Result<QuarantineRecord, QuarantineError> {
        let (_, record) = self.retrieve(id).await?;
        Ok(record)
    }

    /// Deletes all expired quarantine records.
    async fn cleanup_expired(&self) -> Result<usize, QuarantineError> {
        let filter = QuarantineFilter::new().with_include_expired(true);
        let records = self.list(filter).await?;

        let mut deleted = 0;
        for record in records {
            if record.is_expired() {
                if self.delete(&record.id).await.is_ok() {
                    deleted += 1;
                }
            }
        }

        Ok(deleted)
    }
}

/// A no-op quarantine store that doesn't actually store anything.
///
/// Useful for testing or when quarantine is disabled.
#[derive(Debug, Default)]
pub struct NoOpQuarantineStore;

impl NoOpQuarantineStore {
    /// Creates a new no-op store.
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl QuarantineStore for NoOpQuarantineStore {
    async fn store(
        &self,
        _input: &FileInput,
        record: QuarantineRecord,
    ) -> Result<QuarantineId, QuarantineError> {
        tracing::debug!(id = %record.id, "NoOp quarantine store: file not actually stored");
        Ok(record.id)
    }

    async fn retrieve(
        &self,
        id: &QuarantineId,
    ) -> Result<(Vec<u8>, QuarantineRecord), QuarantineError> {
        Err(QuarantineError::NotFound { id: id.to_string() })
    }

    async fn delete(&self, _id: &QuarantineId) -> Result<(), QuarantineError> {
        Ok(())
    }

    async fn list(
        &self,
        _filter: QuarantineFilter,
    ) -> Result<Vec<QuarantineRecord>, QuarantineError> {
        Ok(Vec::new())
    }

    async fn count(&self) -> Result<usize, QuarantineError> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_store() {
        let store = NoOpQuarantineStore::new();

        // Count should always be 0
        assert_eq!(store.count().await.unwrap(), 0);

        // Retrieve should always fail
        let result = store.retrieve(&QuarantineId::new()).await;
        assert!(matches!(result, Err(QuarantineError::NotFound { .. })));

        // List should always be empty
        let records = store.list(QuarantineFilter::new()).await.unwrap();
        assert!(records.is_empty());
    }
}

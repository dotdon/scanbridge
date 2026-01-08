//! File input abstraction for flexible file handling.
//!
//! This module provides `FileInput`, which allows scanners to accept
//! files from multiple sources: paths, in-memory bytes, or async streams.

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::io::AsyncRead;
use pin_project_lite::pin_project;

/// Flexible file input supporting paths, bytes, and async streams.
///
/// This enum allows the library to handle files from various sources
/// without requiring the caller to materialize the entire file in memory.
///
/// # Examples
///
/// ```rust
/// use scanbridge::core::FileInput;
/// use std::path::PathBuf;
///
/// // From a file path
/// let input = FileInput::from_path("/path/to/file.exe");
///
/// // From bytes
/// let data = vec![0x4D, 0x5A]; // MZ header
/// let input = FileInput::from_bytes(data).with_filename("test.exe");
/// ```
pub enum FileInput {
    /// A file path on disk.
    Path(PathBuf),

    /// In-memory bytes with optional filename.
    Bytes {
        /// The file data.
        data: Vec<u8>,
        /// Optional original filename.
        filename: Option<String>,
    },

    /// An async stream of bytes (not Send+Sync, use Path or Bytes for async contexts).
    Stream {
        /// The async reader providing the data (wrapped in Arc<Mutex> for Sync).
        reader: Arc<tokio::sync::Mutex<Box<dyn AsyncRead + Send + Unpin>>>,
        /// Optional size hint for progress reporting.
        size_hint: Option<u64>,
        /// Optional filename.
        filename: Option<String>,
    },
}

impl std::fmt::Debug for FileInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Path(path) => f.debug_tuple("Path").field(path).finish(),
            Self::Bytes { data, filename } => f
                .debug_struct("Bytes")
                .field("data_len", &data.len())
                .field("filename", filename)
                .finish(),
            Self::Stream {
                size_hint,
                filename,
                ..
            } => f
                .debug_struct("Stream")
                .field("size_hint", size_hint)
                .field("filename", filename)
                .finish_non_exhaustive(),
        }
    }
}

impl Clone for FileInput {
    fn clone(&self) -> Self {
        match self {
            Self::Path(path) => Self::Path(path.clone()),
            Self::Bytes { data, filename } => Self::Bytes {
                data: data.clone(),
                filename: filename.clone(),
            },
            Self::Stream {
                reader,
                size_hint,
                filename,
            } => Self::Stream {
                reader: Arc::clone(reader),
                size_hint: *size_hint,
                filename: filename.clone(),
            },
        }
    }
}

impl FileInput {
    /// Creates a `FileInput` from a file path.
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self::Path(path.into())
    }

    /// Creates a `FileInput` from bytes.
    pub fn from_bytes(data: impl Into<Vec<u8>>) -> Self {
        Self::Bytes {
            data: data.into(),
            filename: None,
        }
    }

    /// Creates a `FileInput` from an async reader.
    pub fn from_stream(reader: impl AsyncRead + Send + Unpin + 'static) -> Self {
        Self::Stream {
            reader: Arc::new(tokio::sync::Mutex::new(Box::new(reader))),
            size_hint: None,
            filename: None,
        }
    }

    /// Sets the filename for bytes or stream inputs.
    pub fn with_filename(mut self, filename: impl Into<String>) -> Self {
        match &mut self {
            Self::Bytes { filename: f, .. } => *f = Some(filename.into()),
            Self::Stream { filename: f, .. } => *f = Some(filename.into()),
            Self::Path(_) => {} // Filename is derived from path
        }
        self
    }

    /// Sets the size hint for stream inputs.
    pub fn with_size_hint(mut self, size: u64) -> Self {
        if let Self::Stream { size_hint, .. } = &mut self {
            *size_hint = Some(size);
        }
        self
    }

    /// Returns the filename, if known.
    pub fn filename(&self) -> Option<&str> {
        match self {
            Self::Path(path) => path.file_name().and_then(|n| n.to_str()),
            Self::Bytes { filename, .. } => filename.as_deref(),
            Self::Stream { filename, .. } => filename.as_deref(),
        }
    }

    /// Returns the size in bytes, if known.
    ///
    /// For paths, this requires a filesystem stat call.
    /// For bytes, the size is always known.
    /// For streams, returns the size hint if provided.
    pub fn size_hint(&self) -> Option<u64> {
        match self {
            Self::Path(_) => None, // Would require a stat call
            Self::Bytes { data, .. } => Some(data.len() as u64),
            Self::Stream { size_hint, .. } => *size_hint,
        }
    }

    /// Returns `true` if this is a path-based input.
    pub fn is_path(&self) -> bool {
        matches!(self, Self::Path(_))
    }

    /// Returns `true` if this is a bytes-based input.
    pub fn is_bytes(&self) -> bool {
        matches!(self, Self::Bytes { .. })
    }

    /// Returns `true` if this is a stream-based input.
    pub fn is_stream(&self) -> bool {
        matches!(self, Self::Stream { .. })
    }

    /// Returns the path, if this is a path-based input.
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            Self::Path(path) => Some(path),
            _ => None,
        }
    }

    /// Returns the bytes, if this is a bytes-based input.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes { data, .. } => Some(data),
            _ => None,
        }
    }
}

impl From<PathBuf> for FileInput {
    fn from(path: PathBuf) -> Self {
        Self::Path(path)
    }
}

impl From<&Path> for FileInput {
    fn from(path: &Path) -> Self {
        Self::Path(path.to_path_buf())
    }
}

impl From<&str> for FileInput {
    fn from(path: &str) -> Self {
        Self::Path(PathBuf::from(path))
    }
}

impl From<String> for FileInput {
    fn from(path: String) -> Self {
        Self::Path(PathBuf::from(path))
    }
}

impl From<Vec<u8>> for FileInput {
    fn from(data: Vec<u8>) -> Self {
        Self::from_bytes(data)
    }
}

impl From<&[u8]> for FileInput {
    fn from(data: &[u8]) -> Self {
        Self::from_bytes(data.to_vec())
    }
}

pin_project! {
    /// A wrapper that allows reading bytes as an async stream.
    pub struct BytesReader {
        data: Vec<u8>,
        position: usize,
    }
}

impl BytesReader {
    /// Creates a new `BytesReader` from the given bytes.
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, position: 0 }
    }
}

impl AsyncRead for BytesReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let remaining = &this.data[*this.position..];
        let to_copy = std::cmp::min(buf.len(), remaining.len());
        buf[..to_copy].copy_from_slice(&remaining[..to_copy]);
        *this.position += to_copy;
        Poll::Ready(Ok(to_copy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_input_from_path() {
        let input = FileInput::from_path("/test/file.exe");
        assert!(input.is_path());
        assert_eq!(input.filename(), Some("file.exe"));
        assert_eq!(input.as_path(), Some(Path::new("/test/file.exe")));
    }

    #[test]
    fn test_file_input_from_bytes() {
        let data = vec![1, 2, 3, 4];
        let input = FileInput::from_bytes(data.clone()).with_filename("test.bin");
        assert!(input.is_bytes());
        assert_eq!(input.filename(), Some("test.bin"));
        assert_eq!(input.as_bytes(), Some(data.as_slice()));
        assert_eq!(input.size_hint(), Some(4));
    }

    #[test]
    fn test_file_input_conversions() {
        let _: FileInput = PathBuf::from("/test").into();
        let _: FileInput = "/test".into();
        let _: FileInput = String::from("/test").into();
        let _: FileInput = vec![1u8, 2, 3].into();
        let _: FileInput = [1u8, 2, 3].as_slice().into();
    }
}

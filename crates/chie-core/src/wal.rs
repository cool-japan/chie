//! Write-Ahead Logging (WAL) for crash recovery.
//!
//! This module implements a write-ahead log that ensures durability and enables
//! crash recovery for storage operations. All mutations are logged before being
//! applied, allowing recovery from incomplete operations after a crash.
//!
//! # Example
//!
//! ```rust
//! use chie_core::wal::{WriteAheadLog, LogEntry, Operation};
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut wal = WriteAheadLog::new(PathBuf::from("/tmp/wal")).await?;
//!
//! // Log a write operation
//! let entry = LogEntry {
//!     sequence: 1,
//!     operation: Operation::WriteChunk {
//!         cid: "QmTest".to_string(),
//!         chunk_index: 0,
//!         data: vec![1, 2, 3],
//!     },
//!     timestamp_ms: 1234567890,
//! };
//!
//! wal.append(&entry).await?;
//!
//! // Replay log after crash
//! let entries = wal.replay().await?;
//! for entry in entries {
//!     // Apply logged operations
//! }
//!
//! // Truncate log after successful checkpoint
//! wal.truncate(10).await?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs::{self, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// WAL error types.
#[derive(Debug, Error)]
pub enum WalError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Deserialization error: {0}")]
    Deserialization(String),

    #[error("Corrupted WAL entry at sequence {0}")]
    CorruptedEntry(u64),

    #[error("Invalid WAL format")]
    InvalidFormat,
}

/// Types of operations that can be logged.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Operation {
    /// Write a chunk to storage.
    WriteChunk {
        cid: String,
        chunk_index: u64,
        data: Vec<u8>,
    },
    /// Delete a chunk from storage.
    DeleteChunk { cid: String, chunk_index: u64 },
    /// Pin content.
    PinContent { cid: String, chunk_count: u64 },
    /// Unpin content.
    UnpinContent { cid: String },
    /// Update metadata.
    UpdateMetadata { cid: String, metadata: Vec<u8> },
    /// Checkpoint marker (all prior operations completed).
    Checkpoint { sequence: u64 },
}

/// A log entry in the WAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Sequence number (monotonically increasing).
    pub sequence: u64,
    /// Operation to perform.
    pub operation: Operation,
    /// Timestamp when logged (Unix milliseconds).
    pub timestamp_ms: i64,
}

impl LogEntry {
    /// Create a new log entry.
    #[must_use]
    pub fn new(sequence: u64, operation: Operation) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        Self {
            sequence,
            operation,
            timestamp_ms,
        }
    }

    /// Get the sequence number.
    #[must_use]
    #[inline]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Get the operation.
    #[must_use]
    #[inline]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Serialize to bytes with length prefix.
    fn to_bytes(&self) -> Result<Vec<u8>, WalError> {
        let data = crate::serde_helpers::encode(self)
            .map_err(|e| WalError::Serialization(e.to_string()))?;

        // Length prefix (4 bytes) + data
        let len = data.len() as u32;
        let mut result = Vec::with_capacity(4 + data.len());
        result.extend_from_slice(&len.to_le_bytes());
        result.extend_from_slice(&data);

        Ok(result)
    }

    /// Deserialize from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, WalError> {
        crate::serde_helpers::decode(bytes).map_err(|e| WalError::Deserialization(e.to_string()))
    }
}

/// Write-ahead log for crash recovery.
pub struct WriteAheadLog {
    log_path: PathBuf,
    next_sequence: u64,
    checkpoint_sequence: u64,
}

impl WriteAheadLog {
    /// Create a new WAL or open an existing one.
    pub async fn new(log_path: PathBuf) -> Result<Self, WalError> {
        // Ensure parent directory exists
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut wal = Self {
            log_path,
            next_sequence: 1,
            checkpoint_sequence: 0,
        };

        // Scan existing log to find next sequence number
        if wal.log_path.exists() {
            let entries = wal.replay().await?;
            if let Some(last_entry) = entries.last() {
                wal.next_sequence = last_entry.sequence + 1;

                // Find latest checkpoint
                for entry in entries.iter().rev() {
                    if let Operation::Checkpoint { sequence } = entry.operation {
                        wal.checkpoint_sequence = sequence;
                        break;
                    }
                }
            }
        }

        Ok(wal)
    }

    /// Append a new entry to the log.
    pub async fn append(&mut self, entry: &LogEntry) -> Result<(), WalError> {
        let bytes = entry.to_bytes()?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)
            .await?;

        file.write_all(&bytes).await?;
        file.sync_all().await?; // Ensure durability

        self.next_sequence = self.next_sequence.max(entry.sequence + 1);

        Ok(())
    }

    /// Append an operation, automatically assigning sequence number.
    pub async fn log_operation(&mut self, operation: Operation) -> Result<u64, WalError> {
        let sequence = self.next_sequence;
        let entry = LogEntry::new(sequence, operation);
        self.append(&entry).await?;
        Ok(sequence)
    }

    /// Replay the log, returning all entries.
    ///
    /// This should be called during recovery to get all pending operations.
    pub async fn replay(&self) -> Result<Vec<LogEntry>, WalError> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }

        let mut file = fs::File::open(&self.log_path).await?;
        let mut entries = Vec::new();

        loop {
            // Read length prefix
            let mut len_bytes = [0u8; 4];
            match file.read_exact(&mut len_bytes).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(WalError::Io(e)),
            }

            let len = u32::from_le_bytes(len_bytes) as usize;

            // Read entry data
            let mut data = vec![0u8; len];
            file.read_exact(&mut data).await?;

            // Deserialize entry
            let entry = LogEntry::from_bytes(&data)?;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Truncate log up to and including the given sequence number.
    ///
    /// This is typically called after a successful checkpoint to remove old entries.
    pub async fn truncate(&mut self, up_to_sequence: u64) -> Result<(), WalError> {
        let entries = self.replay().await?;
        let remaining: Vec<LogEntry> = entries
            .into_iter()
            .filter(|e| e.sequence > up_to_sequence)
            .collect();

        // Rewrite log with remaining entries
        if self.log_path.exists() {
            fs::remove_file(&self.log_path).await?;
        }

        for entry in &remaining {
            self.append(entry).await?;
        }

        self.checkpoint_sequence = up_to_sequence;

        Ok(())
    }

    /// Write a checkpoint entry.
    pub async fn checkpoint(&mut self) -> Result<u64, WalError> {
        let sequence = self.next_sequence;
        let operation = Operation::Checkpoint { sequence };
        self.log_operation(operation).await?;
        self.checkpoint_sequence = sequence;
        Ok(sequence)
    }

    /// Get entries since last checkpoint.
    pub async fn entries_since_checkpoint(&self) -> Result<Vec<LogEntry>, WalError> {
        let all_entries = self.replay().await?;
        Ok(all_entries
            .into_iter()
            .filter(|e| e.sequence > self.checkpoint_sequence)
            .collect())
    }

    /// Get the next sequence number.
    #[must_use]
    #[inline]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Get the last checkpoint sequence number.
    #[must_use]
    #[inline]
    pub const fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    /// Clear the entire log.
    pub async fn clear(&mut self) -> Result<(), WalError> {
        if self.log_path.exists() {
            fs::remove_file(&self.log_path).await?;
        }
        self.next_sequence = 1;
        self.checkpoint_sequence = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_wal_creation() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.wal");

        let wal = WriteAheadLog::new(log_path).await.unwrap();
        assert_eq!(wal.next_sequence(), 1);
        assert_eq!(wal.checkpoint_sequence(), 0);
    }

    #[tokio::test]
    async fn test_wal_append_and_replay() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.wal");

        let mut wal = WriteAheadLog::new(log_path.clone()).await.unwrap();

        // Append some entries
        let op1 = Operation::WriteChunk {
            cid: "QmTest1".to_string(),
            chunk_index: 0,
            data: vec![1, 2, 3],
        };
        let op2 = Operation::WriteChunk {
            cid: "QmTest2".to_string(),
            chunk_index: 1,
            data: vec![4, 5, 6],
        };

        wal.log_operation(op1.clone()).await.unwrap();
        wal.log_operation(op2.clone()).await.unwrap();

        // Replay log
        let entries = wal.replay().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 1);
        assert_eq!(entries[1].sequence, 2);
        assert_eq!(entries[0].operation, op1);
        assert_eq!(entries[1].operation, op2);
    }

    #[tokio::test]
    async fn test_wal_checkpoint() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.wal");

        let mut wal = WriteAheadLog::new(log_path).await.unwrap();

        // Log some operations
        wal.log_operation(Operation::PinContent {
            cid: "QmTest".to_string(),
            chunk_count: 5,
        })
        .await
        .unwrap();

        // Create checkpoint
        let checkpoint_seq = wal.checkpoint().await.unwrap();
        assert_eq!(checkpoint_seq, 2);
        assert_eq!(wal.checkpoint_sequence(), 2);
    }

    #[tokio::test]
    async fn test_wal_truncate() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.wal");

        let mut wal = WriteAheadLog::new(log_path).await.unwrap();

        // Log multiple operations
        for i in 0..5 {
            wal.log_operation(Operation::WriteChunk {
                cid: format!("QmTest{}", i),
                chunk_index: i,
                data: vec![i as u8],
            })
            .await
            .unwrap();
        }

        // Truncate after sequence 3
        wal.truncate(3).await.unwrap();

        // Replay should only have entries 4 and 5
        let entries = wal.replay().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 4);
        assert_eq!(entries[1].sequence, 5);
    }

    #[tokio::test]
    async fn test_wal_entries_since_checkpoint() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.wal");

        let mut wal = WriteAheadLog::new(log_path).await.unwrap();

        // Log operations before checkpoint
        wal.log_operation(Operation::PinContent {
            cid: "QmTest1".to_string(),
            chunk_count: 1,
        })
        .await
        .unwrap();
        wal.log_operation(Operation::PinContent {
            cid: "QmTest2".to_string(),
            chunk_count: 2,
        })
        .await
        .unwrap();

        // Checkpoint
        wal.checkpoint().await.unwrap();

        // Log operations after checkpoint
        wal.log_operation(Operation::PinContent {
            cid: "QmTest3".to_string(),
            chunk_count: 3,
        })
        .await
        .unwrap();

        // Should only get operations after checkpoint
        let entries = wal.entries_since_checkpoint().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sequence, 4);
    }

    #[tokio::test]
    async fn test_wal_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.wal");

        {
            let mut wal = WriteAheadLog::new(log_path.clone()).await.unwrap();
            wal.log_operation(Operation::PinContent {
                cid: "QmPersist".to_string(),
                chunk_count: 10,
            })
            .await
            .unwrap();
        }

        // Reopen WAL
        let wal = WriteAheadLog::new(log_path).await.unwrap();
        assert_eq!(wal.next_sequence(), 2); // Should continue from where we left off

        let entries = wal.replay().await.unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_wal_clear() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("test.wal");

        let mut wal = WriteAheadLog::new(log_path).await.unwrap();

        // Log some operations
        for i in 0..3 {
            wal.log_operation(Operation::DeleteChunk {
                cid: format!("QmTest{}", i),
                chunk_index: i,
            })
            .await
            .unwrap();
        }

        // Clear log
        wal.clear().await.unwrap();

        // Should be empty
        let entries = wal.replay().await.unwrap();
        assert_eq!(entries.len(), 0);
        assert_eq!(wal.next_sequence(), 1);
    }
}

//! Transactional chunk operations for atomic storage writes.
//!
//! This module provides ACID-compliant transaction support for chunk storage,
//! ensuring that multi-chunk writes are atomic (all-or-nothing). If any chunk
//! fails to write, all previously written chunks in the transaction are rolled back.
//!
//! # Example
//!
//! ```rust
//! use chie_core::transaction::{Transaction, TransactionManager};
//! use chie_core::ChunkStorage;
//! use chie_crypto::{generate_key, generate_nonce};
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let mut storage = ChunkStorage::new(PathBuf::from("/tmp/storage"), 1_000_000_000).await?;
//! let mut tx_mgr = TransactionManager::new();
//!
//! // Begin a transaction
//! let tx_id = tx_mgr.begin_transaction();
//!
//! let key = generate_key();
//! let nonce = generate_nonce();
//! let chunks = vec![vec![1, 2, 3], vec![4, 5, 6]];
//!
//! // Perform transactional write
//! match tx_mgr.transactional_write(&mut storage, tx_id, "QmTest", &chunks, &key, &nonce).await {
//!     Ok(()) => {
//!         // Commit transaction
//!         tx_mgr.commit(tx_id)?;
//!     }
//!     Err(e) => {
//!         // Rollback on error
//!         tx_mgr.rollback(&mut storage, tx_id).await?;
//!         return Err(e.into());
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use crate::storage::{ChunkStorage, StorageError};
use chie_crypto::{EncryptionKey, EncryptionNonce};
use std::collections::HashMap;
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs;

/// Transaction error types.
#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("Transaction not found: {0}")]
    TransactionNotFound(u64),

    #[error("Transaction already committed: {0}")]
    AlreadyCommitted(u64),

    #[error("Transaction already rolled back: {0}")]
    AlreadyRolledBack(u64),

    #[error("Concurrent transaction conflict")]
    ConcurrentConflict,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// Transaction is active and can accept operations.
    Active,
    /// Transaction has been committed.
    Committed,
    /// Transaction has been rolled back.
    RolledBack,
}

/// Information about a written chunk in a transaction.
#[derive(Debug, Clone)]
struct WrittenChunk {
    #[allow(dead_code)]
    cid: String,
    #[allow(dead_code)]
    chunk_index: u64,
    chunk_path: PathBuf,
    meta_path: PathBuf,
    #[allow(dead_code)]
    size_bytes: u64,
}

/// A transaction for atomic chunk operations.
#[derive(Debug)]
pub struct Transaction {
    id: u64,
    state: TransactionState,
    written_chunks: Vec<WrittenChunk>,
    content_dirs: Vec<PathBuf>,
    total_bytes: u64,
}

impl Transaction {
    /// Create a new transaction.
    #[must_use]
    fn new(id: u64) -> Self {
        Self {
            id,
            state: TransactionState::Active,
            written_chunks: Vec::new(),
            content_dirs: Vec::new(),
            total_bytes: 0,
        }
    }

    /// Get the transaction ID.
    #[must_use]
    #[inline]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Get the transaction state.
    #[must_use]
    #[inline]
    pub const fn state(&self) -> TransactionState {
        self.state
    }

    /// Get the total bytes written in this transaction.
    #[must_use]
    #[inline]
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Check if the transaction is active.
    #[must_use]
    #[inline]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, TransactionState::Active)
    }

    /// Record a written chunk.
    fn record_chunk(
        &mut self,
        cid: String,
        chunk_index: u64,
        chunk_path: PathBuf,
        meta_path: PathBuf,
        size_bytes: u64,
    ) {
        self.written_chunks.push(WrittenChunk {
            cid,
            chunk_index,
            chunk_path,
            meta_path,
            size_bytes,
        });
        self.total_bytes += size_bytes;
    }

    /// Record a content directory.
    fn record_content_dir(&mut self, dir: PathBuf) {
        if !self.content_dirs.contains(&dir) {
            self.content_dirs.push(dir);
        }
    }

    /// Rollback this transaction by deleting all written chunks.
    async fn rollback(&mut self) -> Result<(), TransactionError> {
        if self.state != TransactionState::Active {
            return Err(TransactionError::AlreadyRolledBack(self.id));
        }

        // Delete all written chunks and metadata
        for chunk in &self.written_chunks {
            let _ = fs::remove_file(&chunk.chunk_path).await;
            let _ = fs::remove_file(&chunk.meta_path).await;
        }

        // Delete content directories if empty
        for dir in &self.content_dirs {
            let _ = fs::remove_dir(dir).await;
        }

        self.state = TransactionState::RolledBack;
        self.written_chunks.clear();
        self.content_dirs.clear();
        self.total_bytes = 0;

        Ok(())
    }

    /// Commit this transaction.
    fn commit(&mut self) -> Result<(), TransactionError> {
        if self.state != TransactionState::Active {
            return Err(TransactionError::AlreadyCommitted(self.id));
        }

        self.state = TransactionState::Committed;
        Ok(())
    }
}

/// Manages transactions for atomic chunk operations.
pub struct TransactionManager {
    next_id: u64,
    active_transactions: HashMap<u64, Transaction>,
}

impl TransactionManager {
    /// Create a new transaction manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: 1,
            active_transactions: HashMap::new(),
        }
    }

    /// Begin a new transaction.
    pub fn begin_transaction(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;

        let tx = Transaction::new(id);
        self.active_transactions.insert(id, tx);

        id
    }

    /// Get a transaction by ID.
    #[must_use]
    pub fn get_transaction(&self, id: u64) -> Option<&Transaction> {
        self.active_transactions.get(&id)
    }

    /// Commit a transaction.
    pub fn commit(&mut self, id: u64) -> Result<(), TransactionError> {
        let tx = self
            .active_transactions
            .get_mut(&id)
            .ok_or(TransactionError::TransactionNotFound(id))?;

        tx.commit()?;
        self.active_transactions.remove(&id);
        Ok(())
    }

    /// Rollback a transaction.
    pub async fn rollback(
        &mut self,
        storage: &mut ChunkStorage,
        id: u64,
    ) -> Result<(), TransactionError> {
        let mut tx = self
            .active_transactions
            .remove(&id)
            .ok_or(TransactionError::TransactionNotFound(id))?;

        // Rollback the transaction
        tx.rollback().await?;

        // Update storage used_bytes
        storage.decrease_used_bytes(tx.total_bytes);

        Ok(())
    }

    /// Perform a transactional write of chunks.
    ///
    /// This method writes all chunks atomically. If any chunk fails to write,
    /// all previously written chunks are rolled back.
    pub async fn transactional_write(
        &mut self,
        storage: &mut ChunkStorage,
        tx_id: u64,
        cid: &str,
        chunks: &[Vec<u8>],
        key: &EncryptionKey,
        nonce: &EncryptionNonce,
    ) -> Result<(), TransactionError> {
        let tx = self
            .active_transactions
            .get_mut(&tx_id)
            .ok_or(TransactionError::TransactionNotFound(tx_id))?;

        if !tx.is_active() {
            return Err(TransactionError::AlreadyCommitted(tx_id));
        }

        // Calculate total size
        let total_size: u64 = chunks.iter().map(|c| c.len() as u64).sum();

        // Check quota
        if storage.used_bytes() + total_size > storage.max_bytes() {
            // Remove transaction on quota error
            self.active_transactions.remove(&tx_id);
            return Err(TransactionError::Storage(StorageError::QuotaExceeded {
                used: storage.used_bytes(),
                max: storage.max_bytes(),
            }));
        }

        // Create content directory and record it
        let content_dir = storage.get_chunk_dir(cid);
        if let Err(e) = fs::create_dir_all(&content_dir).await {
            // Remove transaction on IO error
            self.active_transactions.remove(&tx_id);
            return Err(TransactionError::Io(e));
        }

        // Record content dir in transaction
        let tx = self
            .active_transactions
            .get_mut(&tx_id)
            .ok_or(TransactionError::TransactionNotFound(tx_id))?;
        tx.record_content_dir(content_dir);

        // Write chunks transactionally
        match storage
            .write_chunks_for_transaction(cid, chunks, key, nonce)
            .await
        {
            Ok(written_chunks) => {
                // Record all written chunks in the transaction
                let tx = self
                    .active_transactions
                    .get_mut(&tx_id)
                    .ok_or(TransactionError::TransactionNotFound(tx_id))?;

                for (chunk_index, chunk_path, meta_path, size_bytes) in written_chunks {
                    tx.record_chunk(
                        cid.to_string(),
                        chunk_index,
                        chunk_path,
                        meta_path,
                        size_bytes,
                    );
                }
                Ok(())
            }
            Err(e) => {
                // Rollback on error and remove transaction
                let mut tx = self
                    .active_transactions
                    .remove(&tx_id)
                    .ok_or(TransactionError::TransactionNotFound(tx_id))?;
                tx.rollback().await?;
                storage.decrease_used_bytes(tx.total_bytes);
                Err(TransactionError::Storage(e))
            }
        }
    }

    /// Get the number of active transactions.
    #[must_use]
    #[inline]
    pub fn active_transaction_count(&self) -> usize {
        self.active_transactions.len()
    }
}

impl Default for TransactionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chie_crypto::{generate_key, generate_nonce};
    use tempfile::TempDir;

    async fn create_test_storage() -> (TempDir, ChunkStorage) {
        let temp_dir = TempDir::new().unwrap();
        let storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 10_000_000)
            .await
            .unwrap();
        (temp_dir, storage)
    }

    #[tokio::test]
    async fn test_transaction_begin_commit() {
        let mut tx_mgr = TransactionManager::new();

        let tx_id = tx_mgr.begin_transaction();
        assert_eq!(tx_mgr.active_transaction_count(), 1);

        let tx = tx_mgr.get_transaction(tx_id).unwrap();
        assert_eq!(tx.id(), tx_id);
        assert_eq!(tx.state(), TransactionState::Active);

        tx_mgr.commit(tx_id).unwrap();
        assert_eq!(tx_mgr.active_transaction_count(), 0);
    }

    #[tokio::test]
    async fn test_transaction_rollback() {
        let (_temp_dir, mut storage) = create_test_storage().await;
        let mut tx_mgr = TransactionManager::new();

        let tx_id = tx_mgr.begin_transaction();
        tx_mgr.rollback(&mut storage, tx_id).await.unwrap();

        assert_eq!(tx_mgr.active_transaction_count(), 0);
    }

    #[tokio::test]
    async fn test_transactional_write_success() {
        let (_temp_dir, mut storage) = create_test_storage().await;
        let mut tx_mgr = TransactionManager::new();

        let tx_id = tx_mgr.begin_transaction();

        let key = generate_key();
        let nonce = generate_nonce();
        let chunks = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        tx_mgr
            .transactional_write(&mut storage, tx_id, "QmTest", &chunks, &key, &nonce)
            .await
            .unwrap();

        let tx = tx_mgr.get_transaction(tx_id).unwrap();
        assert!(tx.total_bytes() > 0);

        tx_mgr.commit(tx_id).unwrap();
    }

    #[tokio::test]
    async fn test_transactional_write_rollback_on_quota_exceeded() {
        let temp_dir = TempDir::new().unwrap();
        // Create storage with very small quota
        let mut storage = ChunkStorage::new(temp_dir.path().to_path_buf(), 100)
            .await
            .unwrap();
        let mut tx_mgr = TransactionManager::new();

        let tx_id = tx_mgr.begin_transaction();

        let key = generate_key();
        let nonce = generate_nonce();
        // Large chunks that exceed quota
        let chunks = vec![vec![0u8; 1000], vec![0u8; 1000]];

        let result = tx_mgr
            .transactional_write(&mut storage, tx_id, "QmTest", &chunks, &key, &nonce)
            .await;

        assert!(result.is_err());
        // Transaction should be automatically rolled back
        assert_eq!(tx_mgr.active_transaction_count(), 0);
    }

    #[tokio::test]
    async fn test_commit_nonexistent_transaction() {
        let mut tx_mgr = TransactionManager::new();

        let result = tx_mgr.commit(999);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            TransactionError::TransactionNotFound(999)
        ));
    }

    #[tokio::test]
    async fn test_double_commit() {
        let mut tx_mgr = TransactionManager::new();

        let tx_id = tx_mgr.begin_transaction();
        tx_mgr.commit(tx_id).unwrap();

        let result = tx_mgr.commit(tx_id);
        assert!(result.is_err());
    }
}

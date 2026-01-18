//! State machine types with compile-time state enforcement using phantom types.
//!
//! This module provides zero-cost state machine abstractions using Rust's type system
//! to prevent invalid state transitions at compile time.

use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

/// Bandwidth proof lifecycle states.
pub mod proof_states {
    /// Initial state: proof created but not submitted
    #[derive(Debug)]
    pub struct Created;
    /// Proof has been submitted for verification
    #[derive(Debug)]
    pub struct Submitted;
    /// Proof has been verified and accepted
    #[derive(Debug)]
    pub struct Verified;
    /// Proof was rejected during verification
    #[derive(Debug)]
    pub struct Rejected;
}

/// Type-safe bandwidth proof with state machine enforcement.
///
/// Uses phantom types to ensure only valid state transitions are possible.
///
/// # Example
/// ```
/// use chie_shared::BandwidthProofState;
/// use chie_shared::proof_states::*;
///
/// // Create a new proof
/// let proof = BandwidthProofState::<Created>::new("proof123", 1024, 100);
///
/// // Submit for verification (changes state)
/// let submitted = proof.submit();
///
/// // Verify the proof (changes state again)
/// let verified = submitted.verify(true);
///
/// // Can't submit again - compile error!
/// // let error = verified.submit(); // Error: method not available for Verified state
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BandwidthProofState<S> {
    /// Proof identifier
    pub id: String,
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Latency in milliseconds
    pub latency_ms: u64,
    /// Points awarded (only set in Verified state)
    pub points: u64,
    /// Rejection reason (only set in Rejected state)
    pub rejection_reason: Option<String>,
    /// Phantom state marker (zero-sized)
    #[serde(skip)]
    _state: PhantomData<S>,
}

impl BandwidthProofState<proof_states::Created> {
    /// Create a new bandwidth proof in Created state.
    #[must_use]
    pub fn new(id: impl Into<String>, bytes_transferred: u64, latency_ms: u64) -> Self {
        Self {
            id: id.into(),
            bytes_transferred,
            latency_ms,
            points: 0,
            rejection_reason: None,
            _state: PhantomData,
        }
    }

    /// Submit the proof for verification (transition to Submitted state).
    #[must_use]
    pub fn submit(self) -> BandwidthProofState<proof_states::Submitted> {
        BandwidthProofState {
            id: self.id,
            bytes_transferred: self.bytes_transferred,
            latency_ms: self.latency_ms,
            points: self.points,
            rejection_reason: self.rejection_reason,
            _state: PhantomData,
        }
    }
}

impl BandwidthProofState<proof_states::Submitted> {
    /// Verify the proof (transition to Verified or Rejected state).
    ///
    /// # Errors
    ///
    /// Returns `BandwidthProofState<Rejected>` if validation fails
    pub fn verify(
        self,
        valid: bool,
    ) -> Result<
        BandwidthProofState<proof_states::Verified>,
        BandwidthProofState<proof_states::Rejected>,
    > {
        if valid {
            // Calculate points (simplified)
            let points = self.bytes_transferred / 1_000_000;
            Ok(BandwidthProofState {
                id: self.id,
                bytes_transferred: self.bytes_transferred,
                latency_ms: self.latency_ms,
                points,
                rejection_reason: None,
                _state: PhantomData,
            })
        } else {
            Err(BandwidthProofState {
                id: self.id,
                bytes_transferred: self.bytes_transferred,
                latency_ms: self.latency_ms,
                points: 0,
                rejection_reason: Some("Verification failed".to_string()),
                _state: PhantomData,
            })
        }
    }
}

impl BandwidthProofState<proof_states::Verified> {
    /// Get the awarded points (only available in Verified state).
    #[must_use]
    pub fn awarded_points(&self) -> u64 {
        self.points
    }
}

impl BandwidthProofState<proof_states::Rejected> {
    /// Get the rejection reason (only available in Rejected state).
    #[must_use]
    pub fn reason(&self) -> &str {
        self.rejection_reason
            .as_deref()
            .unwrap_or("Unknown rejection reason")
    }
}

/// Content upload lifecycle states.
pub mod content_states {
    /// Content is being uploaded
    #[derive(Debug)]
    pub struct Uploading;
    /// Upload complete, pending processing
    #[derive(Debug)]
    pub struct Processing;
    /// Content is published and available
    #[derive(Debug)]
    pub struct Published;
    /// Content is archived
    #[derive(Debug)]
    pub struct Archived;
}

/// Type-safe content upload with state machine enforcement.
#[derive(Debug, Clone)]
pub struct ContentUpload<S> {
    /// Content identifier
    pub content_id: String,
    /// Upload progress (bytes)
    pub uploaded_bytes: u64,
    /// Total size (bytes)
    pub total_bytes: u64,
    /// CID (only set in Published state)
    pub cid: Option<String>,
    _state: PhantomData<S>,
}

impl ContentUpload<content_states::Uploading> {
    /// Create a new content upload.
    #[must_use]
    pub fn new(content_id: impl Into<String>, total_bytes: u64) -> Self {
        Self {
            content_id: content_id.into(),
            uploaded_bytes: 0,
            total_bytes,
            cid: None,
            _state: PhantomData,
        }
    }

    /// Update upload progress.
    pub fn update_progress(&mut self, bytes: u64) {
        self.uploaded_bytes = self
            .uploaded_bytes
            .saturating_add(bytes)
            .min(self.total_bytes);
    }

    /// Check if upload is complete.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.uploaded_bytes >= self.total_bytes
    }

    /// Transition to Processing state when upload completes.
    #[must_use]
    pub fn complete_upload(self) -> ContentUpload<content_states::Processing> {
        ContentUpload {
            content_id: self.content_id,
            uploaded_bytes: self.uploaded_bytes,
            total_bytes: self.total_bytes,
            cid: None,
            _state: PhantomData,
        }
    }
}

impl ContentUpload<content_states::Processing> {
    /// Finish processing and publish content.
    #[must_use]
    pub fn publish(self, cid: impl Into<String>) -> ContentUpload<content_states::Published> {
        ContentUpload {
            content_id: self.content_id,
            uploaded_bytes: self.uploaded_bytes,
            total_bytes: self.total_bytes,
            cid: Some(cid.into()),
            _state: PhantomData,
        }
    }
}

impl ContentUpload<content_states::Published> {
    /// Get the content CID (only available in Published state).
    #[must_use]
    pub fn cid(&self) -> &str {
        self.cid.as_deref().unwrap_or("")
    }

    /// Archive the content.
    #[must_use]
    pub fn archive(self) -> ContentUpload<content_states::Archived> {
        ContentUpload {
            content_id: self.content_id,
            uploaded_bytes: self.uploaded_bytes,
            total_bytes: self.total_bytes,
            cid: self.cid,
            _state: PhantomData,
        }
    }
}

impl ContentUpload<content_states::Archived> {
    /// Get the archived content CID.
    #[must_use]
    pub fn archived_cid(&self) -> &str {
        self.cid.as_deref().unwrap_or("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_state_machine_happy_path() {
        // Create proof
        let proof = BandwidthProofState::<proof_states::Created>::new("proof1", 10_000_000, 100);
        assert_eq!(proof.id, "proof1");
        assert_eq!(proof.bytes_transferred, 10_000_000);

        // Submit proof
        let submitted = proof.submit();
        assert_eq!(submitted.id, "proof1");

        // Verify proof
        let verified = submitted.verify(true).unwrap();
        assert_eq!(verified.id, "proof1");
        assert_eq!(verified.awarded_points(), 10); // 10_000_000 / 1_000_000
    }

    #[test]
    fn test_proof_state_machine_rejection() {
        let proof = BandwidthProofState::<proof_states::Created>::new("proof1", 1024, 100);
        let submitted = proof.submit();
        let rejected = submitted.verify(false).unwrap_err();

        assert_eq!(rejected.id, "proof1");
        assert!(rejected.reason().contains("Verification failed"));
    }

    #[test]
    fn test_content_upload_state_machine() {
        // Start upload
        let mut upload = ContentUpload::<content_states::Uploading>::new("content1", 1000);
        assert_eq!(upload.uploaded_bytes, 0);
        assert!(!upload.is_complete());

        // Update progress
        upload.update_progress(500);
        assert_eq!(upload.uploaded_bytes, 500);
        assert!(!upload.is_complete());

        // Complete upload
        upload.update_progress(500);
        assert!(upload.is_complete());

        let processing = upload.complete_upload();
        assert_eq!(processing.content_id, "content1");

        // Publish
        let published = processing.publish("QmXXX123");
        assert_eq!(published.cid(), "QmXXX123");

        // Archive
        let archived = published.archive();
        assert_eq!(archived.archived_cid(), "QmXXX123");
    }

    #[test]
    fn test_content_upload_progress_clamping() {
        let mut upload = ContentUpload::<content_states::Uploading>::new("content1", 100);
        upload.update_progress(150); // More than total
        assert_eq!(upload.uploaded_bytes, 100); // Clamped to total
    }

    #[test]
    fn test_proof_serde() {
        let proof = BandwidthProofState::<proof_states::Created>::new("proof1", 1024, 50);
        let json = serde_json::to_string(&proof).unwrap();
        let _decoded: BandwidthProofState<proof_states::Created> =
            serde_json::from_str(&json).unwrap();
        // PhantomData doesn't serialize, but struct does
    }

    // Compile-time tests (these should fail to compile if uncommented)
    // #[test]
    // fn test_invalid_transitions() {
    //     let proof = BandwidthProofState::<proof_states::Created>::new("proof1", 1024, 100);
    //     let verified = proof.verify(true); // Error: verify() only available on Submitted
    //
    //     let submitted = proof.submit();
    //     let resubmitted = submitted.submit(); // Error: submit() only available on Created
    // }
}

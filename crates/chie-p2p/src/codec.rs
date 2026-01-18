//! Bandwidth proof protocol codec for libp2p request-response.

use async_trait::async_trait;
use chie_shared::{ChunkRequest, ChunkResponse, MAX_MESSAGE_SIZE};
use futures::prelude::*;
use libp2p::StreamProtocol;
use std::io;

/// Protocol name for bandwidth proof.
pub const BANDWIDTH_PROOF_PROTOCOL: &str = "/chie/bandwidth-proof/1.0.0";

/// Codec for the bandwidth proof protocol.
/// Uses length-prefixed bincode serialization for efficiency.
#[derive(Clone, Default)]
pub struct BandwidthProofCodec {
    max_message_size: usize,
}

impl BandwidthProofCodec {
    /// Create a new codec with default max message size.
    pub fn new() -> Self {
        Self {
            max_message_size: MAX_MESSAGE_SIZE,
        }
    }

    /// Create a codec with custom max message size.
    pub fn with_max_size(max_message_size: usize) -> Self {
        Self { max_message_size }
    }
}

#[async_trait]
impl libp2p::request_response::Codec for BandwidthProofCodec {
    type Protocol = StreamProtocol;
    type Request = ChunkRequest;
    type Response = ChunkResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_length_prefixed(io, self.max_message_size).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_length_prefixed(io, self.max_message_size).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed(io, &res).await
    }
}

/// Read a length-prefixed message from the stream.
async fn read_length_prefixed<T, M>(io: &mut T, max_size: usize) -> io::Result<M>
where
    T: AsyncRead + Unpin + Send,
    M: serde::de::DeserializeOwned,
{
    // Read 4-byte length prefix (big-endian)
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate message size
    if len > max_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Message too large: {} > {}", len, max_size),
        ));
    }

    // Read message body
    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;

    // Deserialize using bincode for efficient binary serialization
    crate::serde_helpers::decode(&buf).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Deserialization error: {}", e),
        )
    })
}

/// Write a length-prefixed message to the stream.
async fn write_length_prefixed<T, M>(io: &mut T, msg: &M) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    M: serde::Serialize,
{
    // Serialize message using bincode
    let data = crate::serde_helpers::encode(msg).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Serialization error: {}", e),
        )
    })?;

    // Write length prefix
    let len = (data.len() as u32).to_be_bytes();
    io.write_all(&len).await?;

    // Write message body
    io.write_all(&data).await?;
    io.flush().await?;

    Ok(())
}

/// Protocol support information.
pub fn protocol_support()
-> impl Iterator<Item = (&'static str, libp2p::request_response::ProtocolSupport)> {
    std::iter::once((
        BANDWIDTH_PROOF_PROTOCOL,
        libp2p::request_response::ProtocolSupport::Full,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chie_shared::ChunkRequest;
    use futures::io::Cursor;

    #[tokio::test]
    async fn test_roundtrip_request() {
        let request = ChunkRequest {
            content_cid: "QmTest123".to_string(),
            chunk_index: 42,
            challenge_nonce: [1u8; 32],
            requester_peer_id: "12D3KooW...".to_string(),
            requester_public_key: [2u8; 32],
            timestamp_ms: 1234567890000,
        };

        let mut buf = Vec::new();
        write_length_prefixed(&mut buf, &request).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: ChunkRequest = read_length_prefixed(&mut cursor, MAX_MESSAGE_SIZE)
            .await
            .unwrap();

        assert_eq!(request.content_cid, decoded.content_cid);
        assert_eq!(request.chunk_index, decoded.chunk_index);
        assert_eq!(request.challenge_nonce, decoded.challenge_nonce);
    }

    #[tokio::test]
    async fn test_bincode_smaller_than_json() {
        let request = ChunkRequest {
            content_cid: "QmTest123".to_string(),
            chunk_index: 42,
            challenge_nonce: [1u8; 32],
            requester_peer_id: "12D3KooW...".to_string(),
            requester_public_key: [2u8; 32],
            timestamp_ms: 1234567890000,
        };

        let bincode_data = crate::serde_helpers::encode(&request).unwrap();
        let json_data = serde_json::to_vec(&request).unwrap();

        // Bincode should be more compact than JSON
        assert!(bincode_data.len() < json_data.len());
    }
}

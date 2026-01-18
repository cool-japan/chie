//! WebRTC transport for browser-based nodes.
//!
//! This module enables browser clients to participate in the CHIE network
//! using WebRTC data channels. It provides:
//!
//! - WebRTC transport configuration for libp2p
//! - Signaling protocol for connection establishment
//! - STUN/TURN server configuration
//! - Browser client integration helpers

#![allow(dead_code)]

use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::{RwLock, mpsc};

/// Errors specific to WebRTC operations.
#[derive(Debug, Error)]
pub enum WebRtcError {
    #[error("Signaling failed: {0}")]
    SignalingFailed(String),

    #[error("Connection timeout")]
    ConnectionTimeout,

    #[error("ICE negotiation failed: {0}")]
    IceNegotiationFailed(String),

    #[error("Invalid offer/answer: {0}")]
    InvalidSdp(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Transport error: {0}")]
    TransportError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for WebRTC operations.
pub type WebRtcResult<T> = Result<T, WebRtcError>;

/// ICE server configuration (STUN/TURN).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceServer {
    /// Server URL(s) (e.g., "stun:stun.l.google.com:19302").
    pub urls: Vec<String>,
    /// Username for TURN authentication (optional).
    pub username: Option<String>,
    /// Credential for TURN authentication (optional).
    pub credential: Option<String>,
}

impl IceServer {
    /// Create a STUN server configuration.
    pub fn stun(url: impl Into<String>) -> Self {
        Self {
            urls: vec![url.into()],
            username: None,
            credential: None,
        }
    }

    /// Create a TURN server configuration with authentication.
    pub fn turn(
        url: impl Into<String>,
        username: impl Into<String>,
        credential: impl Into<String>,
    ) -> Self {
        Self {
            urls: vec![url.into()],
            username: Some(username.into()),
            credential: Some(credential.into()),
        }
    }

    /// Add additional URLs.
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.urls.push(url.into());
        self
    }
}

/// Default public STUN servers.
pub fn default_stun_servers() -> Vec<IceServer> {
    vec![
        IceServer::stun("stun:stun.l.google.com:19302"),
        IceServer::stun("stun:stun1.l.google.com:19302"),
        IceServer::stun("stun:stun2.l.google.com:19302"),
        IceServer::stun("stun:stun3.l.google.com:19302"),
        IceServer::stun("stun:stun4.l.google.com:19302"),
    ]
}

/// WebRTC transport configuration.
#[derive(Debug, Clone)]
pub struct WebRtcConfig {
    /// Whether WebRTC transport is enabled.
    pub enabled: bool,
    /// ICE servers (STUN/TURN).
    pub ice_servers: Vec<IceServer>,
    /// Listen address for WebRTC (with /webrtc-direct).
    pub listen_addr: Option<Multiaddr>,
    /// Connection timeout.
    pub connection_timeout: Duration,
    /// Data channel label for CHIE protocol.
    pub data_channel_label: String,
    /// Enable signaling server.
    pub enable_signaling_server: bool,
    /// Signaling server listen address.
    pub signaling_addr: Option<SocketAddr>,
    /// Maximum concurrent WebRTC connections.
    pub max_connections: usize,
}

impl Default for WebRtcConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default, must be explicitly enabled
            ice_servers: default_stun_servers(),
            listen_addr: None,
            connection_timeout: Duration::from_secs(30),
            data_channel_label: "chie-protocol".to_string(),
            enable_signaling_server: false,
            signaling_addr: None,
            max_connections: 100,
        }
    }
}

impl WebRtcConfig {
    /// Create a new WebRTC configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable WebRTC transport.
    pub fn enabled(mut self) -> Self {
        self.enabled = true;
        self
    }

    /// Set ICE servers.
    pub fn with_ice_servers(mut self, servers: Vec<IceServer>) -> Self {
        self.ice_servers = servers;
        self
    }

    /// Add an ICE server.
    pub fn add_ice_server(mut self, server: IceServer) -> Self {
        self.ice_servers.push(server);
        self
    }

    /// Set the listen address for WebRTC.
    pub fn with_listen_addr(mut self, addr: Multiaddr) -> Self {
        self.listen_addr = Some(addr);
        self
    }

    /// Enable the signaling server.
    pub fn with_signaling_server(mut self, addr: SocketAddr) -> Self {
        self.enable_signaling_server = true;
        self.signaling_addr = Some(addr);
        self
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.connection_timeout = timeout;
        self
    }

    /// Set maximum concurrent connections.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Create a WebRTC listen address from port.
    pub fn webrtc_listen_addr(port: u16) -> Multiaddr {
        format!("/ip4/0.0.0.0/udp/{}/webrtc-direct", port)
            .parse()
            .unwrap()
    }

    /// Create a WebRTC listen address for IPv6.
    pub fn webrtc_listen_addr_v6(port: u16) -> Multiaddr {
        format!("/ip6/::/udp/{}/webrtc-direct", port)
            .parse()
            .unwrap()
    }
}

/// SDP (Session Description Protocol) message types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SdpType {
    Offer,
    Answer,
}

/// SDP message for WebRTC signaling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdpMessage {
    /// Type of SDP (offer or answer).
    #[serde(rename = "type")]
    pub sdp_type: SdpType,
    /// SDP content.
    pub sdp: String,
}

impl SdpMessage {
    /// Create an offer.
    pub fn offer(sdp: impl Into<String>) -> Self {
        Self {
            sdp_type: SdpType::Offer,
            sdp: sdp.into(),
        }
    }

    /// Create an answer.
    pub fn answer(sdp: impl Into<String>) -> Self {
        Self {
            sdp_type: SdpType::Answer,
            sdp: sdp.into(),
        }
    }
}

/// ICE candidate for WebRTC connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Candidate string.
    pub candidate: String,
    /// SDP m-line index.
    pub sdp_m_line_index: u32,
    /// SDP mid.
    pub sdp_mid: Option<String>,
}

impl IceCandidate {
    /// Create a new ICE candidate.
    pub fn new(candidate: impl Into<String>, m_line_index: u32) -> Self {
        Self {
            candidate: candidate.into(),
            sdp_m_line_index: m_line_index,
            sdp_mid: None,
        }
    }

    /// Set SDP mid.
    pub fn with_mid(mut self, mid: impl Into<String>) -> Self {
        self.sdp_mid = Some(mid.into());
        self
    }
}

/// Signaling message types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalingMessage {
    /// Register with the signaling server.
    Register { peer_id: String },
    /// Registration acknowledgment.
    Registered { peer_id: String },
    /// Send SDP offer/answer to a peer.
    Sdp {
        from: String,
        to: String,
        sdp: SdpMessage,
    },
    /// Send ICE candidate to a peer.
    Ice {
        from: String,
        to: String,
        candidate: IceCandidate,
    },
    /// Peer discovery - list available peers.
    ListPeers,
    /// Peer list response.
    PeerList { peers: Vec<String> },
    /// Error message.
    Error { message: String },
    /// Peer disconnected notification.
    PeerDisconnected { peer_id: String },
}

/// Connection state for WebRTC peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Initial state.
    New,
    /// Connecting (ICE gathering).
    Connecting,
    /// Connected and ready.
    Connected,
    /// Connection failed.
    Failed,
    /// Connection closed.
    Closed,
}

/// WebRTC peer connection info.
#[derive(Debug, Clone)]
pub struct WebRtcPeerInfo {
    /// Peer identifier.
    pub peer_id: String,
    /// Connection state.
    pub state: ConnectionState,
    /// Local ICE candidates.
    pub local_candidates: Vec<IceCandidate>,
    /// Remote ICE candidates.
    pub remote_candidates: Vec<IceCandidate>,
    /// Connection established timestamp.
    pub connected_at: Option<u64>,
    /// Data channel ready.
    pub data_channel_ready: bool,
}

impl WebRtcPeerInfo {
    /// Create new peer info.
    pub fn new(peer_id: impl Into<String>) -> Self {
        Self {
            peer_id: peer_id.into(),
            state: ConnectionState::New,
            local_candidates: Vec::new(),
            remote_candidates: Vec::new(),
            connected_at: None,
            data_channel_ready: false,
        }
    }
}

/// Signaling server for WebRTC connection establishment.
///
/// This server helps browser clients and native nodes establish
/// WebRTC connections by relaying SDP offers/answers and ICE candidates.
pub struct SignalingServer {
    /// Configuration.
    config: WebRtcConfig,
    /// Registered peers (peer_id -> sender channel).
    peers: Arc<RwLock<HashMap<String, mpsc::Sender<SignalingMessage>>>>,
    /// Running state.
    running: Arc<RwLock<bool>>,
}

impl SignalingServer {
    /// Create a new signaling server.
    pub fn new(config: WebRtcConfig) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
        }
    }

    /// Check if server is running.
    pub async fn is_running(&self) -> bool {
        *self.running.read().await
    }

    /// Get number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get list of connected peer IDs.
    pub async fn list_peers(&self) -> Vec<String> {
        self.peers.read().await.keys().cloned().collect()
    }

    /// Register a peer.
    pub async fn register_peer(
        &self,
        peer_id: String,
        sender: mpsc::Sender<SignalingMessage>,
    ) -> WebRtcResult<()> {
        let mut peers = self.peers.write().await;

        if peers.len() >= self.config.max_connections {
            return Err(WebRtcError::ConfigError(
                "Maximum peer connections reached".to_string(),
            ));
        }

        peers.insert(peer_id.clone(), sender);

        // Notify all other peers about new peer
        let notification = SignalingMessage::PeerList {
            peers: peers.keys().cloned().collect(),
        };

        for (id, tx) in peers.iter() {
            if *id != peer_id {
                let _ = tx.send(notification.clone()).await;
            }
        }

        Ok(())
    }

    /// Unregister a peer.
    pub async fn unregister_peer(&self, peer_id: &str) {
        let mut peers = self.peers.write().await;
        peers.remove(peer_id);

        // Notify remaining peers
        let notification = SignalingMessage::PeerDisconnected {
            peer_id: peer_id.to_string(),
        };

        for tx in peers.values() {
            let _ = tx.send(notification.clone()).await;
        }
    }

    /// Relay a message to a peer.
    pub async fn relay_message(&self, to: &str, message: SignalingMessage) -> WebRtcResult<()> {
        let peers = self.peers.read().await;

        let sender = peers
            .get(to)
            .ok_or_else(|| WebRtcError::PeerNotFound(to.to_string()))?;

        sender
            .send(message)
            .await
            .map_err(|_| WebRtcError::ChannelClosed)?;

        Ok(())
    }

    /// Handle incoming signaling message.
    pub async fn handle_message(
        &self,
        from: &str,
        message: SignalingMessage,
    ) -> WebRtcResult<Option<SignalingMessage>> {
        match message {
            SignalingMessage::Sdp { to, sdp, .. } => {
                let relay = SignalingMessage::Sdp {
                    from: from.to_string(),
                    to: to.clone(),
                    sdp,
                };
                self.relay_message(&to, relay).await?;
                Ok(None)
            }
            SignalingMessage::Ice { to, candidate, .. } => {
                let relay = SignalingMessage::Ice {
                    from: from.to_string(),
                    to: to.clone(),
                    candidate,
                };
                self.relay_message(&to, relay).await?;
                Ok(None)
            }
            SignalingMessage::ListPeers => {
                let peers = self.list_peers().await;
                Ok(Some(SignalingMessage::PeerList { peers }))
            }
            _ => Ok(None),
        }
    }
}

/// Statistics for WebRTC connections.
#[derive(Debug, Clone, Default)]
pub struct WebRtcStats {
    /// Total connections established.
    pub total_connections: u64,
    /// Currently active connections.
    pub active_connections: usize,
    /// Failed connections.
    pub failed_connections: u64,
    /// Bytes sent over WebRTC.
    pub bytes_sent: u64,
    /// Bytes received over WebRTC.
    pub bytes_received: u64,
    /// Average connection setup time (ms).
    pub avg_setup_time_ms: u64,
    /// ICE candidates gathered.
    pub ice_candidates_gathered: u64,
}

/// Helper for generating browser-compatible JavaScript.
///
/// This generates JavaScript code that browser clients can use
/// to connect to CHIE network nodes via WebRTC.
pub struct BrowserClientHelper {
    config: WebRtcConfig,
}

impl BrowserClientHelper {
    /// Create a new browser client helper.
    pub fn new(config: WebRtcConfig) -> Self {
        Self { config }
    }

    /// Generate ICE servers configuration as JSON for browser.
    pub fn ice_servers_json(&self) -> String {
        serde_json::to_string_pretty(&self.config.ice_servers).unwrap_or_else(|_| "[]".to_string())
    }

    /// Generate JavaScript code for WebRTC connection setup.
    pub fn generate_connection_js(&self, signaling_url: &str) -> String {
        let ice_servers = self.ice_servers_json();
        format!(
            r#"// CHIE WebRTC Browser Client
// Generated configuration for connecting to CHIE network

const CHIE_CONFIG = {{
  signalingUrl: '{}',
  iceServers: {},
  dataChannelLabel: '{}',
  connectionTimeout: {}
}};

class ChieWebRtcClient {{
  constructor(config = CHIE_CONFIG) {{
    this.config = config;
    this.peerConnection = null;
    this.dataChannel = null;
    this.signalingSocket = null;
    this.peerId = this.generatePeerId();
  }}

  generatePeerId() {{
    return 'browser-' + Math.random().toString(36).substring(2, 15);
  }}

  async connect() {{
    // Initialize WebSocket for signaling
    this.signalingSocket = new WebSocket(this.config.signalingUrl);

    this.signalingSocket.onopen = () => {{
      this.signalingSocket.send(JSON.stringify({{
        type: 'register',
        peer_id: this.peerId
      }}));
    }};

    this.signalingSocket.onmessage = (event) => {{
      this.handleSignalingMessage(JSON.parse(event.data));
    }};

    // Create peer connection
    this.peerConnection = new RTCPeerConnection({{
      iceServers: this.config.iceServers.map(s => ({{
        urls: s.urls,
        username: s.username,
        credential: s.credential
      }}))
    }});

    this.peerConnection.onicecandidate = (event) => {{
      if (event.candidate) {{
        // Send candidate to signaling server
        this.signalingSocket.send(JSON.stringify({{
          type: 'ice',
          from: this.peerId,
          to: this.targetPeerId,
          candidate: {{
            candidate: event.candidate.candidate,
            sdp_m_line_index: event.candidate.sdpMLineIndex,
            sdp_mid: event.candidate.sdpMid
          }}
        }}));
      }}
    }};

    this.peerConnection.ondatachannel = (event) => {{
      this.dataChannel = event.channel;
      this.setupDataChannel();
    }};
  }}

  setupDataChannel() {{
    this.dataChannel.onopen = () => {{
      console.log('CHIE data channel open');
      this.onConnected?.();
    }};

    this.dataChannel.onmessage = (event) => {{
      this.onMessage?.(event.data);
    }};

    this.dataChannel.onclose = () => {{
      console.log('CHIE data channel closed');
      this.onDisconnected?.();
    }};
  }}

  async initiateConnection(targetPeerId) {{
    this.targetPeerId = targetPeerId;

    // Create data channel
    this.dataChannel = this.peerConnection.createDataChannel(this.config.dataChannelLabel);
    this.setupDataChannel();

    // Create and send offer
    const offer = await this.peerConnection.createOffer();
    await this.peerConnection.setLocalDescription(offer);

    this.signalingSocket.send(JSON.stringify({{
      type: 'sdp',
      from: this.peerId,
      to: targetPeerId,
      sdp: {{
        type: 'offer',
        sdp: offer.sdp
      }}
    }}));
  }}

  async handleSignalingMessage(message) {{
    switch (message.type) {{
      case 'sdp':
        await this.handleSdp(message);
        break;
      case 'ice':
        await this.handleIceCandidate(message);
        break;
      case 'peer_list':
        this.onPeerList?.(message.peers);
        break;
      case 'error':
        console.error('Signaling error:', message.message);
        break;
    }}
  }}

  async handleSdp(message) {{
    const description = new RTCSessionDescription({{
      type: message.sdp.type,
      sdp: message.sdp.sdp
    }});

    await this.peerConnection.setRemoteDescription(description);

    if (message.sdp.type === 'offer') {{
      this.targetPeerId = message.from;
      const answer = await this.peerConnection.createAnswer();
      await this.peerConnection.setLocalDescription(answer);

      this.signalingSocket.send(JSON.stringify({{
        type: 'sdp',
        from: this.peerId,
        to: message.from,
        sdp: {{
          type: 'answer',
          sdp: answer.sdp
        }}
      }}));
    }}
  }}

  async handleIceCandidate(message) {{
    const candidate = new RTCIceCandidate({{
      candidate: message.candidate.candidate,
      sdpMLineIndex: message.candidate.sdp_m_line_index,
      sdpMid: message.candidate.sdp_mid
    }});
    await this.peerConnection.addIceCandidate(candidate);
  }}

  send(data) {{
    if (this.dataChannel?.readyState === 'open') {{
      this.dataChannel.send(data);
    }}
  }}

  disconnect() {{
    this.dataChannel?.close();
    this.peerConnection?.close();
    this.signalingSocket?.close();
  }}
}}

// Export for ES modules
if (typeof module !== 'undefined' && module.exports) {{
  module.exports = {{ ChieWebRtcClient, CHIE_CONFIG }};
}}
"#,
            signaling_url,
            ice_servers,
            self.config.data_channel_label,
            self.config.connection_timeout.as_millis()
        )
    }

    /// Generate minimal JavaScript snippet for quick testing.
    pub fn generate_quick_connect_js(&self, signaling_url: &str, target_peer: &str) -> String {
        format!(
            r#"// Quick connect to CHIE node
// Signaling server: {}
const client = new ChieWebRtcClient();
client.onConnected = () => console.log('Connected to CHIE network!');
client.onMessage = (msg) => console.log('Received:', msg);
await client.connect();
await client.initiateConnection('{}');
"#,
            signaling_url, target_peer
        )
    }
}

/// Check if a multiaddr is a WebRTC address.
pub fn is_webrtc_addr(addr: &Multiaddr) -> bool {
    addr.to_string().contains("/webrtc")
}

/// Convert a TCP/QUIC address to WebRTC equivalent.
pub fn to_webrtc_addr(addr: &Multiaddr) -> Option<Multiaddr> {
    let addr_str = addr.to_string();

    // Extract port from TCP or QUIC address
    if let Some(port_start) = addr_str.find("/tcp/").or(addr_str.find("/udp/")) {
        let port_str = &addr_str[port_start + 5..];
        if let Some(port_end) = port_str.find('/') {
            if let Ok(port) = port_str[..port_end].parse::<u16>() {
                let ip_part = &addr_str[..port_start];
                return format!("{}/udp/{}/webrtc-direct", ip_part, port)
                    .parse()
                    .ok();
            }
        } else if let Ok(port) = port_str.parse::<u16>() {
            let ip_part = &addr_str[..port_start];
            return format!("{}/udp/{}/webrtc-direct", ip_part, port)
                .parse()
                .ok();
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webrtc_config_default() {
        let config = WebRtcConfig::default();
        assert!(!config.enabled);
        assert!(!config.ice_servers.is_empty());
    }

    #[test]
    fn test_webrtc_config_builder() {
        let config = WebRtcConfig::new()
            .enabled()
            .with_timeout(Duration::from_secs(60))
            .with_max_connections(50);

        assert!(config.enabled);
        assert_eq!(config.connection_timeout, Duration::from_secs(60));
        assert_eq!(config.max_connections, 50);
    }

    #[test]
    fn test_ice_server_stun() {
        let server = IceServer::stun("stun:example.com:3478");
        assert_eq!(server.urls.len(), 1);
        assert!(server.username.is_none());
    }

    #[test]
    fn test_ice_server_turn() {
        let server = IceServer::turn("turn:example.com:3478", "user", "pass");
        assert_eq!(server.urls.len(), 1);
        assert_eq!(server.username, Some("user".to_string()));
        assert_eq!(server.credential, Some("pass".to_string()));
    }

    #[test]
    fn test_sdp_message() {
        let offer = SdpMessage::offer("v=0\r\n...");
        assert_eq!(offer.sdp_type, SdpType::Offer);

        let answer = SdpMessage::answer("v=0\r\n...");
        assert_eq!(answer.sdp_type, SdpType::Answer);
    }

    #[test]
    fn test_ice_candidate() {
        let candidate = IceCandidate::new("candidate:...", 0).with_mid("0");

        assert_eq!(candidate.sdp_m_line_index, 0);
        assert_eq!(candidate.sdp_mid, Some("0".to_string()));
    }

    #[test]
    fn test_webrtc_peer_info() {
        let info = WebRtcPeerInfo::new("peer-123");
        assert_eq!(info.state, ConnectionState::New);
        assert!(!info.data_channel_ready);
    }

    #[test]
    fn test_webrtc_listen_addr() {
        let addr = WebRtcConfig::webrtc_listen_addr(9090);
        assert!(addr.to_string().contains("/webrtc-direct"));
        assert!(addr.to_string().contains("/udp/9090"));
    }

    #[test]
    fn test_is_webrtc_addr() {
        let webrtc: Multiaddr = "/ip4/0.0.0.0/udp/9090/webrtc-direct".parse().unwrap();
        let tcp: Multiaddr = "/ip4/0.0.0.0/tcp/9090".parse().unwrap();

        assert!(is_webrtc_addr(&webrtc));
        assert!(!is_webrtc_addr(&tcp));
    }

    #[test]
    fn test_to_webrtc_addr() {
        let tcp: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let webrtc = to_webrtc_addr(&tcp).unwrap();
        assert!(webrtc.to_string().contains("/webrtc-direct"));
    }

    #[test]
    fn test_signaling_message_serialization() {
        let msg = SignalingMessage::Register {
            peer_id: "test-peer".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("register"));
        assert!(json.contains("test-peer"));
    }

    #[test]
    fn test_browser_client_helper() {
        let config = WebRtcConfig::new().enabled();
        let helper = BrowserClientHelper::new(config);

        let js = helper.generate_connection_js("ws://localhost:8080/signaling");
        assert!(js.contains("ChieWebRtcClient"));
        assert!(js.contains("ws://localhost:8080/signaling"));
    }

    #[test]
    fn test_default_stun_servers() {
        let servers = default_stun_servers();
        assert!(!servers.is_empty());
        assert!(servers[0].urls[0].starts_with("stun:"));
    }

    #[tokio::test]
    async fn test_signaling_server() {
        let config = WebRtcConfig::new();
        let server = SignalingServer::new(config);

        assert!(!server.is_running().await);
        assert_eq!(server.peer_count().await, 0);

        let (tx, rx) = mpsc::channel(16);
        server
            .register_peer("peer-1".to_string(), tx)
            .await
            .unwrap();

        assert_eq!(server.peer_count().await, 1);
        assert!(server.list_peers().await.contains(&"peer-1".to_string()));

        // Test message handling
        let response = server
            .handle_message("peer-1", SignalingMessage::ListPeers)
            .await
            .unwrap();

        if let Some(SignalingMessage::PeerList { peers }) = response {
            assert!(peers.contains(&"peer-1".to_string()));
        } else {
            panic!("Expected PeerList response");
        }

        server.unregister_peer("peer-1").await;
        assert_eq!(server.peer_count().await, 0);

        // Drain channel
        drop(rx);
    }
}

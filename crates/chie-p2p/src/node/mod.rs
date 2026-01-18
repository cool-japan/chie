//! P2P Node implementation with swarm management.

use crate::{BANDWIDTH_PROOF_PROTOCOL, BandwidthProofCodec};
use chie_crypto::KeyPair;
use chie_shared::{ChunkRequest, ChunkResponse};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm,
    connection_limits::{self, ConnectionLimits},
    gossipsub, identify, kad,
    request_response::{self, OutboundRequestId, ResponseChannel},
    swarm::{NetworkBehaviour, SwarmEvent},
};
use std::collections::HashMap;
use std::convert::Infallible;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Events emitted by the P2P node.
#[derive(Debug)]
pub enum NodeEvent {
    /// A chunk was requested from us.
    ChunkRequested {
        peer: PeerId,
        request: ChunkRequest,
        channel: ResponseChannel<ChunkResponse>,
    },
    /// We received a chunk response.
    ChunkReceived {
        peer: PeerId,
        request_id: OutboundRequestId,
        response: ChunkResponse,
    },
    /// A chunk request failed.
    ChunkRequestFailed {
        peer: PeerId,
        request_id: OutboundRequestId,
        error: String,
    },
    /// A new peer was discovered.
    PeerDiscovered(PeerId),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// Connection established.
    ConnectionEstablished { peer: PeerId, num_established: u32 },
}

/// Configuration for the P2P node.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Listen addresses (TCP).
    pub listen_addrs: Vec<Multiaddr>,
    /// QUIC listen addresses.
    pub quic_listen_addrs: Vec<Multiaddr>,
    /// Enable QUIC transport.
    pub enable_quic: bool,
    /// Bootstrap nodes for initial discovery.
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    /// Enable mDNS for local discovery.
    pub enable_mdns: bool,
    /// Gossipsub topic for network announcements.
    pub gossip_topic: String,
    /// Connection idle timeout.
    pub idle_timeout: Duration,
    /// Maximum total connections.
    pub max_connections: u32,
    /// Maximum connections per peer.
    pub max_connections_per_peer: u32,
    /// Maximum established incoming connections.
    pub max_established_incoming: u32,
    /// Maximum established outgoing connections.
    pub max_established_outgoing: u32,
    /// Maximum pending incoming connections.
    pub max_pending_incoming: u32,
    /// Maximum pending outgoing connections.
    pub max_pending_outgoing: u32,
    /// Rate limit: max requests per minute per peer.
    pub max_requests_per_minute: u32,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addrs: vec![
                "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
                "/ip6/::/tcp/0".parse().unwrap(),
            ],
            quic_listen_addrs: vec![
                "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
                "/ip6/::/udp/0/quic-v1".parse().unwrap(),
            ],
            enable_quic: true,
            bootstrap_nodes: vec![],
            enable_mdns: true,
            gossip_topic: "chie/network/v1".to_string(),
            idle_timeout: Duration::from_secs(30),
            max_connections: 100,
            max_connections_per_peer: 2,
            max_established_incoming: 50,
            max_established_outgoing: 50,
            max_pending_incoming: 20,
            max_pending_outgoing: 20,
            max_requests_per_minute: 60,
        }
    }
}

/// Combined network behaviour for CHIE nodes.
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "NodeBehaviourEvent")]
pub struct NodeBehaviour {
    /// Connection limits.
    pub connection_limits: connection_limits::Behaviour,
    /// Request-response protocol for bandwidth proofs.
    pub request_response: request_response::Behaviour<BandwidthProofCodec>,
    /// Kademlia DHT for peer discovery.
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Gossipsub for pub/sub messaging.
    pub gossipsub: gossipsub::Behaviour,
    /// Identify protocol for peer information exchange.
    pub identify: identify::Behaviour,
}

/// Events from the combined behaviour.
#[derive(Debug)]
pub enum NodeBehaviourEvent {
    RequestResponse(request_response::Event<ChunkRequest, ChunkResponse>),
    Kademlia(kad::Event),
    Gossipsub(gossipsub::Event),
    Identify(Box<identify::Event>),
}

impl From<Infallible> for NodeBehaviourEvent {
    fn from(event: Infallible) -> Self {
        // connection_limits::Behaviour events are Infallible (never happen)
        match event {}
    }
}

impl From<request_response::Event<ChunkRequest, ChunkResponse>> for NodeBehaviourEvent {
    fn from(event: request_response::Event<ChunkRequest, ChunkResponse>) -> Self {
        NodeBehaviourEvent::RequestResponse(event)
    }
}

impl From<kad::Event> for NodeBehaviourEvent {
    fn from(event: kad::Event) -> Self {
        NodeBehaviourEvent::Kademlia(event)
    }
}

impl From<gossipsub::Event> for NodeBehaviourEvent {
    fn from(event: gossipsub::Event) -> Self {
        NodeBehaviourEvent::Gossipsub(event)
    }
}

impl From<identify::Event> for NodeBehaviourEvent {
    fn from(event: identify::Event) -> Self {
        NodeBehaviourEvent::Identify(Box::new(event))
    }
}

/// P2P Node for the CHIE network.
pub struct P2PNode {
    /// The libp2p swarm.
    swarm: Swarm<NodeBehaviour>,
    /// Our keypair.
    keypair: KeyPair,
    /// Our peer ID.
    peer_id: PeerId,
    /// Pending chunk requests (request_id -> callback).
    pending_requests: HashMap<OutboundRequestId, PendingRequest>,
    /// Event sender.
    event_tx: mpsc::Sender<NodeEvent>,
    /// Known peers and their addresses.
    known_peers: HashMap<PeerId, Vec<Multiaddr>>,
    /// Rate limiter state per peer.
    rate_limiter: RateLimiter,
    /// Configuration.
    config: NodeConfig,
}

/// A pending outbound request.
#[allow(dead_code)]
struct PendingRequest {
    peer: PeerId,
    request: ChunkRequest,
    started_at: Instant,
}

/// Simple rate limiter for requests per peer.
pub struct RateLimiter {
    /// Request timestamps per peer.
    peer_requests: HashMap<PeerId, Vec<Instant>>,
    /// Maximum requests per minute.
    max_per_minute: u32,
    /// Window duration.
    window: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            peer_requests: HashMap::new(),
            max_per_minute,
            window: Duration::from_secs(60),
        }
    }

    /// Check if a request from a peer should be allowed.
    pub fn check(&mut self, peer: &PeerId) -> bool {
        let now = Instant::now();
        let requests = self.peer_requests.entry(*peer).or_default();

        // Remove old requests outside the window
        requests.retain(|&t| now.duration_since(t) < self.window);

        // Check if under limit
        if requests.len() >= self.max_per_minute as usize {
            return false;
        }

        // Record this request
        requests.push(now);
        true
    }

    /// Get the number of recent requests from a peer.
    pub fn request_count(&self, peer: &PeerId) -> usize {
        self.peer_requests.get(peer).map(|r| r.len()).unwrap_or(0)
    }

    /// Clean up old entries.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.peer_requests.retain(|_, requests| {
            requests.retain(|&t| now.duration_since(t) < self.window);
            !requests.is_empty()
        });
    }
}

/// Build the node behaviour.
fn build_behaviour(
    key: &libp2p::identity::Keypair,
    connection_limits_config: ConnectionLimits,
) -> NodeBehaviour {
    // Connection limits
    let connection_limits = connection_limits::Behaviour::new(connection_limits_config);

    // Request-response for bandwidth proofs
    let request_response = request_response::Behaviour::new(
        [(
            StreamProtocol::new(BANDWIDTH_PROOF_PROTOCOL),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default().with_request_timeout(Duration::from_secs(30)),
    );

    // Kademlia DHT
    let kad_store = kad::store::MemoryStore::new(key.public().to_peer_id());
    let kademlia = kad::Behaviour::new(key.public().to_peer_id(), kad_store);

    // Gossipsub
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(10))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .build()
        .expect("Valid gossipsub config");

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossipsub_config,
    )
    .expect("Valid gossipsub behaviour");

    // Identify
    let identify = identify::Behaviour::new(identify::Config::new(
        "/chie/1.0.0".to_string(),
        key.public(),
    ));

    NodeBehaviour {
        connection_limits,
        request_response,
        kademlia,
        gossipsub,
        identify,
    }
}

impl P2PNode {
    /// Create a new P2P node.
    pub async fn new(
        config: NodeConfig,
        event_tx: mpsc::Sender<NodeEvent>,
    ) -> anyhow::Result<Self> {
        let keypair = KeyPair::generate();
        let libp2p_keypair = libp2p::identity::Keypair::generate_ed25519();
        let peer_id = PeerId::from(libp2p_keypair.public());

        info!("Local peer ID: {}", peer_id);

        // Build connection limits from config
        let connection_limits_config = ConnectionLimits::default()
            .with_max_established(Some(config.max_connections))
            .with_max_established_incoming(Some(config.max_established_incoming))
            .with_max_established_outgoing(Some(config.max_established_outgoing))
            .with_max_pending_incoming(Some(config.max_pending_incoming))
            .with_max_pending_outgoing(Some(config.max_pending_outgoing))
            .with_max_established_per_peer(Some(config.max_connections_per_peer));

        // Build the swarm with TCP and optionally QUIC
        let swarm_builder = libp2p::SwarmBuilder::with_existing_identity(libp2p_keypair)
            .with_tokio()
            .with_tcp(
                libp2p::tcp::Config::default(),
                libp2p::noise::Config::new,
                libp2p::yamux::Config::default,
            )?;

        // Add QUIC transport if enabled
        let swarm = if config.enable_quic {
            info!("QUIC transport enabled");
            swarm_builder
                .with_quic()
                .with_behaviour(|key| build_behaviour(key, connection_limits_config))?
                .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(config.idle_timeout))
                .build()
        } else {
            swarm_builder
                .with_behaviour(|key| build_behaviour(key, connection_limits_config))?
                .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(config.idle_timeout))
                .build()
        };

        let rate_limiter = RateLimiter::new(config.max_requests_per_minute);

        let mut node = Self {
            swarm,
            keypair,
            peer_id,
            pending_requests: HashMap::new(),
            event_tx,
            known_peers: HashMap::new(),
            rate_limiter,
            config: config.clone(),
        };

        // Start listening on TCP addresses
        for addr in &config.listen_addrs {
            node.swarm.listen_on(addr.clone())?;
        }

        // Start listening on QUIC addresses if enabled
        if config.enable_quic {
            for addr in &config.quic_listen_addrs {
                node.swarm.listen_on(addr.clone())?;
            }
        }

        // Connect to bootstrap nodes
        for (peer_id, addr) in &config.bootstrap_nodes {
            node.swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer_id, addr.clone());
            if let Err(e) = node.swarm.dial(addr.clone()) {
                warn!("Failed to dial bootstrap node {}: {}", addr, e);
            }
        }

        Ok(node)
    }

    /// Check if a request from a peer should be allowed (rate limiting).
    pub fn check_rate_limit(&mut self, peer: &PeerId) -> bool {
        self.rate_limiter.check(peer)
    }

    /// Get current request count for a peer.
    pub fn request_count(&self, peer: &PeerId) -> usize {
        self.rate_limiter.request_count(peer)
    }

    /// Get connection statistics.
    pub fn connection_stats(&self) -> ConnectionStats {
        ConnectionStats {
            connected_peers: self.swarm.connected_peers().count(),
            known_peers: self.known_peers.len(),
            pending_requests: self.pending_requests.len(),
            max_connections: self.config.max_connections,
        }
    }
}

/// Connection statistics.
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    pub connected_peers: usize,
    pub known_peers: usize,
    pub pending_requests: usize,
    pub max_connections: u32,
}

impl P2PNode {
    /// Get our peer ID.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Get our public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair.public_key()
    }

    /// Get our keypair for signing.
    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// Request a chunk from a peer.
    pub fn request_chunk(&mut self, peer: PeerId, request: ChunkRequest) -> OutboundRequestId {
        let request_id = self
            .swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer, request.clone());

        self.pending_requests.insert(
            request_id,
            PendingRequest {
                peer,
                request,
                started_at: std::time::Instant::now(),
            },
        );

        request_id
    }

    /// Send a chunk response.
    #[allow(clippy::result_large_err)]
    pub fn send_response(
        &mut self,
        channel: ResponseChannel<ChunkResponse>,
        response: ChunkResponse,
    ) -> Result<(), ChunkResponse> {
        self.swarm
            .behaviour_mut()
            .request_response
            .send_response(channel, response)
    }

    /// Add a known peer address.
    pub fn add_peer_address(&mut self, peer: PeerId, addr: Multiaddr) {
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer, addr.clone());
        self.known_peers.entry(peer).or_default().push(addr);
    }

    /// Dial a peer.
    pub fn dial(&mut self, peer: PeerId) -> anyhow::Result<()> {
        self.swarm.dial(peer)?;
        Ok(())
    }

    /// Subscribe to a gossipsub topic.
    pub fn subscribe(&mut self, topic: &str) -> anyhow::Result<()> {
        let topic = gossipsub::IdentTopic::new(topic);
        self.swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
        Ok(())
    }

    /// Publish a message to a gossipsub topic.
    pub fn publish(&mut self, topic: &str, data: Vec<u8>) -> anyhow::Result<()> {
        let topic = gossipsub::IdentTopic::new(topic);
        self.swarm.behaviour_mut().gossipsub.publish(topic, data)?;
        Ok(())
    }

    /// Get connected peers count.
    pub fn connected_peers_count(&self) -> usize {
        self.swarm.connected_peers().count()
    }

    /// Get list of connected peers.
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.swarm.connected_peers().cloned().collect()
    }

    /// Run the event loop (call this in a spawned task).
    pub async fn run(&mut self) {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(event) => {
                    self.handle_behaviour_event(event).await;
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    num_established,
                    ..
                } => {
                    let num: u32 = num_established.into();
                    info!("Connected to peer: {} (total: {})", peer_id, num);
                    let _ = self
                        .event_tx
                        .send(NodeEvent::ConnectionEstablished {
                            peer: peer_id,
                            num_established: num,
                        })
                        .await;
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    debug!("Disconnected from peer: {}", peer_id);
                    let _ = self
                        .event_tx
                        .send(NodeEvent::PeerDisconnected(peer_id))
                        .await;
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on: {}", address);
                }
                SwarmEvent::IncomingConnection { .. } => {
                    debug!("Incoming connection");
                }
                _ => {}
            }
        }
    }

    /// Handle a behaviour event.
    async fn handle_behaviour_event(&mut self, event: NodeBehaviourEvent) {
        match event {
            NodeBehaviourEvent::RequestResponse(req_res_event) => {
                self.handle_request_response(req_res_event).await;
            }
            NodeBehaviourEvent::Kademlia(kad_event) => {
                self.handle_kademlia(kad_event).await;
            }
            NodeBehaviourEvent::Gossipsub(gossip_event) => {
                self.handle_gossipsub(gossip_event).await;
            }
            NodeBehaviourEvent::Identify(identify_event) => {
                self.handle_identify(*identify_event).await;
            }
        }
    }

    /// Handle request-response events.
    async fn handle_request_response(
        &mut self,
        event: request_response::Event<ChunkRequest, ChunkResponse>,
    ) {
        match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    debug!("Received chunk request from {}", peer);
                    let _ = self
                        .event_tx
                        .send(NodeEvent::ChunkRequested {
                            peer,
                            request,
                            channel,
                        })
                        .await;
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    debug!("Received chunk response for request {:?}", request_id);
                    if let Some(_pending) = self.pending_requests.remove(&request_id) {
                        let _ = self
                            .event_tx
                            .send(NodeEvent::ChunkReceived {
                                peer,
                                request_id,
                                response,
                            })
                            .await;
                    }
                }
            },
            request_response::Event::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                warn!("Outbound request to {} failed: {:?}", peer, error);
                if let Some(_pending) = self.pending_requests.remove(&request_id) {
                    let _ = self
                        .event_tx
                        .send(NodeEvent::ChunkRequestFailed {
                            peer,
                            request_id,
                            error: format!("{:?}", error),
                        })
                        .await;
                }
            }
            request_response::Event::InboundFailure { peer, error, .. } => {
                warn!("Inbound request from {} failed: {:?}", peer, error);
            }
            request_response::Event::ResponseSent { peer, .. } => {
                debug!("Response sent to {}", peer);
            }
        }
    }

    /// Handle Kademlia events.
    async fn handle_kademlia(&mut self, event: kad::Event) {
        match event {
            kad::Event::RoutingUpdated { peer, .. } => {
                debug!("Kademlia routing updated for peer: {}", peer);
                let _ = self.event_tx.send(NodeEvent::PeerDiscovered(peer)).await;
            }
            kad::Event::OutboundQueryProgressed { result, .. } => {
                debug!("Kademlia query progress: {:?}", result);
            }
            _ => {}
        }
    }

    /// Handle Gossipsub events.
    async fn handle_gossipsub(&mut self, event: gossipsub::Event) {
        match event {
            gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            } => {
                debug!(
                    "Gossipsub message from {}: {} bytes",
                    propagation_source,
                    message.data.len()
                );
            }
            gossipsub::Event::Subscribed { peer_id, topic } => {
                debug!("Peer {} subscribed to {}", peer_id, topic);
            }
            gossipsub::Event::Unsubscribed { peer_id, topic } => {
                debug!("Peer {} unsubscribed from {}", peer_id, topic);
            }
            _ => {}
        }
    }

    /// Handle Identify events.
    async fn handle_identify(&mut self, event: identify::Event) {
        match event {
            identify::Event::Received { peer_id, info, .. } => {
                debug!(
                    "Identified peer {}: {} with {} addresses",
                    peer_id,
                    info.protocol_version,
                    info.listen_addrs.len()
                );
                // Add discovered addresses to Kademlia
                for addr in info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr);
                }
            }
            identify::Event::Sent { peer_id, .. } => {
                debug!("Sent identify to {}", peer_id);
            }
            _ => {}
        }
    }
}

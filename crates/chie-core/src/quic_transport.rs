//! QUIC Transport Integration
//!
//! This module provides QUIC (Quick UDP Internet Connections) transport support for
//! the CHIE protocol, offering improved performance, reliability, and security compared
//! to traditional TCP-based transports.
//!
//! # Features
//!
//! - **Modern Transport Protocol**: QUIC combines the best of TCP, TLS, and HTTP/2
//! - **Zero-RTT Connection Establishment**: Reduced latency for repeat connections
//! - **Multiplexing**: Multiple streams over a single connection without head-of-line blocking
//! - **Connection Migration**: Seamless connection handover between networks
//! - **Built-in Encryption**: TLS 1.3 encryption by default
//! - **Congestion Control**: Improved algorithms for better throughput
//! - **Stream Prioritization**: Efficient resource allocation
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │                    QuicEndpoint                         │
//! │  ┌────────────────┐  ┌─────────────────────────┐       │
//! │  │ Server Binding │  │  Client Configuration   │       │
//! │  └────────────────┘  └─────────────────────────┘       │
//! └──────────────────────┬──────────────────────────────────┘
//!                        │
//!         ┌──────────────┴──────────────┐
//!         │                             │
//!    ┌────▼─────┐                  ┌────▼─────┐
//!    │Connection│                  │Connection│
//!    │  Pool    │                  │ Manager  │
//!    └────┬─────┘                  └────┬─────┘
//!         │                             │
//!    ┌────▼──────────────────────────────▼─────┐
//!    │         Bidirectional Streams           │
//!    │  ┌──────────┐      ┌──────────┐        │
//!    │  │  Send    │      │ Receive  │        │
//!    │  └──────────┘      └──────────┘        │
//!    └────────────────────────────────────────┘
//! ```
//!
//! # Usage Examples
//!
//! ## Server Setup
//!
//! ```rust
//! use chie_core::quic_transport::{QuicConfig, QuicEndpoint};
//!
//! # async fn example() -> anyhow::Result<()> {
//! // Configure QUIC server
//! let config = QuicConfig::builder()
//!     .with_max_concurrent_streams(100)
//!     .with_max_idle_timeout(std::time::Duration::from_secs(30))
//!     .with_keep_alive_interval(std::time::Duration::from_secs(5))
//!     .build();
//!
//! // Create server endpoint
//! let mut endpoint = QuicEndpoint::server("127.0.0.1:4433", config).await?;
//!
//! // Accept incoming connections
//! while let Some(connecting) = endpoint.accept().await {
//!     tokio::spawn(async move {
//!         if let Ok(connection) = connecting.accept().await {
//!             // Handle connection
//!         }
//!     });
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Client Connection
//!
//! ```rust
//! use chie_core::quic_transport::{QuicConfig, QuicEndpoint};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = QuicConfig::default();
//! let endpoint = QuicEndpoint::client(config).await?;
//!
//! // Connect to server
//! let connection = endpoint.connect("127.0.0.1:4433", "localhost").await?;
//!
//! // Open bidirectional stream
//! let mut stream = connection.open_bidirectional_stream().await?;
//! stream.send(b"Hello, QUIC!").await?;
//! stream.finish().await?;
//!
//! let response = stream.receive_all().await?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Stream Communication
//!
//! ```rust
//! # use chie_core::quic_transport::*;
//! # async fn example(mut stream: QuicStream) -> anyhow::Result<()> {
//! // Send data
//! stream.send(b"request data").await?;
//! stream.finish().await?;
//!
//! // Receive response
//! let mut buffer = vec![0u8; 8192];
//! let len = stream.receive(&mut buffer).await?;
//! let response = &buffer[..len];
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::RwLock;

/// QUIC transport configuration
///
/// This type provides comprehensive configuration options for QUIC transport,
/// including connection limits, timeouts, stream management, and performance tuning.
#[derive(Debug, Clone)]
#[must_use]
pub struct QuicConfig {
    /// Maximum number of concurrent bidirectional streams per connection
    pub max_concurrent_bidi_streams: u64,
    /// Maximum number of concurrent unidirectional streams per connection
    pub max_concurrent_uni_streams: u64,
    /// Maximum idle timeout before connection is closed
    pub max_idle_timeout: Duration,
    /// Keep-alive interval to prevent idle timeout
    pub keep_alive_interval: Duration,
    /// Maximum UDP payload size
    pub max_udp_payload_size: u16,
    /// Initial maximum data (flow control window)
    pub initial_max_data: u64,
    /// Initial maximum stream data (per-stream flow control)
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    /// Enable connection migration
    pub enable_migration: bool,
    /// Enable 0-RTT (zero round-trip time) for repeat connections
    pub enable_0rtt: bool,
}

impl Default for QuicConfig {
    #[inline]
    fn default() -> Self {
        Self {
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            max_idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(5),
            max_udp_payload_size: 1350,
            initial_max_data: 10 * 1024 * 1024, // 10 MB
            initial_max_stream_data_bidi_local: 1024 * 1024, // 1 MB
            initial_max_stream_data_bidi_remote: 1024 * 1024, // 1 MB
            initial_max_stream_data_uni: 1024 * 1024, // 1 MB
            enable_migration: true,
            enable_0rtt: false,
        }
    }
}

impl QuicConfig {
    /// Create a new configuration builder
    #[inline]
    #[must_use]
    pub fn builder() -> QuicConfigBuilder {
        QuicConfigBuilder::default()
    }
}

/// Builder for QUIC configuration
#[derive(Debug, Default)]
pub struct QuicConfigBuilder {
    config: QuicConfig,
}

impl QuicConfigBuilder {
    /// Set maximum concurrent bidirectional streams
    #[inline]
    #[must_use]
    pub fn with_max_concurrent_streams(mut self, count: u64) -> Self {
        self.config.max_concurrent_bidi_streams = count;
        self.config.max_concurrent_uni_streams = count;
        self
    }

    /// Set maximum idle timeout
    #[inline]
    #[must_use]
    pub fn with_max_idle_timeout(mut self, timeout: Duration) -> Self {
        self.config.max_idle_timeout = timeout;
        self
    }

    /// Set keep-alive interval
    #[inline]
    #[must_use]
    pub fn with_keep_alive_interval(mut self, interval: Duration) -> Self {
        self.config.keep_alive_interval = interval;
        self
    }

    /// Set maximum UDP payload size
    #[inline]
    #[must_use]
    pub fn with_max_udp_payload_size(mut self, size: u16) -> Self {
        self.config.max_udp_payload_size = size;
        self
    }

    /// Set initial flow control window
    #[inline]
    #[must_use]
    pub fn with_initial_max_data(mut self, size: u64) -> Self {
        self.config.initial_max_data = size;
        self
    }

    /// Enable connection migration
    #[inline]
    #[must_use]
    pub fn with_migration(mut self, enable: bool) -> Self {
        self.config.enable_migration = enable;
        self
    }

    /// Enable 0-RTT connections
    #[inline]
    #[must_use]
    pub fn with_0rtt(mut self, enable: bool) -> Self {
        self.config.enable_0rtt = enable;
        self
    }

    /// Build the configuration
    #[inline]
    pub fn build(self) -> QuicConfig {
        self.config
    }
}

/// QUIC endpoint for server or client connections
///
/// An endpoint manages the QUIC protocol state and can act as either a server
/// (accepting incoming connections) or a client (initiating connections).
pub struct QuicEndpoint {
    endpoint: Endpoint,
    stats: Arc<QuicStats>,
    #[allow(dead_code)]
    config: QuicConfig,
}

impl QuicEndpoint {
    /// Create a server endpoint bound to the specified address
    ///
    /// # Arguments
    ///
    /// * `addr` - Socket address to bind to (e.g., "0.0.0.0:4433")
    /// * `config` - QUIC configuration
    ///
    /// # Errors
    ///
    /// Returns an error if certificate generation fails or binding fails
    pub async fn server(addr: &str, config: QuicConfig) -> Result<Self> {
        let addr: SocketAddr = addr.parse().context("Invalid server address")?;

        // Generate self-signed certificate for server
        let (cert, key) = generate_self_signed_cert()?;

        // Configure server
        let mut server_config = ServerConfig::with_single_cert(vec![cert], key)
            .context("Failed to create server config")?;

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(
            config
                .max_concurrent_bidi_streams
                .try_into()
                .unwrap_or(100u32.into()),
        );
        transport_config.max_concurrent_uni_streams(
            config
                .max_concurrent_uni_streams
                .try_into()
                .unwrap_or(100u32.into()),
        );
        transport_config.max_idle_timeout(Some(config.max_idle_timeout.try_into()?));
        transport_config.keep_alive_interval(Some(config.keep_alive_interval));

        server_config.transport_config(Arc::new(transport_config));

        let endpoint =
            Endpoint::server(server_config, addr).context("Failed to create server endpoint")?;

        Ok(Self {
            endpoint,
            stats: Arc::new(QuicStats::default()),
            config,
        })
    }

    /// Create a client endpoint
    ///
    /// # Arguments
    ///
    /// * `config` - QUIC configuration
    ///
    /// # Errors
    ///
    /// Returns an error if client configuration fails
    pub async fn client(config: QuicConfig) -> Result<Self> {
        let mut client_config = ClientConfig::try_with_platform_verifier()
            .context("Failed to create client config with platform verifier")?;

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(
            config
                .max_concurrent_bidi_streams
                .try_into()
                .unwrap_or(100u32.into()),
        );
        transport_config.max_concurrent_uni_streams(
            config
                .max_concurrent_uni_streams
                .try_into()
                .unwrap_or(100u32.into()),
        );
        transport_config.max_idle_timeout(Some(config.max_idle_timeout.try_into()?));
        transport_config.keep_alive_interval(Some(config.keep_alive_interval));

        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            endpoint,
            stats: Arc::new(QuicStats::default()),
            config,
        })
    }

    /// Accept an incoming connection (server-side)
    ///
    /// # Returns
    ///
    /// Returns `Some(IncomingConnection)` if a connection is available,
    /// or `None` if the endpoint is closed
    #[inline]
    pub async fn accept(&mut self) -> Option<IncomingConnection> {
        self.endpoint.accept().await.map(|incoming| {
            self.stats
                .connections_accepted
                .fetch_add(1, Ordering::Relaxed);
            IncomingConnection {
                incoming,
                stats: Arc::clone(&self.stats),
            }
        })
    }

    /// Connect to a remote server (client-side)
    ///
    /// # Arguments
    ///
    /// * `addr` - Server address (e.g., "example.com:4433")
    /// * `server_name` - Server name for TLS verification
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails
    pub async fn connect(&self, addr: &str, server_name: &str) -> Result<QuicConnection> {
        let addr: SocketAddr = addr.parse().context("Invalid server address")?;

        let connecting = self
            .endpoint
            .connect(addr, server_name)
            .context("Failed to initiate connection")?;

        self.stats
            .connections_initiated
            .fetch_add(1, Ordering::Relaxed);

        let connection = connecting.await.context("Failed to establish connection")?;

        self.stats
            .connections_established
            .fetch_add(1, Ordering::Relaxed);

        Ok(QuicConnection {
            connection,
            stats: Arc::clone(&self.stats),
        })
    }

    /// Get endpoint statistics
    #[inline]
    #[must_use]
    pub fn stats(&self) -> QuicStats {
        (*self.stats).clone()
    }

    /// Get local socket address
    #[inline]
    #[must_use]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.endpoint.local_addr().ok()
    }

    /// Close the endpoint
    ///
    /// # Arguments
    ///
    /// * `error_code` - Error code to send to peers
    /// * `reason` - Human-readable reason for closure
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.endpoint.close(error_code.into(), reason);
    }
}

/// Incoming connection waiting to be accepted
pub struct IncomingConnection {
    incoming: quinn::Incoming,
    stats: Arc<QuicStats>,
}

impl IncomingConnection {
    /// Accept the incoming connection
    ///
    /// # Errors
    ///
    /// Returns an error if connection acceptance fails
    pub async fn accept(self) -> Result<QuicConnection> {
        let connection = self.incoming.await.context("Failed to accept connection")?;

        self.stats
            .connections_established
            .fetch_add(1, Ordering::Relaxed);

        Ok(QuicConnection {
            connection,
            stats: self.stats,
        })
    }

    /// Get remote address of the connecting peer
    #[inline]
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.incoming.remote_address()
    }
}

/// Established QUIC connection
///
/// Represents an active connection to a peer, supporting multiple
/// concurrent streams for efficient data transfer.
pub struct QuicConnection {
    connection: quinn::Connection,
    stats: Arc<QuicStats>,
}

impl QuicConnection {
    /// Open a new bidirectional stream
    ///
    /// # Errors
    ///
    /// Returns an error if stream opening fails
    pub async fn open_bidirectional_stream(&self) -> Result<QuicStream> {
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .context("Failed to open bidirectional stream")?;

        self.stats.streams_opened.fetch_add(1, Ordering::Relaxed);

        Ok(QuicStream {
            send: Some(send),
            recv: Some(recv),
            stats: Arc::clone(&self.stats),
        })
    }

    /// Open a new unidirectional stream (send-only)
    ///
    /// # Errors
    ///
    /// Returns an error if stream opening fails
    pub async fn open_unidirectional_stream(&self) -> Result<QuicSendStream> {
        let send = self
            .connection
            .open_uni()
            .await
            .context("Failed to open unidirectional stream")?;

        self.stats.streams_opened.fetch_add(1, Ordering::Relaxed);

        Ok(QuicSendStream {
            send,
            stats: Arc::clone(&self.stats),
        })
    }

    /// Accept an incoming bidirectional stream
    ///
    /// # Returns
    ///
    /// Returns `Some(QuicStream)` if a stream is available,
    /// or `None` if the connection is closed
    pub async fn accept_bidirectional_stream(&self) -> Option<QuicStream> {
        self.connection.accept_bi().await.ok().map(|(send, recv)| {
            self.stats.streams_accepted.fetch_add(1, Ordering::Relaxed);
            QuicStream {
                send: Some(send),
                recv: Some(recv),
                stats: Arc::clone(&self.stats),
            }
        })
    }

    /// Accept an incoming unidirectional stream
    ///
    /// # Returns
    ///
    /// Returns `Some(QuicRecvStream)` if a stream is available,
    /// or `None` if the connection is closed
    pub async fn accept_unidirectional_stream(&self) -> Option<QuicRecvStream> {
        self.connection.accept_uni().await.ok().map(|recv| {
            self.stats.streams_accepted.fetch_add(1, Ordering::Relaxed);
            QuicRecvStream {
                recv,
                stats: Arc::clone(&self.stats),
            }
        })
    }

    /// Get remote address of the peer
    #[inline]
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    /// Close the connection gracefully
    ///
    /// # Arguments
    ///
    /// * `error_code` - Error code to send to peer
    /// * `reason` - Human-readable reason for closure
    pub fn close(&self, error_code: u32, reason: &[u8]) {
        self.connection.close(error_code.into(), reason);
        self.stats
            .connections_closed
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get connection statistics
    #[inline]
    #[must_use]
    pub fn stats(&self) -> QuicStats {
        (*self.stats).clone()
    }
}

/// Bidirectional QUIC stream
///
/// Supports both sending and receiving data on the same stream.
pub struct QuicStream {
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
    stats: Arc<QuicStats>,
}

impl QuicStream {
    /// Send data on the stream
    ///
    /// # Errors
    ///
    /// Returns an error if sending fails
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let send = self.send.as_mut().context("Send stream already closed")?;

        send.write_all(data).await.context("Failed to send data")?;

        self.stats
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Finish sending (close send side of stream)
    ///
    /// # Errors
    ///
    /// Returns an error if finishing fails
    pub async fn finish(&mut self) -> Result<()> {
        if let Some(mut send) = self.send.take() {
            send.finish().context("Failed to finish stream")?;
        }
        Ok(())
    }

    /// Receive data from the stream
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer to receive data into
    ///
    /// # Returns
    ///
    /// Returns the number of bytes received, or 0 if the stream is finished
    ///
    /// # Errors
    ///
    /// Returns an error if receiving fails
    pub async fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let recv = self
            .recv
            .as_mut()
            .context("Receive stream already closed")?;

        let len = recv
            .read(buffer)
            .await
            .context("Failed to receive data")?
            .unwrap_or(0);

        self.stats
            .bytes_received
            .fetch_add(len as u64, Ordering::Relaxed);

        Ok(len)
    }

    /// Receive all remaining data from the stream
    ///
    /// # Returns
    ///
    /// Returns all data received until the stream is finished
    ///
    /// # Errors
    ///
    /// Returns an error if receiving fails or data exceeds 10MB
    pub async fn receive_all(&mut self) -> Result<Vec<u8>> {
        let recv = self
            .recv
            .as_mut()
            .context("Receive stream already closed")?;

        let data = recv
            .read_to_end(10 * 1024 * 1024) // 10 MB limit
            .await
            .context("Failed to receive all data")?;

        self.stats
            .bytes_received
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(data)
    }
}

impl Drop for QuicStream {
    fn drop(&mut self) {
        self.stats.streams_closed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Unidirectional send-only QUIC stream
pub struct QuicSendStream {
    send: quinn::SendStream,
    stats: Arc<QuicStats>,
}

impl QuicSendStream {
    /// Send data on the stream
    ///
    /// # Errors
    ///
    /// Returns an error if sending fails
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        self.send
            .write_all(data)
            .await
            .context("Failed to send data")?;

        self.stats
            .bytes_sent
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Finish sending (close stream)
    ///
    /// # Errors
    ///
    /// Returns an error if finishing fails
    pub async fn finish(mut self) -> Result<()> {
        self.send.finish().context("Failed to finish stream")?;
        Ok(())
    }
}

impl Drop for QuicSendStream {
    fn drop(&mut self) {
        self.stats.streams_closed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Unidirectional receive-only QUIC stream
pub struct QuicRecvStream {
    recv: quinn::RecvStream,
    stats: Arc<QuicStats>,
}

impl QuicRecvStream {
    /// Receive data from the stream
    ///
    /// # Arguments
    ///
    /// * `buffer` - Buffer to receive data into
    ///
    /// # Returns
    ///
    /// Returns the number of bytes received, or 0 if the stream is finished
    ///
    /// # Errors
    ///
    /// Returns an error if receiving fails
    pub async fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let len = self
            .recv
            .read(buffer)
            .await
            .context("Failed to receive data")?
            .unwrap_or(0);

        self.stats
            .bytes_received
            .fetch_add(len as u64, Ordering::Relaxed);

        Ok(len)
    }

    /// Receive all remaining data from the stream
    ///
    /// # Returns
    ///
    /// Returns all data received until the stream is finished
    ///
    /// # Errors
    ///
    /// Returns an error if receiving fails or data exceeds 10MB
    pub async fn receive_all(mut self) -> Result<Vec<u8>> {
        let data = self
            .recv
            .read_to_end(10 * 1024 * 1024) // 10 MB limit
            .await
            .context("Failed to receive all data")?;

        self.stats
            .bytes_received
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        Ok(data)
    }
}

impl Drop for QuicRecvStream {
    fn drop(&mut self) {
        self.stats.streams_closed.fetch_add(1, Ordering::Relaxed);
    }
}

/// QUIC transport statistics
///
/// Tracks various metrics about QUIC connections and streams.
#[derive(Debug, Default)]
pub struct QuicStats {
    /// Number of connections initiated (client-side)
    pub connections_initiated: AtomicU64,
    /// Number of connections accepted (server-side)
    pub connections_accepted: AtomicU64,
    /// Number of connections successfully established
    pub connections_established: AtomicU64,
    /// Number of connections closed
    pub connections_closed: AtomicU64,
    /// Number of streams opened
    pub streams_opened: AtomicU64,
    /// Number of streams accepted
    pub streams_accepted: AtomicU64,
    /// Number of streams closed
    pub streams_closed: AtomicU64,
    /// Total bytes sent
    pub bytes_sent: AtomicU64,
    /// Total bytes received
    pub bytes_received: AtomicU64,
}

impl Clone for QuicStats {
    fn clone(&self) -> Self {
        Self {
            connections_initiated: AtomicU64::new(
                self.connections_initiated.load(Ordering::Relaxed),
            ),
            connections_accepted: AtomicU64::new(self.connections_accepted.load(Ordering::Relaxed)),
            connections_established: AtomicU64::new(
                self.connections_established.load(Ordering::Relaxed),
            ),
            connections_closed: AtomicU64::new(self.connections_closed.load(Ordering::Relaxed)),
            streams_opened: AtomicU64::new(self.streams_opened.load(Ordering::Relaxed)),
            streams_accepted: AtomicU64::new(self.streams_accepted.load(Ordering::Relaxed)),
            streams_closed: AtomicU64::new(self.streams_closed.load(Ordering::Relaxed)),
            bytes_sent: AtomicU64::new(self.bytes_sent.load(Ordering::Relaxed)),
            bytes_received: AtomicU64::new(self.bytes_received.load(Ordering::Relaxed)),
        }
    }
}

impl QuicStats {
    /// Get number of active connections
    #[inline]
    #[must_use]
    pub fn active_connections(&self) -> u64 {
        let established = self.connections_established.load(Ordering::Relaxed);
        let closed = self.connections_closed.load(Ordering::Relaxed);
        established.saturating_sub(closed)
    }

    /// Get number of active streams
    #[inline]
    #[must_use]
    pub fn active_streams(&self) -> u64 {
        let opened = self.streams_opened.load(Ordering::Relaxed);
        let accepted = self.streams_accepted.load(Ordering::Relaxed);
        let closed = self.streams_closed.load(Ordering::Relaxed);
        (opened + accepted).saturating_sub(closed)
    }

    /// Get total bytes transferred (sent + received)
    #[inline]
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed) + self.bytes_received.load(Ordering::Relaxed)
    }
}

/// Connection pool for managing multiple QUIC connections
///
/// Provides connection reuse and load balancing across multiple connections.
pub struct QuicConnectionPool {
    connections: Arc<RwLock<Vec<QuicConnection>>>,
    endpoint: Arc<QuicEndpoint>,
    server_addr: String,
    server_name: String,
    max_connections: usize,
}

impl QuicConnectionPool {
    /// Create a new connection pool
    ///
    /// # Arguments
    ///
    /// * `endpoint` - QUIC endpoint to use for connections
    /// * `server_addr` - Server address to connect to
    /// * `server_name` - Server name for TLS verification
    /// * `max_connections` - Maximum number of pooled connections
    #[must_use]
    pub fn new(
        endpoint: QuicEndpoint,
        server_addr: String,
        server_name: String,
        max_connections: usize,
    ) -> Self {
        Self {
            connections: Arc::new(RwLock::new(Vec::new())),
            endpoint: Arc::new(endpoint),
            server_addr,
            server_name,
            max_connections,
        }
    }

    /// Get a connection from the pool or create a new one
    ///
    /// # Errors
    ///
    /// Returns an error if connection fails
    pub async fn get_connection(&self) -> Result<QuicConnection> {
        // Try to reuse existing connection
        {
            let mut connections = self.connections.write().await;
            if let Some(conn) = connections.pop() {
                return Ok(conn);
            }
        }

        // Create new connection
        let connection = self
            .endpoint
            .connect(&self.server_addr, &self.server_name)
            .await?;

        Ok(connection)
    }

    /// Return a connection to the pool
    ///
    /// # Arguments
    ///
    /// * `connection` - Connection to return
    pub async fn return_connection(&self, connection: QuicConnection) {
        let mut connections = self.connections.write().await;
        if connections.len() < self.max_connections {
            connections.push(connection);
        }
        // Otherwise, connection is dropped
    }

    /// Get pool statistics
    #[must_use]
    pub async fn stats(&self) -> PoolStats {
        let connections = self.connections.read().await;
        PoolStats {
            pooled_connections: connections.len(),
            max_connections: self.max_connections,
        }
    }
}

/// Connection pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    /// Number of connections currently in the pool
    pub pooled_connections: usize,
    /// Maximum number of connections
    pub max_connections: usize,
}

/// Generate a self-signed certificate for testing
///
/// # Errors
///
/// Returns an error if certificate generation fails
fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("Failed to generate certificate")?;

    let key = PrivateKeyDer::Pkcs8(certified_key.signing_key.serialize_der().into());
    let cert_der = CertificateDer::from(certified_key.cert);

    Ok((cert_der, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{ServerName, UnixTime};

    /// Test-only: Create a client that skips certificate verification
    async fn create_insecure_client(config: QuicConfig) -> Result<QuicEndpoint> {
        // Install default crypto provider if not already installed
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Custom verifier that accepts all certificates
        #[derive(Debug)]
        struct SkipServerVerification;

        impl ServerCertVerifier for SkipServerVerification {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &ServerName<'_>,
                _ocsp_response: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ED25519,
                ]
            }
        }

        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        let mut client_config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_concurrent_bidi_streams(
            config
                .max_concurrent_bidi_streams
                .try_into()
                .unwrap_or(100u32.into()),
        );
        transport_config.max_concurrent_uni_streams(
            config
                .max_concurrent_uni_streams
                .try_into()
                .unwrap_or(100u32.into()),
        );
        transport_config.max_idle_timeout(Some(config.max_idle_timeout.try_into()?));
        transport_config.keep_alive_interval(Some(config.keep_alive_interval));

        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(QuicEndpoint {
            endpoint,
            stats: Arc::new(QuicStats::default()),
            config,
        })
    }

    #[test]
    fn test_config_builder() {
        let config = QuicConfig::builder()
            .with_max_concurrent_streams(200)
            .with_max_idle_timeout(Duration::from_secs(60))
            .with_keep_alive_interval(Duration::from_secs(10))
            .with_migration(false)
            .with_0rtt(true)
            .build();

        assert_eq!(config.max_concurrent_bidi_streams, 200);
        assert_eq!(config.max_concurrent_uni_streams, 200);
        assert_eq!(config.max_idle_timeout, Duration::from_secs(60));
        assert_eq!(config.keep_alive_interval, Duration::from_secs(10));
        assert!(!config.enable_migration);
        assert!(config.enable_0rtt);
    }

    #[test]
    fn test_default_config() {
        let config = QuicConfig::default();
        assert_eq!(config.max_concurrent_bidi_streams, 100);
        assert_eq!(config.max_idle_timeout, Duration::from_secs(30));
        assert!(config.enable_migration);
        assert!(!config.enable_0rtt);
    }

    #[test]
    fn test_stats_calculations() {
        let stats = QuicStats::default();

        stats.connections_established.store(10, Ordering::Relaxed);
        stats.connections_closed.store(3, Ordering::Relaxed);
        assert_eq!(stats.active_connections(), 7);

        stats.streams_opened.store(20, Ordering::Relaxed);
        stats.streams_accepted.store(15, Ordering::Relaxed);
        stats.streams_closed.store(10, Ordering::Relaxed);
        assert_eq!(stats.active_streams(), 25);

        stats.bytes_sent.store(1000, Ordering::Relaxed);
        stats.bytes_received.store(2000, Ordering::Relaxed);
        assert_eq!(stats.total_bytes(), 3000);
    }

    #[tokio::test]
    async fn test_server_creation() {
        let config = QuicConfig::default();
        let result = QuicEndpoint::server("127.0.0.1:0", config).await;
        assert!(result.is_ok());

        let endpoint = result.unwrap();
        assert!(endpoint.local_addr().is_some());
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = QuicConfig::default();
        let result = QuicEndpoint::client(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let config = QuicConfig::default();
        let endpoint = QuicEndpoint::client(config).await.unwrap();

        let pool = QuicConnectionPool::new(
            endpoint,
            "127.0.0.1:4433".to_string(),
            "localhost".to_string(),
            10,
        );

        let stats = pool.stats().await;
        assert_eq!(stats.pooled_connections, 0);
        assert_eq!(stats.max_connections, 10);
    }

    #[tokio::test]
    async fn test_server_client_communication() {
        // Create server
        let server_config = QuicConfig::default();
        let mut server = QuicEndpoint::server("127.0.0.1:0", server_config)
            .await
            .unwrap();

        let server_addr = server.local_addr().unwrap();

        // Spawn server task
        let server_task = tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let connection = incoming.accept().await.unwrap();
                if let Some(mut stream) = connection.accept_bidirectional_stream().await {
                    // Receive all data from client
                    let received_data = stream.receive_all().await.unwrap();
                    let received = String::from_utf8_lossy(&received_data);

                    // Send response
                    stream.send(b"Hello, Client!").await.unwrap();
                    stream.finish().await.unwrap();

                    // Keep connection alive a bit longer
                    tokio::time::sleep(Duration::from_millis(100)).await;

                    received.to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            }
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Create client with insecure certificate verification for testing
        let client_config = QuicConfig::default();
        let client = create_insecure_client(client_config).await.unwrap();

        // Connect to server
        let connection = client
            .connect(&server_addr.to_string(), "localhost")
            .await
            .unwrap();

        // Open stream and send data
        let mut stream = connection.open_bidirectional_stream().await.unwrap();
        stream.send(b"Hello, Server!").await.unwrap();
        stream.finish().await.unwrap();

        // Receive response
        let response = stream.receive_all().await.unwrap();
        assert_eq!(response, b"Hello, Client!");

        // Wait for server
        let server_received = server_task.await.unwrap();
        assert_eq!(server_received, "Hello, Server!");
    }

    #[test]
    fn test_certificate_generation() {
        let result = generate_self_signed_cert();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_stream_statistics() {
        let config = QuicConfig::default();
        let mut server = QuicEndpoint::server("127.0.0.1:0", config.clone())
            .await
            .unwrap();

        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let _ = incoming.accept().await;
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = create_insecure_client(config).await.unwrap();
        let connection = client
            .connect(&server_addr.to_string(), "localhost")
            .await
            .unwrap();

        let stats_before = connection.stats();
        let initial_streams = stats_before.streams_opened.load(Ordering::Relaxed);

        let _stream = connection.open_bidirectional_stream().await.unwrap();

        let stats_after = connection.stats();
        assert_eq!(
            stats_after.streams_opened.load(Ordering::Relaxed),
            initial_streams + 1
        );
    }

    #[tokio::test]
    async fn test_multiple_streams() {
        let config = QuicConfig::default();
        let mut server = QuicEndpoint::server("127.0.0.1:0", config.clone())
            .await
            .unwrap();

        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let connection = incoming.accept().await.unwrap();
                for _ in 0..3 {
                    if let Some(mut stream) = connection.accept_bidirectional_stream().await {
                        // Receive all data from client
                        let _ = stream.receive_all().await;
                        // Send response
                        let _ = stream.send(b"ACK").await;
                        let _ = stream.finish().await;
                    }
                }
                // Keep connection alive a bit longer
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = create_insecure_client(config).await.unwrap();
        let connection = client
            .connect(&server_addr.to_string(), "localhost")
            .await
            .unwrap();

        // Open and use multiple streams
        for i in 0..3 {
            let mut stream = connection.open_bidirectional_stream().await.unwrap();
            stream
                .send(format!("Message {}", i).as_bytes())
                .await
                .unwrap();
            stream.finish().await.unwrap();

            let response = stream.receive_all().await.unwrap();
            assert_eq!(response, b"ACK");
        }

        let stats = connection.stats();
        assert!(stats.streams_opened.load(Ordering::Relaxed) >= 3);
    }

    #[tokio::test]
    async fn test_connection_close() {
        let config = QuicConfig::default();
        let client = QuicEndpoint::client(config).await.unwrap();
        let initial_stats = client.stats();

        client.close(0, b"test close");

        // Stats should remain valid after close
        let final_stats = client.stats();
        assert_eq!(
            initial_stats.connections_initiated.load(Ordering::Relaxed),
            final_stats.connections_initiated.load(Ordering::Relaxed)
        );
    }

    #[tokio::test]
    async fn test_unidirectional_streams() {
        let config = QuicConfig::default();
        let mut server = QuicEndpoint::server("127.0.0.1:0", config.clone())
            .await
            .unwrap();

        let server_addr = server.local_addr().unwrap();

        tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let connection = incoming.accept().await.unwrap();
                if let Some(stream) = connection.accept_unidirectional_stream().await {
                    let data = stream.receive_all().await.unwrap();
                    assert_eq!(data, b"Unidirectional message");
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = create_insecure_client(config).await.unwrap();
        let connection = client
            .connect(&server_addr.to_string(), "localhost")
            .await
            .unwrap();

        let mut stream = connection.open_unidirectional_stream().await.unwrap();
        stream.send(b"Unidirectional message").await.unwrap();
        stream.finish().await.unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

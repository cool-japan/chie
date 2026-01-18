//! Network configuration

use serde::{Deserialize, Serialize};

/// Network configuration for P2P layer
///
/// # Examples
///
/// Using the default configuration:
/// ```
/// use chie_shared::NetworkConfig;
///
/// let config = NetworkConfig::default();
/// assert_eq!(config.max_connections, 100);
/// assert_eq!(config.connection_timeout_ms, 10_000);
/// assert!(config.enable_relay);
/// assert!(config.enable_dht);
/// assert!(config.validate().is_ok());
/// ```
///
/// Building a custom configuration:
/// ```
/// use chie_shared::NetworkConfigBuilder;
///
/// let config = NetworkConfigBuilder::new()
///     .max_connections(50)
///     .connection_timeout_ms(5_000)
///     .enable_relay(false)
///     .add_bootstrap_peer("/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ")
///     .build();
///
/// assert_eq!(config.max_connections, 50);
/// assert_eq!(config.connection_timeout_ms, 5_000);
/// assert!(!config.enable_relay);
/// assert_eq!(config.bootstrap_peers.len(), 1);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Connection timeout in milliseconds
    pub connection_timeout_ms: u64,
    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,
    /// Enable relay mode for NAT traversal
    pub enable_relay: bool,
    /// Enable DHT for peer discovery
    pub enable_dht: bool,
    /// Bootstrap peer multiaddrs
    pub bootstrap_peers: Vec<String>,
    /// Listen addresses
    pub listen_addrs: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            connection_timeout_ms: 10_000,
            request_timeout_ms: 30_000,
            enable_relay: true,
            enable_dht: true,
            bootstrap_peers: Vec::new(),
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
        }
    }
}

impl NetworkConfig {
    /// Validate the network configuration
    ///
    /// # Errors
    ///
    /// Returns error if configuration is invalid
    pub fn validate(&self) -> crate::ChieResult<()> {
        use crate::ChieError;

        if self.max_connections == 0 {
            return Err(ChieError::validation(
                "max_connections must be greater than 0",
            ));
        }

        if self.connection_timeout_ms == 0 {
            return Err(ChieError::validation(
                "connection_timeout_ms must be greater than 0",
            ));
        }

        if self.request_timeout_ms == 0 {
            return Err(ChieError::validation(
                "request_timeout_ms must be greater than 0",
            ));
        }

        if self.listen_addrs.is_empty() {
            return Err(ChieError::validation("listen_addrs must not be empty"));
        }

        Ok(())
    }
}

/// Builder for `NetworkConfig`
///
/// # Examples
///
/// Building a production configuration:
/// ```
/// use chie_shared::NetworkConfigBuilder;
///
/// let config = NetworkConfigBuilder::new()
///     .max_connections(200)
///     .connection_timeout_ms(15_000)
///     .request_timeout_ms(60_000)
///     .enable_relay(true)
///     .enable_dht(true)
///     .add_bootstrap_peer("/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN")
///     .add_listen_addr("/ip4/0.0.0.0/tcp/4001")
///     .build();
///
/// assert_eq!(config.max_connections, 200);
/// assert!(config.validate().is_ok());
/// ```
#[derive(Debug, Default)]
pub struct NetworkConfigBuilder {
    config: NetworkConfig,
}

impl NetworkConfigBuilder {
    /// Create a new builder with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum concurrent connections
    #[must_use]
    pub const fn max_connections(mut self, max: usize) -> Self {
        self.config.max_connections = max;
        self
    }

    /// Set connection timeout
    #[must_use]
    pub const fn connection_timeout_ms(mut self, timeout: u64) -> Self {
        self.config.connection_timeout_ms = timeout;
        self
    }

    /// Set request timeout
    #[must_use]
    pub const fn request_timeout_ms(mut self, timeout: u64) -> Self {
        self.config.request_timeout_ms = timeout;
        self
    }

    /// Enable or disable relay mode
    #[must_use]
    pub const fn enable_relay(mut self, enable: bool) -> Self {
        self.config.enable_relay = enable;
        self
    }

    /// Enable or disable DHT
    #[must_use]
    pub const fn enable_dht(mut self, enable: bool) -> Self {
        self.config.enable_dht = enable;
        self
    }

    /// Add a bootstrap peer
    #[must_use]
    pub fn add_bootstrap_peer(mut self, addr: impl Into<String>) -> Self {
        self.config.bootstrap_peers.push(addr.into());
        self
    }

    /// Set bootstrap peers
    #[must_use]
    pub fn bootstrap_peers(mut self, peers: Vec<String>) -> Self {
        self.config.bootstrap_peers = peers;
        self
    }

    /// Add a listen address
    #[must_use]
    pub fn add_listen_addr(mut self, addr: impl Into<String>) -> Self {
        self.config.listen_addrs.push(addr.into());
        self
    }

    /// Set listen addresses
    #[must_use]
    pub fn listen_addrs(mut self, addrs: Vec<String>) -> Self {
        self.config.listen_addrs = addrs;
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> NetworkConfig {
        self.config
    }
}

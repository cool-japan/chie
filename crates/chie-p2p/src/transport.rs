//! Transport configuration for CHIE P2P network.
//!
//! This module provides multi-transport support:
//! - TCP with Noise encryption and Yamux multiplexing
//! - QUIC for modern, fast connections
//! - WebRTC for browser-based nodes
//! - Automatic fallback between transports

use libp2p::Multiaddr;
use std::time::Duration;
use tracing::info;

/// Transport type to use for connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportType {
    /// TCP only with Noise + Yamux.
    TcpOnly,
    /// QUIC only.
    QuicOnly,
    /// WebRTC only (for browser nodes).
    WebRtcOnly,
    /// Both TCP and QUIC (default, recommended).
    #[default]
    Both,
    /// All transports including WebRTC.
    All,
}

/// Configuration for transport layer.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Which transport(s) to use.
    pub transport_type: TransportType,
    /// TCP listen addresses (e.g., "/ip4/0.0.0.0/tcp/0").
    pub tcp_listen_addrs: Vec<Multiaddr>,
    /// QUIC listen addresses (e.g., "/ip4/0.0.0.0/udp/0/quic-v1").
    pub quic_listen_addrs: Vec<Multiaddr>,
    /// WebRTC listen addresses (e.g., "/ip4/0.0.0.0/udp/0/webrtc-direct").
    pub webrtc_listen_addrs: Vec<Multiaddr>,
    /// Connection idle timeout.
    pub idle_timeout: Duration,
    /// Enable TCP keep-alive.
    pub tcp_keep_alive: bool,
    /// TCP keep-alive interval (if enabled).
    pub keep_alive_interval: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: TransportType::Both,
            tcp_listen_addrs: vec![
                "/ip4/0.0.0.0/tcp/0".parse().unwrap(),
                "/ip6/::/tcp/0".parse().unwrap(),
            ],
            quic_listen_addrs: vec![
                "/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap(),
                "/ip6/::/udp/0/quic-v1".parse().unwrap(),
            ],
            webrtc_listen_addrs: vec![], // Disabled by default
            idle_timeout: Duration::from_secs(30),
            tcp_keep_alive: true,
            keep_alive_interval: Duration::from_secs(15),
        }
    }
}

impl TransportConfig {
    /// Create a TCP-only configuration.
    pub fn tcp_only() -> Self {
        Self {
            transport_type: TransportType::TcpOnly,
            quic_listen_addrs: vec![],
            webrtc_listen_addrs: vec![],
            ..Default::default()
        }
    }

    /// Create a QUIC-only configuration.
    pub fn quic_only() -> Self {
        Self {
            transport_type: TransportType::QuicOnly,
            tcp_listen_addrs: vec![],
            webrtc_listen_addrs: vec![],
            ..Default::default()
        }
    }

    /// Create a WebRTC-only configuration (for browser nodes).
    pub fn webrtc_only(port: u16) -> Self {
        Self {
            transport_type: TransportType::WebRtcOnly,
            tcp_listen_addrs: vec![],
            quic_listen_addrs: vec![],
            webrtc_listen_addrs: vec![
                format!("/ip4/0.0.0.0/udp/{}/webrtc-direct", port)
                    .parse()
                    .unwrap(),
            ],
            ..Default::default()
        }
    }

    /// Create a configuration with all transports including WebRTC.
    pub fn all_transports(webrtc_port: u16) -> Self {
        Self {
            transport_type: TransportType::All,
            webrtc_listen_addrs: vec![
                format!("/ip4/0.0.0.0/udp/{}/webrtc-direct", webrtc_port)
                    .parse()
                    .unwrap(),
            ],
            ..Default::default()
        }
    }

    /// Get all listen addresses for the configured transports.
    pub fn listen_addrs(&self) -> Vec<Multiaddr> {
        match self.transport_type {
            TransportType::TcpOnly => self.tcp_listen_addrs.clone(),
            TransportType::QuicOnly => self.quic_listen_addrs.clone(),
            TransportType::WebRtcOnly => self.webrtc_listen_addrs.clone(),
            TransportType::Both => {
                let mut addrs = self.tcp_listen_addrs.clone();
                addrs.extend(self.quic_listen_addrs.clone());
                addrs
            }
            TransportType::All => {
                let mut addrs = self.tcp_listen_addrs.clone();
                addrs.extend(self.quic_listen_addrs.clone());
                addrs.extend(self.webrtc_listen_addrs.clone());
                addrs
            }
        }
    }

    /// Check if TCP is enabled.
    pub fn tcp_enabled(&self) -> bool {
        matches!(
            self.transport_type,
            TransportType::TcpOnly | TransportType::Both | TransportType::All
        )
    }

    /// Check if QUIC is enabled.
    pub fn quic_enabled(&self) -> bool {
        matches!(
            self.transport_type,
            TransportType::QuicOnly | TransportType::Both | TransportType::All
        )
    }

    /// Check if WebRTC is enabled.
    pub fn webrtc_enabled(&self) -> bool {
        matches!(
            self.transport_type,
            TransportType::WebRtcOnly | TransportType::All
        )
    }

    /// Set custom TCP listen addresses.
    pub fn with_tcp_addrs(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.tcp_listen_addrs = addrs;
        self
    }

    /// Set custom QUIC listen addresses.
    pub fn with_quic_addrs(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.quic_listen_addrs = addrs;
        self
    }

    /// Set custom WebRTC listen addresses.
    pub fn with_webrtc_addrs(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.webrtc_listen_addrs = addrs;
        self
    }

    /// Set the idle timeout.
    pub fn with_idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = timeout;
        self
    }

    /// Log the configuration.
    pub fn log_config(&self) {
        info!("Transport configuration:");
        info!("  Type: {:?}", self.transport_type);
        if self.tcp_enabled() {
            info!("  TCP addresses: {:?}", self.tcp_listen_addrs);
        }
        if self.quic_enabled() {
            info!("  QUIC addresses: {:?}", self.quic_listen_addrs);
        }
        if self.webrtc_enabled() {
            info!("  WebRTC addresses: {:?}", self.webrtc_listen_addrs);
        }
        info!("  Idle timeout: {:?}", self.idle_timeout);
    }
}

/// Parse a multiaddr and determine its transport type.
pub fn parse_transport_type(addr: &Multiaddr) -> Option<TransportType> {
    let addr_str = addr.to_string();
    if addr_str.contains("/webrtc") {
        Some(TransportType::WebRtcOnly)
    } else if addr_str.contains("/quic") {
        Some(TransportType::QuicOnly)
    } else if addr_str.contains("/tcp") {
        Some(TransportType::TcpOnly)
    } else {
        None
    }
}

/// Create TCP listen address from port.
pub fn tcp_listen_addr(port: u16) -> Multiaddr {
    format!("/ip4/0.0.0.0/tcp/{}", port).parse().unwrap()
}

/// Create QUIC listen address from port.
pub fn quic_listen_addr(port: u16) -> Multiaddr {
    format!("/ip4/0.0.0.0/udp/{}/quic-v1", port)
        .parse()
        .unwrap()
}

/// Create TCP listen address for IPv6 from port.
pub fn tcp_listen_addr_v6(port: u16) -> Multiaddr {
    format!("/ip6/::/tcp/{}", port).parse().unwrap()
}

/// Create QUIC listen address for IPv6 from port.
pub fn quic_listen_addr_v6(port: u16) -> Multiaddr {
    format!("/ip6/::/udp/{}/quic-v1", port).parse().unwrap()
}

/// Create WebRTC listen address from port.
pub fn webrtc_listen_addr(port: u16) -> Multiaddr {
    format!("/ip4/0.0.0.0/udp/{}/webrtc-direct", port)
        .parse()
        .unwrap()
}

/// Create WebRTC listen address for IPv6 from port.
pub fn webrtc_listen_addr_v6(port: u16) -> Multiaddr {
    format!("/ip6/::/udp/{}/webrtc-direct", port)
        .parse()
        .unwrap()
}

/// Convert a TCP address to its QUIC equivalent.
pub fn tcp_to_quic(tcp_addr: &Multiaddr) -> Option<Multiaddr> {
    let addr_str = tcp_addr.to_string();
    if !addr_str.contains("/tcp/") {
        return None;
    }

    // Replace /tcp/PORT with /udp/PORT/quic-v1
    let quic_str = addr_str
        .replace("/tcp/", "/udp/")
        .trim_end_matches('/')
        .to_string()
        + "/quic-v1";

    quic_str.parse().ok()
}

/// Convert a QUIC address to its TCP equivalent.
pub fn quic_to_tcp(quic_addr: &Multiaddr) -> Option<Multiaddr> {
    let addr_str = quic_addr.to_string();
    if !addr_str.contains("/udp/") || !addr_str.contains("/quic") {
        return None;
    }

    // Remove /quic-v1 and replace /udp/ with /tcp/
    let tcp_str = addr_str
        .replace("/quic-v1", "")
        .replace("/quic", "")
        .replace("/udp/", "/tcp/");

    tcp_str.parse().ok()
}

/// Transport statistics.
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Number of TCP connections.
    pub tcp_connections: usize,
    /// Number of QUIC connections.
    pub quic_connections: usize,
    /// Number of WebRTC connections.
    pub webrtc_connections: usize,
    /// Bytes sent over TCP.
    pub tcp_bytes_sent: u64,
    /// Bytes received over TCP.
    pub tcp_bytes_received: u64,
    /// Bytes sent over QUIC.
    pub quic_bytes_sent: u64,
    /// Bytes received over QUIC.
    pub quic_bytes_received: u64,
    /// Bytes sent over WebRTC.
    pub webrtc_bytes_sent: u64,
    /// Bytes received over WebRTC.
    pub webrtc_bytes_received: u64,
}

impl TransportStats {
    /// Total connections.
    pub fn total_connections(&self) -> usize {
        self.tcp_connections + self.quic_connections + self.webrtc_connections
    }

    /// Total bytes sent.
    pub fn total_bytes_sent(&self) -> u64 {
        self.tcp_bytes_sent + self.quic_bytes_sent + self.webrtc_bytes_sent
    }

    /// Total bytes received.
    pub fn total_bytes_received(&self) -> u64 {
        self.tcp_bytes_received + self.quic_bytes_received + self.webrtc_bytes_received
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_config_default() {
        let config = TransportConfig::default();
        assert_eq!(config.transport_type, TransportType::Both);
        assert!(config.tcp_enabled());
        assert!(config.quic_enabled());
    }

    #[test]
    fn test_transport_config_tcp_only() {
        let config = TransportConfig::tcp_only();
        assert_eq!(config.transport_type, TransportType::TcpOnly);
        assert!(config.tcp_enabled());
        assert!(!config.quic_enabled());
    }

    #[test]
    fn test_transport_config_quic_only() {
        let config = TransportConfig::quic_only();
        assert_eq!(config.transport_type, TransportType::QuicOnly);
        assert!(!config.tcp_enabled());
        assert!(config.quic_enabled());
        assert!(!config.webrtc_enabled());
    }

    #[test]
    fn test_transport_config_webrtc_only() {
        let config = TransportConfig::webrtc_only(9090);
        assert_eq!(config.transport_type, TransportType::WebRtcOnly);
        assert!(!config.tcp_enabled());
        assert!(!config.quic_enabled());
        assert!(config.webrtc_enabled());
        assert_eq!(config.webrtc_listen_addrs.len(), 1);
    }

    #[test]
    fn test_transport_config_all() {
        let config = TransportConfig::all_transports(9090);
        assert_eq!(config.transport_type, TransportType::All);
        assert!(config.tcp_enabled());
        assert!(config.quic_enabled());
        assert!(config.webrtc_enabled());
    }

    #[test]
    fn test_listen_addrs() {
        let config = TransportConfig::default();
        let addrs = config.listen_addrs();
        assert_eq!(addrs.len(), 4); // 2 TCP + 2 QUIC (no WebRTC by default)
    }

    #[test]
    fn test_listen_addrs_all() {
        let config = TransportConfig::all_transports(9090);
        let addrs = config.listen_addrs();
        assert_eq!(addrs.len(), 5); // 2 TCP + 2 QUIC + 1 WebRTC
    }

    #[test]
    fn test_tcp_to_quic() {
        let tcp: Multiaddr = "/ip4/127.0.0.1/tcp/4001".parse().unwrap();
        let quic = tcp_to_quic(&tcp).unwrap();
        assert!(quic.to_string().contains("/udp/4001/quic-v1"));
    }

    #[test]
    fn test_quic_to_tcp() {
        let quic: Multiaddr = "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap();
        let tcp = quic_to_tcp(&quic).unwrap();
        assert!(tcp.to_string().contains("/tcp/4001"));
    }

    #[test]
    fn test_parse_transport_type() {
        let tcp: Multiaddr = "/ip4/0.0.0.0/tcp/4001".parse().unwrap();
        let quic: Multiaddr = "/ip4/0.0.0.0/udp/4001/quic-v1".parse().unwrap();
        let webrtc: Multiaddr = "/ip4/0.0.0.0/udp/9090/webrtc-direct".parse().unwrap();

        assert_eq!(parse_transport_type(&tcp), Some(TransportType::TcpOnly));
        assert_eq!(parse_transport_type(&quic), Some(TransportType::QuicOnly));
        assert_eq!(
            parse_transport_type(&webrtc),
            Some(TransportType::WebRtcOnly)
        );
    }

    #[test]
    fn test_helper_functions() {
        let tcp = tcp_listen_addr(4001);
        assert!(tcp.to_string().contains("/tcp/4001"));

        let quic = quic_listen_addr(4002);
        assert!(quic.to_string().contains("/udp/4002/quic-v1"));

        let webrtc = webrtc_listen_addr(9090);
        assert!(webrtc.to_string().contains("/udp/9090/webrtc-direct"));
    }

    #[test]
    fn test_webrtc_listen_addr_v6() {
        let webrtc = webrtc_listen_addr_v6(9091);
        assert!(webrtc.to_string().contains("/ip6/"));
        assert!(webrtc.to_string().contains("/webrtc-direct"));
    }
}

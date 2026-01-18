//! Peer blocklist and allowlist system for security and access control.
//!
//! This module provides:
//! - IP address blocking/allowing
//! - Peer ID blocking/allowing
//! - Automatic blocking based on violations
//! - Temporary and permanent blocks
//! - Block expiry and cleanup

use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Reason for blocking a peer
///
/// # Examples
///
/// ```
/// use chie_p2p::{BlockReason, BlocklistManager};
/// use std::time::Duration;
///
/// let manager = BlocklistManager::new();
/// // Block an IP for spam (temporary, 1 hour)
/// manager.block_ip("192.168.1.100".parse().unwrap(),
///     BlockReason::Spam, Some(Duration::from_secs(3600)));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlockReason {
    /// Manual block by administrator
    Manual,
    /// Excessive connection attempts
    TooManyConnections,
    /// Repeated failed authentications
    AuthFailure,
    /// Malicious behavior detected
    Malicious,
    /// Spam or flooding
    Spam,
    /// Protocol violation
    ProtocolViolation,
    /// Low reputation score
    LowReputation,
}

/// Block entry with expiry time
#[derive(Debug, Clone)]
struct BlockEntry {
    #[allow(dead_code)]
    reason: BlockReason,
    #[allow(dead_code)]
    blocked_at: Instant,
    expires_at: Option<Instant>,
}

impl BlockEntry {
    fn new(reason: BlockReason, duration: Option<Duration>) -> Self {
        let blocked_at = Instant::now();
        let expires_at = duration.map(|d| blocked_at + d);
        Self {
            reason,
            blocked_at,
            expires_at,
        }
    }

    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| Instant::now() >= exp)
            .unwrap_or(false)
    }

    fn is_permanent(&self) -> bool {
        self.expires_at.is_none()
    }
}

/// Access control mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessMode {
    /// Default mode: allow all except blocked
    #[default]
    AllowAll,
    /// Restrictive mode: allow only allowlisted
    AllowListOnly,
}

/// Peer blocklist and allowlist manager
#[derive(Clone)]
pub struct BlocklistManager {
    inner: Arc<RwLock<BlocklistInner>>,
}

struct BlocklistInner {
    /// Blocked peer IDs
    blocked_peers: HashMap<PeerId, BlockEntry>,
    /// Blocked IP addresses
    blocked_ips: HashMap<IpAddr, BlockEntry>,
    /// Allowed peer IDs (for allowlist mode)
    allowed_peers: HashSet<PeerId>,
    /// Allowed IP addresses (for allowlist mode)
    allowed_ips: HashSet<IpAddr>,
    /// Access control mode
    mode: AccessMode,
    /// Violation counts per peer
    violations: HashMap<PeerId, usize>,
    /// Threshold for auto-blocking
    auto_block_threshold: usize,
    /// Default block duration
    default_block_duration: Duration,
}

impl Default for BlocklistManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BlocklistManager {
    /// Create a new blocklist manager
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(BlocklistInner {
                blocked_peers: HashMap::new(),
                blocked_ips: HashMap::new(),
                allowed_peers: HashSet::new(),
                allowed_ips: HashSet::new(),
                mode: AccessMode::AllowAll,
                violations: HashMap::new(),
                auto_block_threshold: 5,
                default_block_duration: Duration::from_secs(3600), // 1 hour
            })),
        }
    }

    /// Set the access control mode
    pub fn set_mode(&self, mode: AccessMode) {
        if let Ok(mut inner) = self.inner.write() {
            inner.mode = mode;
        }
    }

    /// Get the current access mode
    pub fn mode(&self) -> AccessMode {
        self.inner
            .read()
            .map(|inner| inner.mode)
            .unwrap_or(AccessMode::AllowAll)
    }

    /// Set the auto-block threshold
    pub fn set_auto_block_threshold(&self, threshold: usize) {
        if let Ok(mut inner) = self.inner.write() {
            inner.auto_block_threshold = threshold;
        }
    }

    /// Set the default block duration
    pub fn set_default_block_duration(&self, duration: Duration) {
        if let Ok(mut inner) = self.inner.write() {
            inner.default_block_duration = duration;
        }
    }

    /// Block a peer temporarily
    pub fn block_peer(&self, peer_id: PeerId, reason: BlockReason, duration: Option<Duration>) {
        if let Ok(mut inner) = self.inner.write() {
            let duration = duration.unwrap_or(inner.default_block_duration);
            inner
                .blocked_peers
                .insert(peer_id, BlockEntry::new(reason, Some(duration)));
        }
    }

    /// Block a peer permanently
    pub fn block_peer_permanent(&self, peer_id: PeerId, reason: BlockReason) {
        if let Ok(mut inner) = self.inner.write() {
            inner
                .blocked_peers
                .insert(peer_id, BlockEntry::new(reason, None));
        }
    }

    /// Block an IP address temporarily
    pub fn block_ip(&self, ip: IpAddr, reason: BlockReason, duration: Option<Duration>) {
        if let Ok(mut inner) = self.inner.write() {
            let duration = duration.unwrap_or(inner.default_block_duration);
            inner
                .blocked_ips
                .insert(ip, BlockEntry::new(reason, Some(duration)));
        }
    }

    /// Block an IP address permanently
    pub fn block_ip_permanent(&self, ip: IpAddr, reason: BlockReason) {
        if let Ok(mut inner) = self.inner.write() {
            inner.blocked_ips.insert(ip, BlockEntry::new(reason, None));
        }
    }

    /// Unblock a peer
    pub fn unblock_peer(&self, peer_id: &PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            inner.blocked_peers.remove(peer_id);
            inner.violations.remove(peer_id);
        }
    }

    /// Unblock an IP address
    pub fn unblock_ip(&self, ip: &IpAddr) {
        if let Ok(mut inner) = self.inner.write() {
            inner.blocked_ips.remove(ip);
        }
    }

    /// Add a peer to the allowlist
    pub fn allow_peer(&self, peer_id: PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            inner.allowed_peers.insert(peer_id);
        }
    }

    /// Add an IP to the allowlist
    pub fn allow_ip(&self, ip: IpAddr) {
        if let Ok(mut inner) = self.inner.write() {
            inner.allowed_ips.insert(ip);
        }
    }

    /// Remove a peer from the allowlist
    pub fn disallow_peer(&self, peer_id: &PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            inner.allowed_peers.remove(peer_id);
        }
    }

    /// Remove an IP from the allowlist
    pub fn disallow_ip(&self, ip: &IpAddr) {
        if let Ok(mut inner) = self.inner.write() {
            inner.allowed_ips.remove(ip);
        }
    }

    /// Check if a peer is allowed to connect
    pub fn is_allowed(&self, peer_id: &PeerId, addr: &Multiaddr) -> bool {
        let Ok(inner) = self.inner.read() else {
            return true; // Default to allow on lock failure
        };

        // Extract IP from multiaddr
        let ip_opt = extract_ip_from_multiaddr(addr);

        // Check blocklist first (highest priority)
        if let Some(entry) = inner.blocked_peers.get(peer_id) {
            if !entry.is_expired() {
                return false;
            }
        }

        if let Some(ip) = ip_opt {
            if let Some(entry) = inner.blocked_ips.get(&ip) {
                if !entry.is_expired() {
                    return false;
                }
            }
        }

        // Check allowlist based on mode
        match inner.mode {
            AccessMode::AllowAll => true,
            AccessMode::AllowListOnly => {
                let peer_allowed = inner.allowed_peers.contains(peer_id);
                let ip_allowed = ip_opt
                    .map(|ip| inner.allowed_ips.contains(&ip))
                    .unwrap_or(false);
                peer_allowed || ip_allowed
            }
        }
    }

    /// Record a violation for a peer
    pub fn record_violation(&self, peer_id: PeerId, reason: BlockReason) {
        if let Ok(mut inner) = self.inner.write() {
            let count = inner.violations.entry(peer_id).or_insert(0);
            *count += 1;

            // Auto-block if threshold exceeded
            if *count >= inner.auto_block_threshold {
                let duration = inner.default_block_duration;
                inner
                    .blocked_peers
                    .insert(peer_id, BlockEntry::new(reason, Some(duration)));
            }
        }
    }

    /// Get violation count for a peer
    pub fn violation_count(&self, peer_id: &PeerId) -> usize {
        self.inner
            .read()
            .ok()
            .and_then(|inner| inner.violations.get(peer_id).copied())
            .unwrap_or(0)
    }

    /// Clear violations for a peer
    pub fn clear_violations(&self, peer_id: &PeerId) {
        if let Ok(mut inner) = self.inner.write() {
            inner.violations.remove(peer_id);
        }
    }

    /// Clean up expired blocks
    pub fn cleanup_expired(&self) -> usize {
        let Ok(mut inner) = self.inner.write() else {
            return 0;
        };

        let mut removed = 0;

        // Remove expired peer blocks
        inner.blocked_peers.retain(|_, entry| {
            let expired = entry.is_expired();
            if expired {
                removed += 1;
            }
            !expired
        });

        // Remove expired IP blocks
        inner.blocked_ips.retain(|_, entry| {
            let expired = entry.is_expired();
            if expired {
                removed += 1;
            }
            !expired
        });

        removed
    }

    /// Get statistics
    pub fn stats(&self) -> BlocklistStats {
        let Ok(inner) = self.inner.read() else {
            return BlocklistStats::default();
        };

        let blocked_peers_permanent = inner
            .blocked_peers
            .values()
            .filter(|e| e.is_permanent())
            .count();
        let blocked_peers_temporary = inner
            .blocked_peers
            .values()
            .filter(|e| !e.is_permanent() && !e.is_expired())
            .count();

        let blocked_ips_permanent = inner
            .blocked_ips
            .values()
            .filter(|e| e.is_permanent())
            .count();
        let blocked_ips_temporary = inner
            .blocked_ips
            .values()
            .filter(|e| !e.is_permanent() && !e.is_expired())
            .count();

        BlocklistStats {
            blocked_peers_total: inner.blocked_peers.len(),
            blocked_peers_permanent,
            blocked_peers_temporary,
            blocked_ips_total: inner.blocked_ips.len(),
            blocked_ips_permanent,
            blocked_ips_temporary,
            allowed_peers: inner.allowed_peers.len(),
            allowed_ips: inner.allowed_ips.len(),
            mode: inner.mode,
            total_violations: inner.violations.values().sum(),
        }
    }
}

/// Blocklist statistics
#[derive(Debug, Clone, Default)]
pub struct BlocklistStats {
    pub blocked_peers_total: usize,
    pub blocked_peers_permanent: usize,
    pub blocked_peers_temporary: usize,
    pub blocked_ips_total: usize,
    pub blocked_ips_permanent: usize,
    pub blocked_ips_temporary: usize,
    pub allowed_peers: usize,
    pub allowed_ips: usize,
    pub mode: AccessMode,
    pub total_violations: usize,
}

/// Extract IP address from a multiaddr
fn extract_ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
    use libp2p::multiaddr::Protocol;

    for component in addr.iter() {
        match component {
            Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => continue,
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_block_peer_temporary() {
        let manager = BlocklistManager::new();
        let peer_id = PeerId::random();
        let addr = "/ip4/127.0.0.1/tcp/8000".parse().unwrap();

        assert!(manager.is_allowed(&peer_id, &addr));

        manager.block_peer(peer_id, BlockReason::Spam, Some(Duration::from_millis(100)));
        assert!(!manager.is_allowed(&peer_id, &addr));

        thread::sleep(Duration::from_millis(150));
        manager.cleanup_expired();
        assert!(manager.is_allowed(&peer_id, &addr));
    }

    #[test]
    fn test_block_peer_permanent() {
        let manager = BlocklistManager::new();
        let peer_id = PeerId::random();
        let addr = "/ip4/127.0.0.1/tcp/8000".parse().unwrap();

        manager.block_peer_permanent(peer_id, BlockReason::Malicious);
        assert!(!manager.is_allowed(&peer_id, &addr));

        thread::sleep(Duration::from_millis(100));
        manager.cleanup_expired();
        assert!(!manager.is_allowed(&peer_id, &addr));
    }

    #[test]
    fn test_block_ip() {
        let manager = BlocklistManager::new();
        let peer_id = PeerId::random();
        let ip = "127.0.0.1".parse().unwrap();
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/8000".parse().unwrap();

        manager.block_ip(ip, BlockReason::TooManyConnections, None);
        assert!(!manager.is_allowed(&peer_id, &addr));

        manager.unblock_ip(&ip);
        assert!(manager.is_allowed(&peer_id, &addr));
    }

    #[test]
    fn test_allowlist_mode() {
        let manager = BlocklistManager::new();
        let allowed_peer = PeerId::random();
        let blocked_peer = PeerId::random();
        let addr = "/ip4/127.0.0.1/tcp/8000".parse().unwrap();

        manager.set_mode(AccessMode::AllowListOnly);
        manager.allow_peer(allowed_peer);

        assert!(manager.is_allowed(&allowed_peer, &addr));
        assert!(!manager.is_allowed(&blocked_peer, &addr));
    }

    #[test]
    fn test_auto_blocking() {
        let manager = BlocklistManager::new();
        manager.set_auto_block_threshold(3);
        let peer_id = PeerId::random();
        let addr = "/ip4/127.0.0.1/tcp/8000".parse().unwrap();

        assert!(manager.is_allowed(&peer_id, &addr));

        // Record violations
        manager.record_violation(peer_id, BlockReason::ProtocolViolation);
        assert_eq!(manager.violation_count(&peer_id), 1);
        assert!(manager.is_allowed(&peer_id, &addr));

        manager.record_violation(peer_id, BlockReason::ProtocolViolation);
        assert_eq!(manager.violation_count(&peer_id), 2);
        assert!(manager.is_allowed(&peer_id, &addr));

        manager.record_violation(peer_id, BlockReason::ProtocolViolation);
        assert_eq!(manager.violation_count(&peer_id), 3);
        assert!(!manager.is_allowed(&peer_id, &addr)); // Auto-blocked
    }

    #[test]
    fn test_unblock_peer() {
        let manager = BlocklistManager::new();
        let peer_id = PeerId::random();
        let addr = "/ip4/127.0.0.1/tcp/8000".parse().unwrap();

        manager.block_peer_permanent(peer_id, BlockReason::Manual);
        assert!(!manager.is_allowed(&peer_id, &addr));

        manager.unblock_peer(&peer_id);
        assert!(manager.is_allowed(&peer_id, &addr));
    }

    #[test]
    fn test_stats() {
        let manager = BlocklistManager::new();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        manager.block_peer_permanent(peer1, BlockReason::Malicious);
        manager.block_peer(peer2, BlockReason::Spam, Some(Duration::from_secs(3600)));
        manager.block_ip(ip, BlockReason::Manual, None);
        manager.allow_peer(PeerId::random());

        let stats = manager.stats();
        assert_eq!(stats.blocked_peers_total, 2);
        assert_eq!(stats.blocked_peers_permanent, 1);
        assert_eq!(stats.blocked_peers_temporary, 1);
        assert_eq!(stats.blocked_ips_total, 1);
        assert_eq!(stats.allowed_peers, 1);
    }

    #[test]
    fn test_cleanup_expired() {
        let manager = BlocklistManager::new();
        let peer_id = PeerId::random();

        manager.block_peer(peer_id, BlockReason::Spam, Some(Duration::from_millis(50)));

        let stats = manager.stats();
        assert_eq!(stats.blocked_peers_total, 1);

        thread::sleep(Duration::from_millis(100));
        let removed = manager.cleanup_expired();
        assert_eq!(removed, 1);

        let stats = manager.stats();
        assert_eq!(stats.blocked_peers_total, 0);
    }

    #[test]
    fn test_clear_violations() {
        let manager = BlocklistManager::new();
        let peer_id = PeerId::random();

        manager.record_violation(peer_id, BlockReason::Spam);
        manager.record_violation(peer_id, BlockReason::Spam);
        assert_eq!(manager.violation_count(&peer_id), 2);

        manager.clear_violations(&peer_id);
        assert_eq!(manager.violation_count(&peer_id), 0);
    }
}

//! Graceful shutdown handling for the coordinator server
//!
//! This module provides graceful shutdown capabilities including:
//! - Signal handling (SIGTERM, SIGINT, SIGQUIT)
//! - Graceful connection draining
//! - Resource cleanup coordination
//! - Shutdown timeout enforcement

use std::time::Duration;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Shutdown signal type
#[derive(Debug, Clone, Copy)]
pub enum ShutdownSignal {
    /// SIGTERM - graceful termination
    Terminate,
    /// SIGINT - interrupt (Ctrl+C)
    Interrupt,
    /// SIGQUIT - quit with core dump
    Quit,
    /// Manual shutdown trigger
    Manual,
}

impl ShutdownSignal {
    /// Get a human-readable description
    pub fn description(&self) -> &'static str {
        match self {
            ShutdownSignal::Terminate => "SIGTERM",
            ShutdownSignal::Interrupt => "SIGINT (Ctrl+C)",
            ShutdownSignal::Quit => "SIGQUIT",
            ShutdownSignal::Manual => "Manual shutdown",
        }
    }
}

/// Shutdown coordinator that manages graceful shutdown
#[derive(Clone)]
pub struct ShutdownCoordinator {
    /// Broadcast channel for shutdown notifications
    tx: broadcast::Sender<ShutdownSignal>,
    /// Graceful shutdown timeout
    timeout: Duration,
}

impl ShutdownCoordinator {
    /// Create a new shutdown coordinator
    pub fn new(timeout: Duration) -> Self {
        let (tx, _) = broadcast::channel(16);
        Self { tx, timeout }
    }

    /// Create with default timeout (30 seconds)
    pub fn with_default_timeout() -> Self {
        Self::new(Duration::from_secs(30))
    }

    /// Subscribe to shutdown notifications
    pub fn subscribe(&self) -> broadcast::Receiver<ShutdownSignal> {
        self.tx.subscribe()
    }

    /// Trigger a manual shutdown
    pub fn trigger_shutdown(&self, signal: ShutdownSignal) {
        info!(signal = signal.description(), "Shutdown triggered");
        let _ = self.tx.send(signal);
    }

    /// Get the configured timeout
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Wait for a shutdown signal from the OS
    pub async fn wait_for_signal(&self) {
        let signal = wait_for_shutdown_signal().await;
        self.trigger_shutdown(signal);
    }
}

/// Wait for shutdown signal from the operating system
async fn wait_for_shutdown_signal() -> ShutdownSignal {
    #[cfg(unix)]
    {
        use signal::unix::{SignalKind, signal};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("Failed to install SIGINT handler");
        let mut sigquit = signal(SignalKind::quit()).expect("Failed to install SIGQUIT handler");

        tokio::select! {
            _ = sigterm.recv() => ShutdownSignal::Terminate,
            _ = sigint.recv() => ShutdownSignal::Interrupt,
            _ = sigquit.recv() => ShutdownSignal::Quit,
        }
    }

    #[cfg(not(unix))]
    {
        // On Windows, we only have Ctrl+C
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        ShutdownSignal::Interrupt
    }
}

/// Shutdown task tracker for coordinating cleanup tasks
pub struct ShutdownTracker {
    task_name: String,
    completed: bool,
}

impl ShutdownTracker {
    /// Create a new shutdown tracker
    pub fn new(task_name: impl Into<String>) -> Self {
        Self {
            task_name: task_name.into(),
            completed: false,
        }
    }

    /// Mark the shutdown task as completed
    pub fn complete(&mut self) {
        if !self.completed {
            info!(task = %self.task_name, "Shutdown task completed");
            self.completed = true;
        }
    }

    /// Check if the task is completed
    pub fn is_completed(&self) -> bool {
        self.completed
    }
}

impl Drop for ShutdownTracker {
    fn drop(&mut self) {
        if !self.completed {
            warn!(
                task = %self.task_name,
                "Shutdown task dropped without completion"
            );
        }
    }
}

/// Perform graceful shutdown sequence
#[allow(dead_code)]
pub async fn perform_graceful_shutdown(
    coordinator: &ShutdownCoordinator,
    mut shutdown_rx: broadcast::Receiver<ShutdownSignal>,
) {
    // Wait for shutdown signal
    if let Ok(signal) = shutdown_rx.recv().await {
        info!(
            signal = signal.description(),
            timeout_secs = coordinator.timeout().as_secs(),
            "Beginning graceful shutdown"
        );

        // Start shutdown timeout
        let timeout = coordinator.timeout();
        let shutdown_start = std::time::Instant::now();

        // Give tasks time to complete
        tokio::select! {
            _ = tokio::time::sleep(timeout) => {
                warn!(
                    elapsed_secs = shutdown_start.elapsed().as_secs(),
                    "Shutdown timeout reached, forcing exit"
                );
            }
            _ = async {
                // Wait a bit for connections to drain
                tokio::time::sleep(Duration::from_secs(5)).await;
                info!("Connection draining period completed");
            } => {
                info!(
                    elapsed_secs = shutdown_start.elapsed().as_secs(),
                    "Graceful shutdown completed successfully"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shutdown_coordinator_creation() {
        let coordinator = ShutdownCoordinator::with_default_timeout();
        assert_eq!(coordinator.timeout().as_secs(), 30);
    }

    #[test]
    fn test_shutdown_signal_description() {
        assert_eq!(ShutdownSignal::Terminate.description(), "SIGTERM");
        assert_eq!(ShutdownSignal::Interrupt.description(), "SIGINT (Ctrl+C)");
        assert_eq!(ShutdownSignal::Quit.description(), "SIGQUIT");
        assert_eq!(ShutdownSignal::Manual.description(), "Manual shutdown");
    }

    #[tokio::test]
    async fn test_shutdown_subscription() {
        let coordinator = ShutdownCoordinator::with_default_timeout();
        let mut rx = coordinator.subscribe();

        // Trigger shutdown in background
        let coord_clone = coordinator.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            coord_clone.trigger_shutdown(ShutdownSignal::Manual);
        });

        // Wait for signal
        let signal = rx.recv().await.unwrap();
        assert!(matches!(signal, ShutdownSignal::Manual));
    }

    #[test]
    fn test_shutdown_tracker() {
        let mut tracker = ShutdownTracker::new("test_task");
        assert!(!tracker.is_completed());

        tracker.complete();
        assert!(tracker.is_completed());

        // Calling complete again should be idempotent
        tracker.complete();
        assert!(tracker.is_completed());
    }

    #[test]
    fn test_custom_timeout() {
        let timeout = Duration::from_secs(60);
        let coordinator = ShutdownCoordinator::new(timeout);
        assert_eq!(coordinator.timeout().as_secs(), 60);
    }
}

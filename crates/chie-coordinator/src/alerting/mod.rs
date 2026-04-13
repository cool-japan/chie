//! Comprehensive alerting system for CHIE Coordinator.
//!
//! Provides multi-channel alert notifications with configurable rules,
//! severity levels, escalation policies, and alert deduplication.
//!
//! This module is split into focused sub-modules:
//! - `types`    — All data types and the `AlertingManager` struct
//! - `rules`    — Rule management, metric evaluation, alert lifecycle
//! - `channels` — Notification channel implementations (console, email, Slack, webhook)
//! - `email`    — Email retry queue, bounce tracking, unsubscribes, SLA monitoring
//! - `utils`    — Shared utility functions

pub mod channels;
pub mod email;
pub mod rules;
pub mod types;
pub mod utils;

#[cfg(test)]
mod tests;

// Re-export the full public API so callers can continue to use `crate::alerting::*`
#[allow(unused_imports)]
pub use types::{
    Alert, AlertChannel, AlertCondition, AlertRule, AlertSeverity, AlertStats, AlertStatus,
    AlertingConfig, AlertingManager, ComparisonOperator, EmailBounce, EmailBounceConfig,
    EmailPriority, EmailRetryConfig, EmailSlaConfig, EmailSlaMetrics, EmailUnsubscribe,
    EmailUnsubscribeConfig, FailedEmail, SmtpConfig, UnsubscribeSource,
};

//! Common types used across CHIE Protocol.
//!
//! This module is organized into several submodules:
//! - `core`: Core type aliases and constants
//! - `enums`: Enumeration types (categories, statuses, roles, etc.)
//! - `validation`: Validation types and error handling
//! - `content`: Content metadata and related types
//! - `bandwidth`: Bandwidth proof protocol types
//! - `api`: API-related types (responses, errors, pagination, etc.)
//! - `stats`: Statistics and metrics types
//! - `cache`: Cache statistics and metrics types
//! - `profiling`: Performance profiling and operation metrics types
//! - `quota`: Quota management types (storage, bandwidth, rate limits)
//! - `batch`: Batch operation types for efficient processing
//! - `ids`: Strongly-typed ID wrappers for type safety
//! - `fixed_arrays`: Const-generic fixed-size array types for cryptographic operations
//! - `experiments`: A/B testing and feature experiment types
//! - `state_machine`: Phantom types for compile-time state machine enforcement
//! - `gamification`: Gamification types (badges, quests, leaderboard, user state)

pub mod api;
pub mod bandwidth;
pub mod batch;
pub mod cache;
pub mod content;
pub mod core;
pub mod enums;
pub mod experiments;
pub mod fixed_arrays;
pub mod gamification;
pub mod ids;
pub mod profiling;
pub mod quota;
pub mod state_machine;
pub mod stats;
pub mod validation;

// Re-export everything from submodules for convenience
pub use api::*;
pub use bandwidth::*;
pub use batch::*;
pub use cache::*;
pub use content::*;
pub use core::*;
pub use enums::*;
pub use experiments::*;
pub use fixed_arrays::*;
pub use ids::*;
pub use profiling::*;
pub use quota::*;
pub use state_machine::*;
pub use stats::*;
pub use validation::*;

// Re-export key gamification types (submodule kept separate to avoid name clashes)
pub use gamification::{
    Badge, LeaderboardEntry, Quest, QuestStatus, QuestType, UserGamificationState,
};

// Re-export test helpers for use in other crates' tests
#[cfg(test)]
pub use bandwidth::test_helpers;

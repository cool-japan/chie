//! Serialization helpers for oxicode.
//!
//! This module provides simplified wrappers for oxicode serialization
//! with the standard configuration, hiding the API details.

use serde::{Deserialize, Serialize};

/// Encode a value to bytes using oxicode with standard configuration.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, oxicode::error::Error> {
    oxicode::serde::encode_to_vec(value, oxicode::config::standard())
}

/// Decode bytes to a value using oxicode with standard configuration.
pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, oxicode::error::Error> {
    oxicode::serde::decode_from_slice(bytes, oxicode::config::standard()).map(|(v, _)| v)
}

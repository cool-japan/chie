//! Utility functions for CHIE Protocol.

// Module declarations
mod calculations;
mod circuit_breaker;
mod collections;
mod content;
mod formatting;
mod network;
mod security;
mod statistics;
mod time;
mod time_window;
mod validation;

// Re-export statistics types
pub use statistics::{ExponentialBackoff, Histogram, SlidingWindow, StreamingStats};

// Re-export circuit breaker types
pub use circuit_breaker::{CircuitBreaker, CircuitState};

// Re-export time window types
pub use time_window::{BucketedTimeSeries, SlidingWindowRateLimiter, TimeBucket, TimeWindow};

// Re-export time functions
pub use time::{
    format_timestamp, is_timestamp_valid, ms_to_secs, now_ms, now_secs, parse_duration_str,
    secs_to_ms,
};

// Re-export formatting functions
pub use formatting::{
    cid_to_short_id, format_bandwidth, format_bytes, format_duration_ms, format_points,
    format_ratio_as_percentage, generate_slug, normalize_tag, sanitize_string, sanitize_tag,
    sanitize_tags, truncate_string,
};

// Re-export validation functions
pub use validation::{
    is_private_ipv4, is_safe_string, is_valid_cid, is_valid_email, is_valid_hex, is_valid_ipv4,
    is_valid_ipv6, is_valid_multiaddr, is_valid_peer_id, is_valid_port, is_valid_url,
    is_valid_username, validate_and_sanitize_tag, validate_bandwidth_reasonable,
    validate_blake3_hash, validate_challenge_nonce, validate_chunk_indices_batch,
    validate_chunk_size, validate_cids_batch, validate_content_size_in_range,
    validate_ed25519_public_key, validate_ed25519_signature, validate_emails_batch,
    validate_hash_length, validate_latency, validate_nonce_length, validate_price_range,
    validate_proof_freshness, validate_public_key_length, validate_signature_length,
    validate_tags_list, validate_usernames_batch,
};

// Re-export calculation functions
pub use calculations::{
    actual_chunk_size, average, bps_to_mbps, byte_to_chunk_index, bytes_to_gb_f64,
    calculate_bandwidth_mbps, calculate_content_price, calculate_creator_share,
    calculate_demand_multiplier, calculate_ema, calculate_growth_rate, calculate_latency_ms,
    calculate_mean, calculate_median, calculate_moving_average, calculate_percentage,
    calculate_percentage_change, calculate_percentile, calculate_platform_fee,
    calculate_provider_earnings, calculate_rate, calculate_reputation_bonus,
    calculate_reputation_decay, calculate_reward_with_penalty, calculate_sliding_window_count,
    calculate_stats, calculate_std_dev, calculate_storage_cost, calculate_token_bucket,
    calculate_uptime_percentage, calculate_z_score, chunk_byte_range, chunk_offset, clamp,
    estimate_transfer_time, gb_to_bytes_f64, is_outlier_iqr, is_rate_limit_allowed,
    is_valid_chunk_index, is_within_tolerance, lerp, mbps_to_bps, normalize,
    round_down_to_multiple, round_up_to_multiple, update_reputation,
};

// Re-export security functions
pub use security::{
    constant_time_eq, constant_time_eq_32, count_set_bits, decode_hex, encode_hex, generate_nonce,
    is_all_zeros, random_jitter, rotate_bytes_left, rotate_bytes_right, xor_bytes,
};

// Re-export network functions
pub use network::{
    chunk_vec, extract_peer_id_from_multiaddr, generate_session_id, is_valid_peer_id_format,
    parse_bandwidth_str,
};

// Re-export content functions
pub use content::{get_file_extension, has_valid_extension, mime_to_category_hint};

// Re-export collection functions
pub use collections::{
    batch_by_size, deduplicate_preserve_order, find_duplicates, flatten, group_by, merge_sorted,
    partition, skip, take, zip_with,
};

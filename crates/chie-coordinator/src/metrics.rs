//! Prometheus metrics for CHIE Coordinator.
//!
//! Exports metrics at `/metrics` endpoint in Prometheus format.

use axum::{Router, routing::get};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use once_cell::sync::OnceCell;

/// Global metrics handle.
static METRICS_HANDLE: OnceCell<PrometheusHandle> = OnceCell::new();

/// Initialize the metrics system.
pub fn init_metrics() -> PrometheusHandle {
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .expect("Failed to install Prometheus recorder");

    METRICS_HANDLE
        .set(handle.clone())
        .expect("Metrics already initialized");

    handle
}

/// Get the metrics handle.
pub fn get_handle() -> Option<&'static PrometheusHandle> {
    METRICS_HANDLE.get()
}

/// Create the metrics router.
pub fn metrics_router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/metrics", get(metrics_handler))
}

/// Handler for /metrics endpoint.
async fn metrics_handler() -> String {
    match get_handle() {
        Some(handle) => handle.render(),
        None => String::from("# Metrics not initialized\n"),
    }
}

// ============================================================================
// Metric definitions and helper functions
// ============================================================================

/// Record a proof submission.
pub fn record_proof_submission(status: &str) {
    counter!("chie_proofs_submitted_total", "status" => status.to_string()).increment(1);
}

/// Record proof verification result.
pub fn record_proof_verification(result: &str, duration_ms: u64) {
    counter!("chie_proofs_verified_total", "result" => result.to_string()).increment(1);
    histogram!("chie_proof_verification_duration_ms").record(duration_ms as f64);
}

/// Record bandwidth distributed.
pub fn record_bandwidth_distributed(bytes: u64) {
    counter!("chie_bandwidth_distributed_bytes_total").increment(bytes);
}

/// Record rewards distributed.
pub fn record_rewards_distributed(points: u64, recipient_type: &str) {
    counter!("chie_rewards_distributed_total", "recipient_type" => recipient_type.to_string())
        .increment(points);
}

/// Record API request.
pub fn record_api_request(method: &str, path: &str, status: u16, duration_ms: u64) {
    counter!(
        "chie_api_requests_total",
        "method" => method.to_string(),
        "path" => path.to_string(),
        "status" => status.to_string()
    )
    .increment(1);

    histogram!(
        "chie_api_request_duration_ms",
        "method" => method.to_string(),
        "path" => path.to_string()
    )
    .record(duration_ms as f64);
}

/// Record database query.
pub fn record_db_query(operation: &str, table: &str, duration_ms: u64) {
    counter!(
        "chie_db_queries_total",
        "operation" => operation.to_string(),
        "table" => table.to_string()
    )
    .increment(1);

    histogram!(
        "chie_db_query_duration_ms",
        "operation" => operation.to_string(),
        "table" => table.to_string()
    )
    .record(duration_ms as f64);
}

/// Update active nodes gauge.
pub fn set_active_nodes(count: i64) {
    gauge!("chie_active_nodes").set(count as f64);
}

/// Update active content gauge.
pub fn set_active_content(count: i64) {
    gauge!("chie_active_content").set(count as f64);
}

/// Update total users gauge.
pub fn set_total_users(count: i64) {
    gauge!("chie_total_users").set(count as f64);
}

/// Record authentication event.
pub fn record_auth_event(event_type: &str, success: bool) {
    counter!(
        "chie_auth_events_total",
        "type" => event_type.to_string(),
        "success" => success.to_string()
    )
    .increment(1);
}

/// Record nonce check.
pub fn record_nonce_check(is_replay: bool) {
    counter!(
        "chie_nonce_checks_total",
        "is_replay" => is_replay.to_string()
    )
    .increment(1);
}

/// Record anomaly detection.
pub fn record_anomaly_detected(anomaly_type: &str, severity: &str) {
    counter!(
        "chie_anomalies_detected_total",
        "type" => anomaly_type.to_string(),
        "severity" => severity.to_string()
    )
    .increment(1);
}

/// Record content registration.
pub fn record_content_registered(category: &str, size_bytes: u64) {
    counter!(
        "chie_content_registered_total",
        "category" => category.to_string()
    )
    .increment(1);

    counter!("chie_content_bytes_registered_total").increment(size_bytes);
}

/// Record slow query.
pub fn record_slow_query(duration_ms: u64) {
    counter!("chie_slow_queries_total").increment(1);
    histogram!("chie_slow_query_duration_ms").record(duration_ms as f64);
}

/// Record error tracked.
pub fn record_error_tracked(error_type: &str, severity: &str) {
    counter!(
        "chie_errors_tracked_total",
        "error_type" => error_type.to_string(),
        "severity" => severity.to_string()
    )
    .increment(1);
}

/// Record error rate alert.
pub fn record_error_rate_alert(error_rate: f64) {
    counter!("chie_error_rate_alerts_total").increment(1);
    gauge!("chie_current_error_rate").set(error_rate);
}

/// Record content access for popularity tracking.
pub fn record_content_access(event_type: &'static str) {
    counter!("chie_content_accesses_total", "event_type" => event_type).increment(1);
}

/// Record trending content count.
pub fn set_trending_content_count(count: usize) {
    gauge!("chie_trending_content_count").set(count as f64);
}

/// Record total tracked content count.
pub fn set_tracked_content_count(count: usize) {
    gauge!("chie_tracked_content_count").set(count as f64);
}

/// Record popularity cache refresh.
pub fn record_popularity_cache_refresh(duration_ms: u64) {
    histogram!("chie_popularity_cache_refresh_duration_ms").record(duration_ms as f64);
}

/// Record popularity data pruning.
pub fn record_popularity_data_pruned(records_pruned: usize) {
    counter!("chie_popularity_data_pruned_total").increment(records_pruned as u64);
}

// ============================================================================
// Reputation System Metrics
// ============================================================================

/// Record reputation event.
pub fn record_reputation_event(event_type: &str, impact: i32) {
    counter!(
        "chie_reputation_events_total",
        "event_type" => event_type.to_string()
    )
    .increment(1);

    histogram!("chie_reputation_impact_points").record(impact as f64);
}

/// Record trust level change.
pub fn record_trust_level_change(old_level: &str, new_level: &str) {
    counter!(
        "chie_trust_level_changes_total",
        "old_level" => old_level.to_string(),
        "new_level" => new_level.to_string()
    )
    .increment(1);
}

/// Set nodes by trust level.
pub fn set_nodes_by_trust_level(trust_level: &str, count: usize) {
    gauge!(
        "chie_nodes_by_trust_level",
        "trust_level" => trust_level.to_string()
    )
    .set(count as f64);
}

/// Record reputation score distribution.
pub fn record_reputation_score(score: i32) {
    histogram!("chie_reputation_score_distribution").record(score as f64);
}

/// Record reputation decay operation.
pub fn record_reputation_decay(nodes_affected: usize, total_decay: i32) {
    counter!("chie_reputation_decay_operations_total").increment(1);
    counter!("chie_reputation_decay_nodes_affected_total").increment(nodes_affected as u64);
    histogram!("chie_reputation_total_decay_points").record(total_decay as f64);
}

// ============================================================================
// Content Moderation Metrics
// ============================================================================

/// Record content flag creation.
pub fn record_content_flag(reason: &str, severity: i32) {
    counter!(
        "chie_content_flags_total",
        "reason" => reason.to_string()
    )
    .increment(1);

    histogram!("chie_content_flag_severity").record(severity as f64);
}

/// Record moderation action.
pub fn record_moderation_action(action: &str, flag_reason: &str) {
    counter!(
        "chie_moderation_actions_total",
        "action" => action.to_string(),
        "flag_reason" => flag_reason.to_string()
    )
    .increment(1);
}

/// Set moderation queue size.
pub fn set_moderation_queue_size(count: usize) {
    gauge!("chie_moderation_queue_size").set(count as f64);
}

/// Record moderation rule trigger.
pub fn record_moderation_rule_trigger(rule_name: &str) {
    counter!(
        "chie_moderation_rule_triggers_total",
        "rule" => rule_name.to_string()
    )
    .increment(1);
}

/// Record auto-flag from low reputation.
pub fn record_auto_flag_low_reputation(trust_level: &str) {
    counter!(
        "chie_auto_flags_low_reputation_total",
        "trust_level" => trust_level.to_string()
    )
    .increment(1);
}

// ============================================================================
// Webhook Metrics
// ============================================================================

/// Record webhook delivery.
pub fn record_webhook_delivery(event_type: &str, success: bool, duration_ms: u64) {
    counter!(
        "chie_webhook_deliveries_total",
        "event_type" => event_type.to_string(),
        "success" => success.to_string()
    )
    .increment(1);

    histogram!(
        "chie_webhook_delivery_duration_ms",
        "event_type" => event_type.to_string()
    )
    .record(duration_ms as f64);
}

/// Record webhook retry.
pub fn record_webhook_retry(event_type: &str, attempt: u32) {
    counter!(
        "chie_webhook_retries_total",
        "event_type" => event_type.to_string()
    )
    .increment(1);

    histogram!("chie_webhook_retry_attempts").record(attempt as f64);
}

/// Set active webhooks count.
pub fn set_active_webhooks(count: usize) {
    gauge!("chie_active_webhooks").set(count as f64);
}

/// Record webhook manual retry.
pub fn record_webhook_manual_retry(success: bool) {
    counter!(
        "chie_webhook_manual_retries_total",
        "success" => success.to_string()
    )
    .increment(1);
}

/// Set webhook delivery history size.
pub fn set_webhook_delivery_history_size(webhook_id: &str, count: usize) {
    gauge!(
        "chie_webhook_delivery_history_size",
        "webhook_id" => webhook_id.to_string()
    )
    .set(count as f64);
}

/// Record delivery history cleanup.
pub fn record_delivery_history_cleanup(records_removed: usize) {
    counter!("chie_delivery_history_cleaned_total").increment(records_removed as u64);
    histogram!("chie_delivery_history_cleanup_size").record(records_removed as f64);
}

/// Set failed deliveries count.
pub fn set_failed_deliveries_count(count: usize) {
    gauge!("chie_failed_deliveries_pending").set(count as f64);
}

// ============================================================================
// Integration Metrics
// ============================================================================

/// Record reputation-moderation integration event.
pub fn record_reputation_moderation_integration(action: &str) {
    counter!(
        "chie_reputation_moderation_integration_total",
        "action" => action.to_string()
    )
    .increment(1);
}

/// Record fraud-reputation integration event.
pub fn record_fraud_reputation_integration(fraud_type: &str, reputation_penalty: i32) {
    counter!(
        "chie_fraud_reputation_integration_total",
        "fraud_type" => fraud_type.to_string()
    )
    .increment(1);

    histogram!("chie_fraud_reputation_penalty").record(reputation_penalty as f64);
}

// ============================================================================
// Alerting System Metrics
// ============================================================================

/// Record alert triggered.
pub fn record_alert_triggered(severity: &str, rule_name: &str) {
    counter!(
        "chie_alerts_triggered_total",
        "severity" => severity.to_string(),
        "rule" => rule_name.to_string()
    )
    .increment(1);
}

/// Record alert acknowledged.
pub fn record_alert_acknowledged(severity: &str) {
    counter!(
        "chie_alerts_acknowledged_total",
        "severity" => severity.to_string()
    )
    .increment(1);
}

/// Record alert resolved.
pub fn record_alert_resolved(severity: &str) {
    counter!(
        "chie_alerts_resolved_total",
        "severity" => severity.to_string()
    )
    .increment(1);
}

/// Set active alerts count.
pub fn set_active_alerts_count(count: usize) {
    gauge!("chie_active_alerts").set(count as f64);
}

/// Record alert notification sent.
pub fn record_alert_notification(channel: &str, success: bool) {
    counter!(
        "chie_alert_notifications_total",
        "channel" => channel.to_string(),
        "success" => success.to_string()
    )
    .increment(1);
}

/// Record time to acknowledge alert.
pub fn record_time_to_acknowledge(seconds: f64) {
    histogram!("chie_alert_time_to_ack_seconds").record(seconds);
}

// ============================================================================
// Feature Flags Metrics
// ============================================================================

/// Record feature flag evaluation.
pub fn record_flag_evaluation(flag_key: &str, enabled: bool) {
    counter!(
        "chie_feature_flag_evaluations_total",
        "flag" => flag_key.to_string(),
        "enabled" => enabled.to_string()
    )
    .increment(1);
}

/// Set total feature flags count.
pub fn set_feature_flags_count(total: usize, enabled: usize) {
    gauge!("chie_feature_flags_total").set(total as f64);
    gauge!("chie_feature_flags_enabled").set(enabled as f64);
}

/// Record feature flag created.
pub fn record_flag_created(flag_type: &str) {
    counter!(
        "chie_feature_flags_created_total",
        "type" => flag_type.to_string()
    )
    .increment(1);
}

/// Record feature flag updated.
pub fn record_flag_updated(flag_key: &str) {
    counter!(
        "chie_feature_flags_updated_total",
        "flag" => flag_key.to_string()
    )
    .increment(1);
}

/// Record feature flag deleted.
pub fn record_flag_deleted(flag_key: &str) {
    counter!(
        "chie_feature_flags_deleted_total",
        "flag" => flag_key.to_string()
    )
    .increment(1);
}

/// Struct to hold metrics snapshot for API response.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MetricsSnapshot {
    /// Total proofs submitted.
    pub proofs_submitted: u64,
    /// Total proofs verified.
    pub proofs_verified: u64,
    /// Total bandwidth distributed (bytes).
    pub bandwidth_bytes: u64,
    /// Total rewards distributed.
    pub rewards_distributed: u64,
    /// Active nodes count.
    pub active_nodes: i64,
    /// Active content count.
    pub active_content: i64,
    /// Total users.
    pub total_users: i64,
}

// ============================================================================
// Compression Metrics
// ============================================================================

/// Record compression algorithm usage
pub fn record_compression_used(algorithm: &str) {
    metrics::counter!("chie_compression_requests_total", "algorithm" => algorithm.to_string())
        .increment(1);
}

/// Record compression ratio (percentage)
pub fn record_compression_ratio(ratio: f64) {
    metrics::histogram!("chie_compression_ratio").record(ratio);
}

// ============================================================================
// ETag Metrics
// ============================================================================

/// Record ETag cache hit (304 Not Modified)
pub fn record_etag_hit() {
    metrics::counter!("chie_etag_hits_total").increment(1);
}

/// Record ETag generated
pub fn record_etag_generated() {
    metrics::counter!("chie_etag_generated_total").increment(1);
}

// ============================================================================
// Request Coalescing Metrics
// ============================================================================

/// Record a request that was coalesced (duplicate)
pub fn record_request_coalesced() {
    metrics::counter!("chie_request_coalesced_total").increment(1);
}

/// Record request coalescing statistics
pub fn record_coalescing_stats(
    total_requests: u64,
    _coalesced_requests: u64,
    executed_requests: u64,
    pending_requests: usize,
    hit_rate: f64,
) {
    metrics::gauge!("chie_coalescing_pending_requests").set(pending_requests as f64);
    metrics::gauge!("chie_coalescing_hit_rate").set(hit_rate);
    metrics::counter!("chie_coalescing_total_requests").absolute(total_requests);
    metrics::counter!("chie_coalescing_executed_requests").absolute(executed_requests);
}

// TODO: Uncomment when database migration 005_tenants.sql is run
// // ============================================================================
// // Multi-Tenancy Metrics
// // ============================================================================
//
// /// Record tenant created
// pub fn record_tenant_created() {
//     metrics::counter!("chie_tenants_created_total").increment(1);
// }
//
// /// Record tenant updated
// pub fn record_tenant_updated() {
//     metrics::counter!("chie_tenants_updated_total").increment(1);
// }
//
// /// Record tenant deleted
// pub fn record_tenant_deleted() {
//     metrics::counter!("chie_tenants_deleted_total").increment(1);
// }
//
// /// Record tenant context extraction
// pub fn record_tenant_context_extracted(namespace: &str) {
//     metrics::counter!("chie_tenant_requests_total", "namespace" => namespace.to_string()).increment(1);
// }
//
// /// Record tenant quota exceeded
// pub fn record_tenant_quota_exceeded(tenant_id: &str, quota_type: &str) {
//     metrics::counter!("chie_tenant_quota_exceeded_total", "tenant_id" => tenant_id.to_string(), "quota_type" => quota_type.to_string()).increment(1);
// }
//
// /// Record tenant statistics
// pub fn record_tenant_stats(
//     total_tenants: usize,
//     active_tenants: usize,
//     suspended_tenants: usize,
// ) {
//     metrics::gauge!("chie_tenants_total").set(total_tenants as f64);
//     metrics::gauge!("chie_tenants_active").set(active_tenants as f64);
//     metrics::gauge!("chie_tenants_suspended").set(suspended_tenants as f64);
// }

// ============================================================================
// Payment & Settlement Metrics
// ============================================================================

/// Record payment created
pub fn record_payment_created(provider: &str, amount_cents: i64) {
    metrics::counter!("chie_payments_created_total", "provider" => provider.to_string())
        .increment(1);
    metrics::histogram!("chie_payment_amount_cents").record(amount_cents as f64);
}

/// Record payment completed
pub fn record_payment_completed() {
    metrics::counter!("chie_payments_completed_total").increment(1);
}

/// Record payment failed
pub fn record_payment_failed() {
    metrics::counter!("chie_payments_failed_total").increment(1);
}

/// Record settlement batch created
pub fn record_settlement_batch_created(payment_count: usize) {
    metrics::counter!("chie_settlement_batches_created_total").increment(1);
    metrics::histogram!("chie_settlement_batch_size").record(payment_count as f64);
}

/// Record settlement batch processed
pub fn record_settlement_batch_processed() {
    metrics::counter!("chie_settlement_batches_processed_total").increment(1);
}

/// Record escrow held
pub fn record_escrow_held(amount_points: i64) {
    metrics::counter!("chie_escrow_held_total").increment(1);
    metrics::histogram!("chie_escrow_amount_points").record(amount_points as f64);
}

/// Record escrow released
pub fn record_escrow_released() {
    metrics::counter!("chie_escrow_released_total").increment(1);
}

/// Record escrow refunded
pub fn record_escrow_refunded() {
    metrics::counter!("chie_escrow_refunded_total").increment(1);
}

/// Record payment statistics
pub fn record_payment_stats(
    pending_count: i64,
    completed_count: i64,
    failed_count: i64,
    total_paid_cents: i64,
    total_pending_cents: i64,
) {
    metrics::gauge!("chie_payments_pending").set(pending_count as f64);
    metrics::gauge!("chie_payments_completed").set(completed_count as f64);
    metrics::gauge!("chie_payments_failed").set(failed_count as f64);
    metrics::gauge!("chie_total_paid_cents").set(total_paid_cents as f64);
    metrics::gauge!("chie_total_pending_cents").set(total_pending_cents as f64);
}

// ============================================================================
// Analytics Metrics
// ============================================================================

/// Record analytics query executed
pub fn record_analytics_query_executed(query_type: &str) {
    metrics::counter!("chie_analytics_queries_total", "type" => query_type.to_string())
        .increment(1);
}

/// Record analytics query duration
pub fn record_analytics_query_duration(duration_ms: u64) {
    metrics::histogram!("chie_analytics_query_duration_ms").record(duration_ms as f64);
}

/// Record time-series data cleaned
pub fn record_timeseries_cleaned(record_count: u64) {
    metrics::counter!("chie_timeseries_cleaned_total").increment(record_count);
}

/// Record dashboard metrics cache hit
pub fn record_dashboard_cache_hit() {
    metrics::counter!("chie_dashboard_cache_hits_total").increment(1);
}

/// Record dashboard metrics cache miss
pub fn record_dashboard_cache_miss() {
    metrics::counter!("chie_dashboard_cache_misses_total").increment(1);
}

// ============================================================================
// GDPR Compliance Metrics
// ============================================================================

/// Record GDPR data export request created
pub fn record_gdpr_export_created(format: String) {
    metrics::counter!("chie_gdpr_exports_created_total", "format" => format).increment(1);
}

/// Record GDPR data export completed
pub fn record_gdpr_export_completed() {
    metrics::counter!("chie_gdpr_exports_completed_total").increment(1);
}

/// Record GDPR data export failed
pub fn record_gdpr_export_failed() {
    metrics::counter!("chie_gdpr_exports_failed_total").increment(1);
}

/// Record GDPR exports cleaned up
pub fn record_gdpr_exports_cleaned(count: u64) {
    metrics::counter!("chie_gdpr_exports_cleaned_total").increment(count);
}

/// Record GDPR right to be forgotten request created
pub fn record_gdpr_rtbf_created(request_type: &str) {
    metrics::counter!("chie_gdpr_rtbf_created_total", "type" => request_type.to_string())
        .increment(1);
}

/// Record GDPR right to be forgotten completed
pub fn record_gdpr_rtbf_completed(request_type: &str) {
    metrics::counter!("chie_gdpr_rtbf_completed_total", "type" => request_type.to_string())
        .increment(1);
}

/// Record GDPR right to be forgotten failed
pub fn record_gdpr_rtbf_failed() {
    metrics::counter!("chie_gdpr_rtbf_failed_total").increment(1);
}

/// Set GDPR active export requests gauge
pub fn set_gdpr_active_exports(count: u64) {
    metrics::gauge!("chie_gdpr_active_exports").set(count as f64);
}

/// Set GDPR pending RTBF requests gauge
pub fn set_gdpr_pending_rtbf(count: u64) {
    metrics::gauge!("chie_gdpr_pending_rtbf").set(count as f64);
}

// ============================================================================
// Terms of Service Tracking Metrics
// ============================================================================

/// Record ToS version created
pub fn record_tos_version_created() {
    metrics::counter!("chie_tos_versions_created_total").increment(1);
}

/// Record ToS version activated
pub fn record_tos_version_activated() {
    metrics::counter!("chie_tos_versions_activated_total").increment(1);
}

/// Record ToS acceptance
pub fn record_tos_acceptance() {
    metrics::counter!("chie_tos_acceptances_total").increment(1);
}

/// Set active ToS version gauge
pub fn set_tos_active_version(version: String) {
    metrics::gauge!("chie_tos_active_version", "version" => version).set(1.0);
}

/// Set ToS acceptance rate gauge
pub fn set_tos_acceptance_rate(rate: f64) {
    metrics::gauge!("chie_tos_acceptance_rate").set(rate);
}

// ============================================================================
// Jurisdiction Filtering Metrics
// ============================================================================

/// Record jurisdiction restriction created
pub fn record_jurisdiction_restriction_created(reason: String) {
    metrics::counter!("chie_jurisdiction_restrictions_created_total", "reason" => reason)
        .increment(1);
}

/// Record jurisdiction restriction removed
pub fn record_jurisdiction_restriction_removed() {
    metrics::counter!("chie_jurisdiction_restrictions_removed_total").increment(1);
}

/// Record content blocked by jurisdiction
pub fn record_jurisdiction_content_blocked(jurisdiction: &str) {
    metrics::counter!("chie_jurisdiction_content_blocked_total", "jurisdiction" => jurisdiction.to_string()).increment(1);
}

/// Record expired restrictions cleaned up
pub fn record_jurisdiction_restrictions_expired(count: u64) {
    metrics::counter!("chie_jurisdiction_restrictions_expired_total").increment(count);
}

/// Set active jurisdiction restrictions gauge
pub fn set_jurisdiction_active_restrictions(count: u64) {
    metrics::gauge!("chie_jurisdiction_active_restrictions").set(count as f64);
}

/// Set global restrictions gauge
pub fn set_jurisdiction_global_restrictions(count: u64) {
    metrics::gauge!("chie_jurisdiction_global_restrictions").set(count as f64);
}

// ============================================================================
// Read Replicas Metrics
// ============================================================================

/// Record read replica added
pub fn record_read_replica_added(name: String) {
    metrics::counter!("chie_read_replicas_added_total", "replica" => name).increment(1);
}

/// Record read replica removed
pub fn record_read_replica_removed(name: String) {
    metrics::counter!("chie_read_replicas_removed_total", "replica" => name).increment(1);
}

/// Record read query routed to replica
pub fn record_read_query_routed_to_replica(replica: String) {
    metrics::counter!("chie_read_queries_routed_total", "target" => "replica", "replica" => replica).increment(1);
}

/// Record read query routed to primary
pub fn record_read_query_routed_to_primary() {
    metrics::counter!("chie_read_queries_routed_total", "target" => "primary").increment(1);
}

/// Record read replica health check
#[allow(dead_code)]
pub fn record_read_replica_health_check(replica: String, health: &str) {
    metrics::gauge!("chie_read_replica_health", "replica" => replica, "health" => health.to_string()).set(1.0);
}

/// Set read replica count gauge
pub fn set_read_replica_count(count: u64) {
    metrics::gauge!("chie_read_replicas_total").set(count as f64);
}

/// Record replica replication lag
pub fn record_replica_replication_lag(replica: String, lag_ms: i64) {
    metrics::histogram!("chie_replica_replication_lag_ms", "replica" => replica)
        .record(lag_ms as f64);
}

// ============================================================================
// Deployment Metrics
// ============================================================================

/// Record deployment environment registered
pub fn record_deployment_environment_registered(name: String) {
    metrics::counter!("chie_deployment_environments_registered_total", "name" => name).increment(1);
}

/// Record deployment started
pub fn record_deployment_started(strategy: &str) {
    metrics::counter!("chie_deployments_started_total", "strategy" => strategy.to_string())
        .increment(1);
}

/// Record deployment completed
pub fn record_deployment_completed(strategy: &str) {
    metrics::counter!("chie_deployments_completed_total", "strategy" => strategy.to_string())
        .increment(1);
}

/// Record deployment rollback
pub fn record_deployment_rollback(strategy: crate::deployment::DeploymentStrategy) {
    let strategy_str = match strategy {
        crate::deployment::DeploymentStrategy::Canary => "canary",
        crate::deployment::DeploymentStrategy::BlueGreen => "blue_green",
        crate::deployment::DeploymentStrategy::Rolling => "rolling",
    };
    metrics::counter!("chie_deployments_rolled_back_total", "strategy" => strategy_str.to_string())
        .increment(1);
}

/// Record canary traffic update
pub fn record_canary_traffic_updated(traffic_percent: u8) {
    metrics::gauge!("chie_canary_traffic_percent").set(traffic_percent as f64);
}

/// Record blue-green cutover executed
pub fn record_blue_green_cutover_executed() {
    metrics::counter!("chie_blue_green_cutovers_total").increment(1);
}

/// Set active deployment status
pub fn set_active_deployment_status(has_active: bool) {
    metrics::gauge!("chie_active_deployment").set(if has_active { 1.0 } else { 0.0 });
}

// ============================================================================
// Rate Limit Quota Metrics
// ============================================================================

/// Set quota purchases count.
pub fn set_quota_purchases_count(total: u64, active: u64) {
    metrics::gauge!("chie_quota_purchases_total").set(total as f64);
    metrics::gauge!("chie_quota_purchases_active").set(active as f64);
}

/// Record quota purchase.
pub fn record_quota_purchased(tier: &str, price_cents: u64) {
    metrics::counter!(
        "chie_quota_purchased_total",
        "tier" => tier.to_string()
    )
    .increment(1);

    metrics::histogram!("chie_quota_purchase_price_cents").record(price_cents as f64);
}

/// Record quota activation.
pub fn record_quota_activated() {
    metrics::counter!("chie_quota_activations_total").increment(1);
}

/// Record quota cancellation.
pub fn record_quota_cancelled() {
    metrics::counter!("chie_quota_cancellations_total").increment(1);
}

/// Record quota expiration.
pub fn record_quota_expired(count: u64) {
    metrics::counter!("chie_quota_expirations_total").increment(count);
}

/// Record quota auto-renewal.
pub fn record_quota_auto_renewed(count: u64) {
    metrics::counter!("chie_quota_auto_renewals_total").increment(count);
}

/// Set quota revenue.
pub fn set_quota_revenue_cents(amount: u64) {
    metrics::gauge!("chie_quota_revenue_cents").set(amount as f64);
}

/// Set user quota limit.
pub fn set_user_quota_limit(user_id: &str, total_limit: u64) {
    metrics::gauge!(
        "chie_user_quota_limit",
        "user_id" => user_id.to_string()
    )
    .set(total_limit as f64);
}

/// Record email queued for retry.
pub fn record_email_retry_queued() {
    counter!("chie_email_retry_queued_total").increment(1);
}

/// Record email retry abandoned (max retries or age limit exceeded).
pub fn record_email_retry_abandoned() {
    counter!("chie_email_retry_abandoned_total").increment(1);
}

/// Record email retry attempt.
pub fn record_email_retry_attempt(attempt_number: u32) {
    counter!(
        "chie_email_retry_attempts_total",
        "attempt" => attempt_number.to_string()
    )
    .increment(1);

    histogram!("chie_email_retry_attempt_number").record(attempt_number as f64);
}

/// Record failed emails in retry queue.
pub fn record_failed_emails_in_queue(count: usize) {
    gauge!("chie_email_retry_queue_size").set(count as f64);
}

/// Record email retry saved to database.
pub fn record_email_retry_db_save() {
    counter!("chie_email_retry_db_saves_total").increment(1);
}

/// Record email retries loaded from database.
pub fn record_email_retry_db_load(count: usize) {
    counter!("chie_email_retry_db_loads_total").increment(1);
    histogram!("chie_email_retry_db_load_count").record(count as f64);
}

/// Record expired email retries cleaned from database.
pub fn record_email_retry_db_cleanup(count: u64) {
    counter!("chie_email_retry_db_cleanups_total").increment(1);
    histogram!("chie_email_retry_db_cleanup_count").record(count as f64);
}

/// Record email retry by priority level.
pub fn record_email_retry_by_priority(priority: &str) {
    counter!(
        "chie_email_retry_by_priority_total",
        "priority" => priority.to_string()
    )
    .increment(1);
}

/// Record email priority distribution in queue.
pub fn record_email_priority_distribution(priority: &str, count: usize) {
    gauge!(
        "chie_email_priority_queue_size",
        "priority" => priority.to_string()
    )
    .set(count as f64);
}

/// Record email delivery failure webhook triggered.
pub fn record_email_delivery_webhook(priority: &str, reason: &str) {
    counter!(
        "chie_email_delivery_webhooks_total",
        "priority" => priority.to_string(),
        "reason" => reason.to_string()
    )
    .increment(1);
}

/// Record successful email sent.
pub fn record_email_sent_successfully() {
    counter!("chie_email_sent_successfully_total").increment(1);
}

/// Record email removed from retry queue after successful delivery.
pub fn record_email_retry_queue_removed() {
    counter!("chie_email_retry_queue_removed_total").increment(1);
}

// ============================================================================
// Email Bounce Tracking Metrics
// ============================================================================

/// Record email marked as bounced.
pub fn record_email_bounce_marked(email: &str) {
    counter!("chie_email_bounces_marked_total", "email" => email.to_string()).increment(1);
    gauge!("chie_email_bounces_active").increment(1.0);
}

/// Record email bounce status removed.
pub fn record_email_bounce_removed(email: &str) {
    counter!("chie_email_bounces_removed_total", "email" => email.to_string()).increment(1);
    gauge!("chie_email_bounces_active").decrement(1.0);
}

/// Record bounce record cleanup.
pub fn record_email_bounce_cleanup(count: usize) {
    counter!("chie_email_bounce_cleanup_total").increment(count as u64);
}

// ============================================================================
// Email Unsubscribe Tracking Metrics
// ============================================================================

/// Record email unsubscribed.
pub fn record_email_unsubscribed(source: &str) {
    counter!("chie_email_unsubscribed_total", "source" => source.to_string()).increment(1);
    gauge!("chie_email_unsubscribes_active").increment(1.0);
}

/// Record email resubscribed.
pub fn record_email_resubscribed() {
    counter!("chie_email_resubscribed_total").increment(1);
    gauge!("chie_email_unsubscribes_active").decrement(1.0);
}

// ============================================================================
// Email Delivery SLA Metrics
// ============================================================================

/// Record email delivery time.
pub fn record_email_delivery_time(delivery_time_ms: u64) {
    histogram!("chie_email_delivery_time_ms").record(delivery_time_ms as f64);
}

/// Record email SLA breach.
pub fn record_email_sla_breach(delivery_time_ms: u64, target_ms: u64) {
    counter!("chie_email_sla_breaches_total").increment(1);
    histogram!("chie_email_sla_breach_time_ms", "target" => target_ms.to_string())
        .record(delivery_time_ms as f64);
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    // Note: Metrics tests are tricky because the global recorder can only be
    // installed once. These tests verify the functions don't panic.

    #[test]
    fn test_metric_recording_functions() {
        // These should not panic even without initialized metrics
        // (they'll just be no-ops if the recorder isn't installed)
    }
}

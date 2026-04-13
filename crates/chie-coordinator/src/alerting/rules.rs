//! Alert rule management and metric evaluation.

use tracing::info;
use uuid::Uuid;

use super::types::{
    Alert, AlertRule, AlertRuleState, AlertStats, AlertStatus, AlertingManager, ComparisonOperator,
};
use super::utils::current_timestamp;

impl AlertingManager {
    /// Add an alert rule.
    pub async fn add_rule(&self, rule: AlertRule) {
        let mut rules = self.rules.write().await;
        let rule_id = rule.id;
        rules.insert(
            rule_id,
            AlertRuleState {
                rule,
                last_alert_time: None,
                condition_met_since: None,
            },
        );
        info!(rule_id = %rule_id, "Alert rule added");
    }

    /// Remove an alert rule.
    pub async fn remove_rule(&self, rule_id: Uuid) -> bool {
        let mut rules = self.rules.write().await;
        let removed = rules.remove(&rule_id).is_some();
        if removed {
            info!(rule_id = %rule_id, "Alert rule removed");
        }
        removed
    }

    /// Update an alert rule.
    pub async fn update_rule(&self, rule: AlertRule) -> bool {
        let mut rules = self.rules.write().await;
        let rule_id = rule.id;
        if let Some(state) = rules.get_mut(&rule_id) {
            state.rule = rule;
            info!(rule_id = %rule_id, "Alert rule updated");
            true
        } else {
            false
        }
    }

    /// Get all alert rules.
    pub async fn get_rules(&self) -> Vec<AlertRule> {
        let rules = self.rules.read().await;
        rules.values().map(|state| state.rule.clone()).collect()
    }

    /// Get a specific alert rule.
    pub async fn get_rule(&self, rule_id: Uuid) -> Option<AlertRule> {
        let rules = self.rules.read().await;
        rules.get(&rule_id).map(|state| state.rule.clone())
    }

    /// Enable or disable a rule.
    pub async fn set_rule_enabled(&self, rule_id: Uuid, enabled: bool) -> bool {
        let mut rules = self.rules.write().await;
        if let Some(state) = rules.get_mut(&rule_id) {
            state.rule.enabled = enabled;
            info!(rule_id = %rule_id, enabled = enabled, "Alert rule enabled status changed");
            true
        } else {
            false
        }
    }

    /// Check metric value against all enabled rules.
    pub async fn check_metric(&self, metric_name: &str, value: f64) {
        let now = current_timestamp();
        let mut rules = self.rules.write().await;

        for (rule_id, state) in rules.iter_mut() {
            if !state.rule.enabled {
                continue;
            }

            if state.rule.condition.metric_name != metric_name {
                continue;
            }

            let condition_met = state
                .rule
                .condition
                .operator
                .evaluate(value, state.rule.condition.threshold);

            if condition_met {
                // Condition is met
                if state.condition_met_since.is_none() {
                    state.condition_met_since = Some(now);
                }

                // Check if duration threshold is met
                let duration_met = if let Some(since) = state.condition_met_since {
                    now >= since + state.rule.condition.duration_seconds
                } else {
                    false
                };

                if duration_met {
                    // Check cooldown
                    let can_alert = if let Some(last_alert) = state.last_alert_time {
                        now >= last_alert + state.rule.cooldown_seconds
                    } else {
                        true
                    };

                    if can_alert {
                        // Trigger alert
                        let alert = self.create_alert(*rule_id, &state.rule, value).await;
                        state.last_alert_time = Some(now);
                        state.condition_met_since = None; // Reset

                        // Send notifications (without holding the lock)
                        let channels = state.rule.channels.clone();
                        drop(rules); // Release lock before async operations
                        self.send_notifications(&alert, &channels).await;
                        return;
                    }
                }
            } else {
                // Condition no longer met
                state.condition_met_since = None;
            }
        }
    }

    /// Create an alert.
    pub(super) async fn create_alert(
        &self,
        rule_id: Uuid,
        rule: &AlertRule,
        metric_value: f64,
    ) -> Alert {
        let alert = Alert {
            id: Uuid::new_v4(),
            rule_id,
            severity: rule.severity,
            title: rule.name.clone(),
            message: format!(
                "{}: {} {} {} (current: {})",
                rule.description,
                rule.condition.metric_name,
                match rule.condition.operator {
                    ComparisonOperator::GreaterThan => ">",
                    ComparisonOperator::GreaterThanOrEqual => ">=",
                    ComparisonOperator::LessThan => "<",
                    ComparisonOperator::LessThanOrEqual => "<=",
                    ComparisonOperator::Equal => "==",
                    ComparisonOperator::NotEqual => "!=",
                },
                rule.condition.threshold,
                metric_value
            ),
            metric_value,
            created_at: current_timestamp(),
            acknowledged_at: None,
            acknowledged_by: None,
            status: AlertStatus::Active,
        };

        let mut alerts = self.alerts.write().await;
        alerts.insert(alert.id, alert.clone());

        // Limit active alerts
        let max_active_alerts = self.config.read().await.max_active_alerts;
        if alerts.len() > max_active_alerts {
            // Remove oldest resolved/acknowledged alert
            let oldest_resolved = alerts
                .values()
                .filter(|a| a.status != AlertStatus::Active)
                .min_by_key(|a| a.created_at)
                .map(|a| a.id);

            if let Some(id) = oldest_resolved {
                alerts.remove(&id);
            }
        }

        info!(
            alert_id = %alert.id,
            rule_id = %rule_id,
            severity = rule.severity.as_str(),
            "Alert triggered"
        );

        // Record metric
        crate::metrics::record_alert_triggered(rule.severity.as_str(), &rule.name);

        alert
    }

    /// Acknowledge an alert.
    pub async fn acknowledge_alert(&self, alert_id: Uuid, acknowledged_by: String) -> bool {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.get_mut(&alert_id) {
            if alert.status == AlertStatus::Active {
                alert.status = AlertStatus::Acknowledged;
                alert.acknowledged_at = Some(current_timestamp());
                alert.acknowledged_by = Some(acknowledged_by.clone());

                info!(
                    alert_id = %alert_id,
                    acknowledged_by = %acknowledged_by,
                    "Alert acknowledged"
                );

                return true;
            }
        }
        false
    }

    /// Resolve an alert.
    pub async fn resolve_alert(&self, alert_id: Uuid) -> bool {
        let mut alerts = self.alerts.write().await;
        if let Some(alert) = alerts.get_mut(&alert_id) {
            alert.status = AlertStatus::Resolved;
            info!(alert_id = %alert_id, "Alert resolved");

            // Move to history
            let mut history = self.history.write().await;
            history.push(alert.clone());

            // Clean old history
            let history_retention_seconds = self.config.read().await.history_retention_seconds;
            let cutoff = current_timestamp().saturating_sub(history_retention_seconds);
            history.retain(|a| a.created_at >= cutoff);

            return true;
        }
        false
    }

    /// Get all active alerts.
    pub async fn get_active_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        alerts
            .values()
            .filter(|a| a.status == AlertStatus::Active)
            .cloned()
            .collect()
    }

    /// Get all alerts (active and historical).
    pub async fn get_all_alerts(&self) -> Vec<Alert> {
        let alerts = self.alerts.read().await;
        let mut all: Vec<_> = alerts.values().cloned().collect();

        let history = self.history.read().await;
        all.extend(history.iter().cloned());

        all.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        all
    }

    /// Get alert by ID.
    pub async fn get_alert(&self, alert_id: Uuid) -> Option<Alert> {
        let alerts = self.alerts.read().await;
        if let Some(alert) = alerts.get(&alert_id) {
            return Some(alert.clone());
        }

        let history = self.history.read().await;
        history.iter().find(|a| a.id == alert_id).cloned()
    }

    /// Get alerting statistics.
    pub async fn get_stats(&self) -> AlertStats {
        let alerts = self.alerts.read().await;
        let history = self.history.read().await;

        let mut all_alerts: Vec<_> = alerts.values().collect();
        all_alerts.extend(history.iter());

        let total_alerts = all_alerts.len();
        let mut active_alerts = 0usize;
        let mut acknowledged_alerts = 0usize;
        let mut resolved_alerts = 0usize;
        let mut by_severity = std::collections::HashMap::new();
        let mut by_rule = std::collections::HashMap::new();

        let mut total_ack_time = 0u64;
        let mut ack_count = 0usize;

        for alert in &all_alerts {
            match alert.status {
                AlertStatus::Active => active_alerts += 1,
                AlertStatus::Acknowledged => acknowledged_alerts += 1,
                AlertStatus::Resolved => resolved_alerts += 1,
                AlertStatus::Snoozed => {}
            }

            *by_severity
                .entry(alert.severity.as_str().to_string())
                .or_insert(0) += 1;
            *by_rule.entry(alert.rule_id).or_insert(0) += 1;

            if let Some(ack_time) = alert.acknowledged_at {
                total_ack_time += ack_time.saturating_sub(alert.created_at);
                ack_count += 1;
            }
        }

        let avg_time_to_ack = if ack_count > 0 {
            (total_ack_time as f64) / (ack_count as f64)
        } else {
            0.0
        };

        AlertStats {
            total_alerts,
            active_alerts,
            acknowledged_alerts,
            resolved_alerts,
            by_severity,
            by_rule,
            avg_time_to_ack,
        }
    }
}

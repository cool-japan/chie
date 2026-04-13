//! Developer tools: Postman collection, analytics, and API version/changelog.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::Deserialize;

use crate::AppState;

/// Query parameters for content performance.
#[derive(Debug, Deserialize)]
pub(super) struct ContentPerformanceQuery {
    content_id: Option<uuid::Uuid>,
    time_range: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Query parameters for node leaderboard.
#[derive(Debug, Deserialize)]
pub(super) struct NodeLeaderboardQuery {
    time_range: Option<String>,
    sort_by: Option<String>,
    sort_order: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

/// Parse a time range string into a `crate::analytics::TimeRange`.
fn parse_time_range(tr: &str) -> Option<crate::analytics::TimeRange> {
    match tr {
        "hour" => Some(crate::analytics::TimeRange::Hour),
        "day" => Some(crate::analytics::TimeRange::Day),
        "week" => Some(crate::analytics::TimeRange::Week),
        "month" => Some(crate::analytics::TimeRange::Month),
        "year" => Some(crate::analytics::TimeRange::Year),
        _ => None,
    }
}

/// Generate Postman Collection v2.1 JSON.
pub(super) async fn get_postman_collection_handler() -> Json<serde_json::Value> {
    let collection = serde_json::json!({
        "info": {
            "name": "CHIE Coordinator API",
            "description": "CHIE Protocol Coordinator API - Bandwidth proof verification and reward distribution",
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            "version": "0.1.0"
        },
        "variable": [
            {
                "key": "base_url",
                "value": "http://localhost:8080/api",
                "type": "string"
            },
            {
                "key": "auth_token",
                "value": "",
                "type": "string"
            }
        ],
        "auth": {
            "type": "bearer",
            "bearer": [
                {
                    "key": "token",
                    "value": "{{auth_token}}",
                    "type": "string"
                }
            ]
        },
        "item": [
            {
                "name": "Authentication",
                "item": [
                    {
                        "name": "Generate Token",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/auth/token",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"email\": \"user@example.com\", \"password\": \"password123\"}"
                            }
                        }
                    }
                ]
            },
            {
                "name": "Users",
                "item": [
                    {
                        "name": "Register User",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/users",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"email\": \"user@example.com\", \"username\": \"testuser\", \"password\": \"SecurePass123!\"}"
                            }
                        }
                    },
                    {
                        "name": "Get Current User",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/me"
                        }
                    },
                    {
                        "name": "Get User Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/me/stats"
                        }
                    }
                ]
            },
            {
                "name": "Nodes",
                "item": [
                    {
                        "name": "Register Node",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/nodes",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"peer_id\": \"12D3KooWABC123\", \"public_key\": \"abcdef1234567890\", \"bandwidth_capacity\": 1000000000}"
                            }
                        }
                    },
                    {
                        "name": "Get Node Info",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/nodes/:peer_id"
                        }
                    },
                    {
                        "name": "Get Node Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/nodes/:peer_id/stats"
                        }
                    }
                ]
            },
            {
                "name": "Content",
                "item": [
                    {
                        "name": "List Content",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": {
                                "raw": "{{base_url}}/content?category=video&page=1&limit=20",
                                "host": ["{{base_url}}"],
                                "path": ["content"],
                                "query": [
                                    {"key": "category", "value": "video"},
                                    {"key": "page", "value": "1"},
                                    {"key": "limit", "value": "20"}
                                ]
                            }
                        }
                    },
                    {
                        "name": "Get Content Details",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/content/:id"
                        }
                    },
                    {
                        "name": "Register Content",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/content/register",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"title\": \"My Video\", \"content_id\": \"QmABC123\", \"size\": 1000000, \"category\": \"video\"}"
                            }
                        }
                    },
                    {
                        "name": "Get Content Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/content/:id/stats"
                        }
                    },
                    {
                        "name": "Get Content Seeders",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/content/:id/seeders"
                        }
                    },
                    {
                        "name": "Get Trending Content",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/trending"
                        }
                    },
                    {
                        "name": "Get Content Popularity",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/content/:id/popularity"
                        }
                    }
                ]
            },
            {
                "name": "Bandwidth Proofs",
                "item": [
                    {
                        "name": "Submit Proof",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/proofs",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"requester_id\": \"12D3KooWREQ\", \"provider_id\": \"12D3KooWPROV\", \"content_id\": \"QmABC123\", \"bytes_transferred\": 1048576, \"timestamp\": 1234567890, \"nonce\": \"abc123\", \"requester_signature\": \"sig1\", \"provider_signature\": \"sig2\"}"
                            }
                        }
                    }
                ]
            },
            {
                "name": "Statistics",
                "item": [
                    {
                        "name": "Platform Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/stats/platform"
                        }
                    }
                ]
            },
            {
                "name": "Transactions",
                "item": [
                    {
                        "name": "Get User Transactions",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/transactions"
                        }
                    }
                ]
            },
            {
                "name": "Recommendations",
                "item": [
                    {
                        "name": "Get Content Recommendations",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/recommendations"
                        }
                    }
                ]
            },
            {
                "name": "Rate Limit Quotas",
                "item": [
                    {
                        "name": "Get Quota Tiers",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/quotas/tiers"
                        }
                    },
                    {
                        "name": "Purchase Quota",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/quotas/purchase",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"tier_id\": \"premium\", \"duration_days\": 30}"
                            }
                        }
                    },
                    {
                        "name": "Get My Quotas",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/quotas/my"
                        }
                    },
                    {
                        "name": "Get My Quota History",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/quotas/my/history"
                        }
                    }
                ]
            },
            {
                "name": "Webhooks",
                "item": [
                    {
                        "name": "Register Webhook",
                        "request": {
                            "method": "POST",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/webhooks",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"url\": \"https://example.com/webhook\", \"events\": [\"fraud_detected\", \"node_suspended\"], \"secret\": \"webhook_secret\", \"max_retries\": 3}"
                            }
                        }
                    },
                    {
                        "name": "List Webhooks",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/webhooks"
                        }
                    },
                    {
                        "name": "Get Webhook",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/webhooks/:id"
                        }
                    },
                    {
                        "name": "Update Webhook",
                        "request": {
                            "method": "PUT",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/webhooks/:id",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"url\": \"https://example.com/webhook\", \"events\": [\"fraud_detected\"], \"active\": true}"
                            }
                        }
                    },
                    {
                        "name": "Delete Webhook",
                        "request": {
                            "method": "DELETE",
                            "header": [],
                            "url": "{{base_url}}/webhooks/:id"
                        }
                    },
                    {
                        "name": "Get Webhook Deliveries",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": {
                                "raw": "{{base_url}}/webhooks/:id/deliveries?limit=50&failed_only=false",
                                "host": ["{{base_url}}"],
                                "path": ["webhooks", ":id", "deliveries"],
                                "query": [
                                    {"key": "limit", "value": "50"},
                                    {"key": "failed_only", "value": "false"}
                                ]
                            }
                        }
                    },
                    {
                        "name": "Retry Webhook Delivery",
                        "request": {
                            "method": "POST",
                            "header": [],
                            "url": "{{base_url}}/webhooks/:id/retry/:delivery_id"
                        }
                    },
                    {
                        "name": "Get Webhook Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/webhooks/stats"
                        }
                    },
                    {
                        "name": "Get Webhook Config",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/webhooks/config"
                        }
                    },
                    {
                        "name": "Update Webhook Config",
                        "request": {
                            "method": "PUT",
                            "header": [{"key": "Content-Type", "value": "application/json"}],
                            "url": "{{base_url}}/webhooks/config",
                            "body": {
                                "mode": "raw",
                                "raw": "{\"max_concurrent\": 100, \"default_timeout_ms\": 5000, \"default_max_retries\": 3}"
                            }
                        }
                    }
                ]
            },
            {
                "name": "Email Delivery",
                "item": [
                    {
                        "name": "Get Email Stats",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/stats"
                        }
                    },
                    {
                        "name": "Get Failed Emails",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/failed"
                        }
                    },
                    {
                        "name": "Get Bounced Emails",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/bounced"
                        }
                    },
                    {
                        "name": "Get Unsubscribed Emails",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/unsubscribed"
                        }
                    },
                    {
                        "name": "Get Email SLA Metrics",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/emails/sla"
                        }
                    },
                    {
                        "name": "Remove Failed Email",
                        "request": {
                            "method": "DELETE",
                            "header": [],
                            "url": "{{base_url}}/emails/failed/:id"
                        }
                    },
                    {
                        "name": "Remove Bounce",
                        "request": {
                            "method": "DELETE",
                            "header": [],
                            "url": "{{base_url}}/emails/bounced/:email"
                        }
                    },
                    {
                        "name": "Resubscribe Email",
                        "request": {
                            "method": "DELETE",
                            "header": [],
                            "url": "{{base_url}}/emails/unsubscribed/:email"
                        }
                    }
                ]
            },
            {
                "name": "SDK",
                "item": [
                    {
                        "name": "Generate SDK",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/sdk/generate/:language"
                        }
                    },
                    {
                        "name": "List SDK Languages",
                        "request": {
                            "method": "GET",
                            "header": [],
                            "url": "{{base_url}}/sdk/list"
                        }
                    }
                ]
            }
        ]
    });

    Json(collection)
}

// ==================== Analytics Dashboard Endpoints ====================

/// Get dashboard metrics summary.
pub(super) async fn get_analytics_dashboard_handler(
    State(state): State<AppState>,
) -> Result<Json<crate::analytics::DashboardMetrics>, (StatusCode, String)> {
    match state.analytics_manager.get_dashboard_metrics().await {
        Ok(metrics) => Ok(Json(metrics)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get dashboard metrics: {}", e),
        )),
    }
}

/// Get content performance analytics.
pub(super) async fn get_content_performance_handler(
    State(state): State<AppState>,
    Query(query): Query<ContentPerformanceQuery>,
) -> Result<Json<Vec<crate::analytics::ContentPerformance>>, (StatusCode, String)> {
    let time_range = query
        .time_range
        .as_deref()
        .and_then(parse_time_range)
        .unwrap_or(crate::analytics::TimeRange::Day);

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    match state
        .analytics_manager
        .get_content_performance(query.content_id, time_range, limit, offset)
        .await
    {
        Ok(performance) => Ok(Json(performance)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get content performance: {}", e),
        )),
    }
}

/// Get node performance leaderboard.
pub(super) async fn get_node_leaderboard_handler(
    State(state): State<AppState>,
    Query(query): Query<NodeLeaderboardQuery>,
) -> Result<Json<Vec<crate::analytics::NodePerformance>>, (StatusCode, String)> {
    let time_range = query
        .time_range
        .as_deref()
        .and_then(parse_time_range)
        .unwrap_or(crate::analytics::TimeRange::Day);

    // Parse sort order
    let sort_order = query
        .sort_order
        .and_then(|so| match so.as_str() {
            "asc" => Some(crate::analytics::SortOrder::Asc),
            "desc" => Some(crate::analytics::SortOrder::Desc),
            _ => None,
        })
        .unwrap_or(crate::analytics::SortOrder::Desc);

    let sort_by = query.sort_by.as_deref().unwrap_or("points_earned");
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);

    match state
        .analytics_manager
        .get_node_leaderboard(time_range, sort_by, sort_order, limit, offset)
        .await
    {
        Ok(leaderboard) => Ok(Json(leaderboard)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to get node leaderboard: {}", e),
        )),
    }
}

/// Execute a custom analytics query.
pub(super) async fn execute_custom_analytics_query_handler(
    State(state): State<AppState>,
    Json(query): Json<crate::analytics::AnalyticsQuery>,
) -> Result<Json<crate::analytics::AnalyticsResult>, (StatusCode, String)> {
    match state.analytics_manager.execute_custom_query(query).await {
        Ok(result) => Ok(Json(result)),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to execute custom query: {}", e),
        )),
    }
}

/// Get analytics configuration.
pub(super) async fn get_analytics_config_handler(
    State(state): State<AppState>,
) -> Json<crate::analytics::AnalyticsConfig> {
    let config = state.analytics_manager.config().await;
    Json(config)
}

/// Update analytics configuration.
pub(super) async fn update_analytics_config_handler(
    State(state): State<AppState>,
    Json(config): Json<crate::analytics::AnalyticsConfig>,
) -> Result<StatusCode, (StatusCode, String)> {
    match state.analytics_manager.update_config(config).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update analytics config: {}", e),
        )),
    }
}

// ==================== API Version & Changelog Endpoints ====================

/// Get current API version information.
pub(super) async fn get_api_version_handler() -> Json<crate::api_changelog::ApiVersion> {
    let version = crate::api_changelog::get_current_version();
    Json(version)
}

/// Get all API versions.
pub(super) async fn get_all_versions_handler() -> Json<Vec<crate::api_changelog::ApiVersion>> {
    let versions = crate::api_changelog::get_all_versions();
    Json(versions)
}

/// Get complete API changelog.
pub(super) async fn get_changelog_handler() -> Json<crate::api_changelog::ApiChangelog> {
    let changelog = crate::api_changelog::get_changelog();
    Json(changelog)
}

/// Get changelog for a specific version.
pub(super) async fn get_version_changelog_handler(
    Path(version): Path<String>,
) -> Json<Vec<crate::api_changelog::ChangelogEntry>> {
    let entries = crate::api_changelog::get_version_changelog(&version);
    Json(entries)
}

/// Get changelog by category.
pub(super) async fn get_category_changelog_handler(
    Path(category): Path<String>,
) -> Json<Vec<crate::api_changelog::ChangelogEntry>> {
    let entries = crate::api_changelog::get_changelog_by_category(&category);
    Json(entries)
}

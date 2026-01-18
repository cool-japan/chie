//! API versioning and changelog management.
//!
//! This module provides version information and changelog for the API,
//! helping developers track changes and compatibility.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// API version information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiVersion {
    /// Version string (e.g., "0.1.0").
    pub version: String,
    /// Release date.
    pub release_date: DateTime<Utc>,
    /// API status (stable, beta, deprecated).
    pub status: ApiStatus,
    /// Minimum supported client version.
    pub min_client_version: String,
    /// Whether this is the current version.
    pub is_current: bool,
    /// Deprecation date if applicable.
    pub deprecated_at: Option<DateTime<Utc>>,
    /// Sunset date if applicable.
    pub sunset_at: Option<DateTime<Utc>>,
}

/// API version status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ApiStatus {
    /// Stable production version.
    Stable,
    /// Beta version with potential breaking changes.
    Beta,
    /// Alpha version for testing.
    Alpha,
    /// Deprecated version, still functional.
    Deprecated,
    /// Sunset version, no longer supported.
    Sunset,
}

/// Type of change in the API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeType {
    /// New feature added.
    Feature,
    /// Enhancement to existing feature.
    Enhancement,
    /// Bug fix.
    Bugfix,
    /// Breaking change.
    Breaking,
    /// Deprecation notice.
    Deprecation,
    /// Security fix.
    Security,
    /// Performance improvement.
    Performance,
    /// Documentation update.
    Documentation,
}

/// A single changelog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangelogEntry {
    /// Version this change was introduced in.
    pub version: String,
    /// Date of the change.
    pub date: DateTime<Utc>,
    /// Type of change.
    pub change_type: ChangeType,
    /// Category (e.g., "Authentication", "Webhooks").
    pub category: String,
    /// Description of the change.
    pub description: String,
    /// Related endpoint or feature.
    pub endpoint: Option<String>,
    /// Link to documentation or PR.
    pub documentation_url: Option<String>,
    /// Migration guide if applicable.
    pub migration_guide: Option<String>,
}

/// Complete API changelog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiChangelog {
    /// Current API version.
    pub current_version: String,
    /// All available versions.
    pub versions: Vec<ApiVersion>,
    /// Changelog entries.
    pub changelog: Vec<ChangelogEntry>,
}

/// Get current API version information.
pub fn get_current_version() -> ApiVersion {
    ApiVersion {
        version: "0.1.0".to_string(),
        release_date: Utc::now(),
        status: ApiStatus::Beta,
        min_client_version: "0.1.0".to_string(),
        is_current: true,
        deprecated_at: None,
        sunset_at: None,
    }
}

/// Get all API versions.
pub fn get_all_versions() -> Vec<ApiVersion> {
    vec![ApiVersion {
        version: "0.1.0".to_string(),
        release_date: chrono::DateTime::parse_from_rfc3339("2026-01-08T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        status: ApiStatus::Beta,
        min_client_version: "0.1.0".to_string(),
        is_current: true,
        deprecated_at: None,
        sunset_at: None,
    }]
}

/// Get complete API changelog.
pub fn get_changelog() -> ApiChangelog {
    ApiChangelog {
        current_version: "0.1.0".to_string(),
        versions: get_all_versions(),
        changelog: vec![
            // Version 0.1.0 - Initial Beta Release (2026-01-08)
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-08T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Webhooks".to_string(),
                description: "Added comprehensive webhook management API with CRUD operations, delivery history, and retry functionality.".to_string(),
                endpoint: Some("/api/webhooks".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-08T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Email".to_string(),
                description: "Added email delivery statistics API for monitoring failed, bounced, and unsubscribed emails.".to_string(),
                endpoint: Some("/api/emails/stats".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-08T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Analytics".to_string(),
                description: "Added analytics dashboard API with content performance, node leaderboards, and custom query execution.".to_string(),
                endpoint: Some("/api/analytics/dashboard".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-08T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Developer Tools".to_string(),
                description: "Added Postman collection export endpoint for easy API testing and integration.".to_string(),
                endpoint: Some("/api/postman/collection".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-08T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Rate Limiting".to_string(),
                description: "Implemented rate limit quota purchase API with tiered pricing and quota management.".to_string(),
                endpoint: Some("/api/quotas/purchase".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-04T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Compliance".to_string(),
                description: "Added GDPR compliance endpoints for data export and right to be forgotten.".to_string(),
                endpoint: Some("/admin/gdpr/export".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-04T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Legal".to_string(),
                description: "Implemented Terms of Service version tracking and acceptance management.".to_string(),
                endpoint: Some("/admin/tos/versions".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-04T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Content".to_string(),
                description: "Added jurisdiction-aware content filtering for geographic restrictions.".to_string(),
                endpoint: Some("/admin/restrictions".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-29T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Payments".to_string(),
                description: "Implemented payment ledger and settlement processing system.".to_string(),
                endpoint: Some("/admin/payments".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-29T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Multi-Tenancy".to_string(),
                description: "Added multi-tenant support with tenant isolation and API versioning.".to_string(),
                endpoint: Some("/admin/tenants".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-18T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Authentication".to_string(),
                description: "Implemented JWT-based authentication with token generation and validation.".to_string(),
                endpoint: Some("/api/auth/token".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-18T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Feature,
                category: "Proofs".to_string(),
                description: "Core bandwidth proof verification system with dual-signature validation.".to_string(),
                endpoint: Some("/api/proofs".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-18T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Security,
                category: "Authentication".to_string(),
                description: "Added brute force protection for authentication endpoints.".to_string(),
                endpoint: Some("/api/auth/token".to_string()),
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
            ChangelogEntry {
                version: "0.1.0".to_string(),
                date: chrono::DateTime::parse_from_rfc3339("2026-01-18T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                change_type: ChangeType::Performance,
                category: "Caching".to_string(),
                description: "Implemented Redis-based distributed caching for improved performance.".to_string(),
                endpoint: None,
                documentation_url: Some("/swagger-ui".to_string()),
                migration_guide: None,
            },
        ],
    }
}

/// Get changelog for a specific version.
pub fn get_version_changelog(version: &str) -> Vec<ChangelogEntry> {
    let changelog = get_changelog();
    changelog
        .changelog
        .into_iter()
        .filter(|entry| entry.version == version)
        .collect()
}

/// Get changelog entries by category.
pub fn get_changelog_by_category(category: &str) -> Vec<ChangelogEntry> {
    let changelog = get_changelog();
    changelog
        .changelog
        .into_iter()
        .filter(|entry| entry.category.eq_ignore_ascii_case(category))
        .collect()
}

/// Get changelog entries by change type.
#[allow(dead_code)]
pub fn get_changelog_by_type(change_type: ChangeType) -> Vec<ChangelogEntry> {
    let changelog = get_changelog();
    changelog
        .changelog
        .into_iter()
        .filter(|entry| entry.change_type == change_type)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_version() {
        let version = get_current_version();
        assert_eq!(version.version, "0.1.0");
        assert!(version.is_current);
        assert_eq!(version.status, ApiStatus::Beta);
    }

    #[test]
    fn test_get_all_versions() {
        let versions = get_all_versions();
        assert!(!versions.is_empty());
        assert!(versions.iter().any(|v| v.is_current));
    }

    #[test]
    fn test_get_changelog() {
        let changelog = get_changelog();
        assert_eq!(changelog.current_version, "0.1.0");
        assert!(!changelog.changelog.is_empty());
        assert!(!changelog.versions.is_empty());
    }

    #[test]
    fn test_get_version_changelog() {
        let entries = get_version_changelog("0.1.0");
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e.version == "0.1.0"));
    }

    #[test]
    fn test_get_changelog_by_category() {
        let entries = get_changelog_by_category("Webhooks");
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e.category == "Webhooks"));
    }

    #[test]
    fn test_get_changelog_by_type() {
        let entries = get_changelog_by_type(ChangeType::Feature);
        assert!(!entries.is_empty());
        assert!(entries.iter().all(|e| e.change_type == ChangeType::Feature));
    }
}

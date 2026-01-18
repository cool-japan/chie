//! JSON Schema generation for CHIE Protocol types.
//!
//! This module is only available with the `schema` feature.

#[cfg(feature = "schema")]
use schemars::{JsonSchema, schema_for};

#[cfg(feature = "schema")]
use crate::{
    BandwidthMetrics,
    BandwidthProof,
    BandwidthQuota,
    BandwidthStats,
    BatchContentAnnouncement,
    BatchProofResponse,
    // Batch types
    BatchProofSubmission,
    BatchStatsUpdate,
    // Cache and profiling types
    CacheStats,
    ChunkRequest,
    ChunkResponse,
    ContentCategory,
    ContentInvestment,
    ContentMetadata,
    ContentStats,
    ContentStatus,
    DemandLevel,
    LatencyStats,
    LeaderboardEntry,
    NetworkHealth,
    NodeStats,
    NodeStatus,
    OperationStats,
    PlatformStats,
    ProofResult,
    RateLimitQuota,
    ResourceMetrics,
    RewardDistribution,
    SizedCacheStats,
    // Quota types
    StorageQuota,
    ThroughputMetrics,
    TieredCacheStats,
    TimeSeriesMetric,
    User,
    UserQuota,
    UserRole,
};

/// Generate JSON schema for a type.
#[cfg(feature = "schema")]
#[must_use]
pub fn schema_for_type<T: JsonSchema>() -> schemars::schema::RootSchema {
    schema_for!(T)
}

/// Generate JSON schema as a string.
///
/// # Errors
///
/// Returns error if JSON serialization fails
#[cfg(feature = "schema")]
pub fn schema_json<T: JsonSchema>() -> Result<String, serde_json::Error> {
    let schema = schema_for!(T);
    serde_json::to_string_pretty(&schema)
}

/// Schema definitions for all protocol types.
#[cfg(feature = "schema")]
pub struct SchemaDefinitions;

#[cfg(feature = "schema")]
impl SchemaDefinitions {
    /// Generate schema for ContentMetadata.
    #[must_use]
    pub fn content_metadata() -> schemars::schema::RootSchema {
        schema_for!(ContentMetadata)
    }

    /// Generate schema for BandwidthProof.
    #[must_use]
    pub fn bandwidth_proof() -> schemars::schema::RootSchema {
        schema_for!(BandwidthProof)
    }

    /// Generate schema for ChunkRequest.
    #[must_use]
    pub fn chunk_request() -> schemars::schema::RootSchema {
        schema_for!(ChunkRequest)
    }

    /// Generate schema for ChunkResponse.
    #[must_use]
    pub fn chunk_response() -> schemars::schema::RootSchema {
        schema_for!(ChunkResponse)
    }

    /// Generate schema for User.
    #[must_use]
    pub fn user() -> schemars::schema::RootSchema {
        schema_for!(User)
    }

    /// Generate schema for NodeStats.
    #[must_use]
    pub fn node_stats() -> schemars::schema::RootSchema {
        schema_for!(NodeStats)
    }

    /// Generate schema for RewardDistribution.
    #[must_use]
    pub fn reward_distribution() -> schemars::schema::RootSchema {
        schema_for!(RewardDistribution)
    }

    /// Generate schema for LeaderboardEntry.
    #[must_use]
    pub fn leaderboard_entry() -> schemars::schema::RootSchema {
        schema_for!(LeaderboardEntry)
    }

    /// Generate schema for ContentInvestment.
    #[must_use]
    pub fn content_investment() -> schemars::schema::RootSchema {
        schema_for!(ContentInvestment)
    }

    /// Generate schema for BandwidthStats.
    #[must_use]
    pub fn bandwidth_stats() -> schemars::schema::RootSchema {
        schema_for!(BandwidthStats)
    }

    /// Generate schema for ContentStats.
    #[must_use]
    pub fn content_stats() -> schemars::schema::RootSchema {
        schema_for!(ContentStats)
    }

    /// Generate schema for PlatformStats.
    #[must_use]
    pub fn platform_stats() -> schemars::schema::RootSchema {
        schema_for!(PlatformStats)
    }

    /// Generate schema for NetworkHealth.
    #[must_use]
    pub fn network_health() -> schemars::schema::RootSchema {
        schema_for!(NetworkHealth)
    }

    /// Generate schema for TimeSeriesMetric.
    #[must_use]
    pub fn time_series_metric() -> schemars::schema::RootSchema {
        schema_for!(TimeSeriesMetric)
    }

    // Quota types
    /// Generate schema for StorageQuota.
    #[must_use]
    pub fn storage_quota() -> schemars::schema::RootSchema {
        schema_for!(StorageQuota)
    }

    /// Generate schema for BandwidthQuota.
    #[must_use]
    pub fn bandwidth_quota() -> schemars::schema::RootSchema {
        schema_for!(BandwidthQuota)
    }

    /// Generate schema for RateLimitQuota.
    #[must_use]
    pub fn rate_limit_quota() -> schemars::schema::RootSchema {
        schema_for!(RateLimitQuota)
    }

    /// Generate schema for UserQuota.
    #[must_use]
    pub fn user_quota() -> schemars::schema::RootSchema {
        schema_for!(UserQuota)
    }

    // Batch types
    /// Generate schema for BatchProofSubmission.
    #[must_use]
    pub fn batch_proof_submission() -> schemars::schema::RootSchema {
        schema_for!(BatchProofSubmission)
    }

    /// Generate schema for BatchProofResponse.
    #[must_use]
    pub fn batch_proof_response() -> schemars::schema::RootSchema {
        schema_for!(BatchProofResponse)
    }

    /// Generate schema for ProofResult.
    #[must_use]
    pub fn proof_result() -> schemars::schema::RootSchema {
        schema_for!(ProofResult)
    }

    /// Generate schema for BatchContentAnnouncement.
    #[must_use]
    pub fn batch_content_announcement() -> schemars::schema::RootSchema {
        schema_for!(BatchContentAnnouncement)
    }

    /// Generate schema for BatchStatsUpdate.
    #[must_use]
    pub fn batch_stats_update() -> schemars::schema::RootSchema {
        schema_for!(BatchStatsUpdate)
    }

    // Cache types
    /// Generate schema for CacheStats.
    #[must_use]
    pub fn cache_stats() -> schemars::schema::RootSchema {
        schema_for!(CacheStats)
    }

    /// Generate schema for TieredCacheStats.
    #[must_use]
    pub fn tiered_cache_stats() -> schemars::schema::RootSchema {
        schema_for!(TieredCacheStats)
    }

    /// Generate schema for SizedCacheStats.
    #[must_use]
    pub fn sized_cache_stats() -> schemars::schema::RootSchema {
        schema_for!(SizedCacheStats)
    }

    // Profiling types
    /// Generate schema for OperationStats.
    #[must_use]
    pub fn operation_stats() -> schemars::schema::RootSchema {
        schema_for!(OperationStats)
    }

    /// Generate schema for BandwidthMetrics.
    #[must_use]
    pub fn bandwidth_metrics() -> schemars::schema::RootSchema {
        schema_for!(BandwidthMetrics)
    }

    /// Generate schema for LatencyStats.
    #[must_use]
    pub fn latency_stats() -> schemars::schema::RootSchema {
        schema_for!(LatencyStats)
    }

    /// Generate schema for ThroughputMetrics.
    #[must_use]
    pub fn throughput_metrics() -> schemars::schema::RootSchema {
        schema_for!(ThroughputMetrics)
    }

    /// Generate schema for ResourceMetrics.
    #[must_use]
    pub fn resource_metrics() -> schemars::schema::RootSchema {
        schema_for!(ResourceMetrics)
    }

    /// Generate all schemas as a map.
    #[must_use]
    pub fn all() -> std::collections::HashMap<&'static str, schemars::schema::RootSchema> {
        let mut schemas = std::collections::HashMap::new();

        // Core protocol types
        schemas.insert("ContentMetadata", Self::content_metadata());
        schemas.insert("BandwidthProof", Self::bandwidth_proof());
        schemas.insert("ChunkRequest", Self::chunk_request());
        schemas.insert("ChunkResponse", Self::chunk_response());
        schemas.insert("User", Self::user());
        schemas.insert("NodeStats", Self::node_stats());
        schemas.insert("RewardDistribution", Self::reward_distribution());
        schemas.insert("LeaderboardEntry", Self::leaderboard_entry());
        schemas.insert("ContentInvestment", Self::content_investment());

        // Statistics types
        schemas.insert("BandwidthStats", Self::bandwidth_stats());
        schemas.insert("ContentStats", Self::content_stats());
        schemas.insert("PlatformStats", Self::platform_stats());
        schemas.insert("NetworkHealth", Self::network_health());
        schemas.insert("TimeSeriesMetric", Self::time_series_metric());

        // Quota types
        schemas.insert("StorageQuota", Self::storage_quota());
        schemas.insert("BandwidthQuota", Self::bandwidth_quota());
        schemas.insert("RateLimitQuota", Self::rate_limit_quota());
        schemas.insert("UserQuota", Self::user_quota());

        // Batch types
        schemas.insert("BatchProofSubmission", Self::batch_proof_submission());
        schemas.insert("BatchProofResponse", Self::batch_proof_response());
        schemas.insert("ProofResult", Self::proof_result());
        schemas.insert(
            "BatchContentAnnouncement",
            Self::batch_content_announcement(),
        );
        schemas.insert("BatchStatsUpdate", Self::batch_stats_update());

        // Cache types
        schemas.insert("CacheStats", Self::cache_stats());
        schemas.insert("TieredCacheStats", Self::tiered_cache_stats());
        schemas.insert("SizedCacheStats", Self::sized_cache_stats());

        // Profiling types
        schemas.insert("OperationStats", Self::operation_stats());
        schemas.insert("BandwidthMetrics", Self::bandwidth_metrics());
        schemas.insert("LatencyStats", Self::latency_stats());
        schemas.insert("ThroughputMetrics", Self::throughput_metrics());
        schemas.insert("ResourceMetrics", Self::resource_metrics());

        // Enum types
        schemas.insert("ContentCategory", schema_for!(ContentCategory));
        schemas.insert("ContentStatus", schema_for!(ContentStatus));
        schemas.insert("NodeStatus", schema_for!(NodeStatus));
        schemas.insert("UserRole", schema_for!(UserRole));
        schemas.insert("DemandLevel", schema_for!(DemandLevel));

        schemas
    }

    /// Write all schemas to a directory.
    ///
    /// # Errors
    ///
    /// Returns error if directory creation, file write, or JSON serialization fails
    pub fn write_to_directory(
        dir: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        std::fs::create_dir_all(dir)?;
        for (name, schema) in Self::all() {
            let path = dir.join(format!("{name}.json"));
            let json = serde_json::to_string_pretty(&schema)?;
            std::fs::write(path, json)?;
        }
        Ok(())
    }
}

/// OpenAPI 3.0 specification builder for CHIE Protocol.
#[cfg(feature = "schema")]
pub struct OpenApiSpec {
    title: String,
    version: String,
    description: String,
}

#[cfg(feature = "schema")]
impl Default for OpenApiSpec {
    fn default() -> Self {
        Self {
            title: "CHIE Protocol API".to_string(),
            version: "0.1.0".to_string(),
            description:
                "API specification for the CHIE (Collective Hybrid Intelligence Ecosystem) Protocol"
                    .to_string(),
        }
    }
}

#[cfg(feature = "schema")]
impl OpenApiSpec {
    /// Create a new OpenAPI spec builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the API title.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Set the API version.
    #[must_use]
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Set the API description.
    #[must_use]
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Build the OpenAPI 3.0 specification.
    #[must_use]
    pub fn build(&self) -> serde_json::Value {
        let mut spec = serde_json::json!({
            "openapi": "3.0.3",
            "info": {
                "title": self.title,
                "version": self.version,
                "description": self.description,
                "license": {
                    "name": "MIT OR Apache-2.0"
                }
            },
            "servers": [
                {
                    "url": "https://api.chie.network",
                    "description": "Production server"
                },
                {
                    "url": "http://localhost:8080",
                    "description": "Local development server"
                }
            ],
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    }
                }
            }
        });

        // Add all schema definitions
        let schemas = SchemaDefinitions::all();
        for (name, schema) in schemas {
            if let Some(components) = spec.get_mut("components") {
                if let Some(schemas_obj) = components.get_mut("schemas") {
                    schemas_obj[name] =
                        serde_json::to_value(&schema).unwrap_or(serde_json::Value::Null);
                }
            }
        }

        // Add common API paths
        self.add_api_paths(&mut spec);

        spec
    }

    /// Add API paths to the OpenAPI spec.
    fn add_api_paths(&self, spec: &mut serde_json::Value) {
        let paths = serde_json::json!({
            "/content": {
                "get": {
                    "summary": "List content",
                    "description": "Retrieve a paginated list of content items",
                    "tags": ["Content"],
                    "parameters": [
                        {
                            "name": "category",
                            "in": "query",
                            "schema": {
                                "$ref": "#/components/schemas/ContentCategory"
                            }
                        },
                        {
                            "name": "offset",
                            "in": "query",
                            "schema": {
                                "type": "integer",
                                "minimum": 0
                            }
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "$ref": "#/components/schemas/ContentMetadata"
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "post": {
                    "summary": "Create content",
                    "description": "Upload new content to the network",
                    "tags": ["Content"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/ContentMetadata"
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Content created",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/ContentMetadata"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/content/{cid}": {
                "get": {
                    "summary": "Get content by CID",
                    "description": "Retrieve content metadata by its Content Identifier",
                    "tags": ["Content"],
                    "parameters": [
                        {
                            "name": "cid",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string"
                            },
                            "description": "Content Identifier (CID)"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/ContentMetadata"
                                    }
                                }
                            }
                        },
                        "404": {
                            "description": "Content not found"
                        }
                    }
                }
            },
            "/bandwidth/proof": {
                "post": {
                    "summary": "Submit bandwidth proof",
                    "description": "Submit proof of bandwidth transfer for reward distribution",
                    "tags": ["Bandwidth"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/BandwidthProof"
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Proof submitted successfully"
                        },
                        "400": {
                            "description": "Invalid proof"
                        }
                    }
                }
            },
            "/stats/bandwidth": {
                "get": {
                    "summary": "Get bandwidth statistics",
                    "description": "Retrieve network-wide bandwidth statistics",
                    "tags": ["Statistics"],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/BandwidthStats"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/stats/platform": {
                "get": {
                    "summary": "Get platform statistics",
                    "description": "Retrieve overall platform statistics",
                    "tags": ["Statistics"],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/PlatformStats"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/health": {
                "get": {
                    "summary": "Health check",
                    "description": "Check network health status",
                    "tags": ["System"],
                    "responses": {
                        "200": {
                            "description": "Service is healthy",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/NetworkHealth"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users/{id}": {
                "get": {
                    "summary": "Get user profile",
                    "description": "Retrieve user profile information",
                    "tags": ["Users"],
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "format": "uuid"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/User"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/leaderboard": {
                "get": {
                    "summary": "Get leaderboard",
                    "description": "Retrieve top contributors leaderboard",
                    "tags": ["Leaderboard"],
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {
                                "type": "integer",
                                "minimum": 1,
                                "maximum": 100,
                                "default": 10
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {
                                            "$ref": "#/components/schemas/LeaderboardEntry"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/users/{id}/quota": {
                "get": {
                    "summary": "Get user quota",
                    "description": "Retrieve quota information for a user",
                    "tags": ["Quota"],
                    "security": [{"bearerAuth": []}],
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": true,
                            "schema": {
                                "type": "string",
                                "format": "uuid"
                            }
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/UserQuota"
                                    }
                                }
                            }
                        },
                        "401": {
                            "description": "Unauthorized"
                        },
                        "404": {
                            "description": "User not found"
                        }
                    }
                }
            },
            "/bandwidth/proof/batch": {
                "post": {
                    "summary": "Submit batch proofs",
                    "description": "Submit multiple bandwidth proofs in a single request for efficient processing",
                    "tags": ["Bandwidth"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/BatchProofSubmission"
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Batch processed successfully",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/BatchProofResponse"
                                    }
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid batch submission"
                        },
                        "401": {
                            "description": "Unauthorized"
                        }
                    }
                }
            },
            "/content/batch/announce": {
                "post": {
                    "summary": "Batch content announcement",
                    "description": "Announce multiple content items to the network in a single request",
                    "tags": ["Content"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/BatchContentAnnouncement"
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Announcements processed successfully"
                        },
                        "400": {
                            "description": "Invalid batch announcement"
                        },
                        "401": {
                            "description": "Unauthorized"
                        }
                    }
                }
            },
            "/stats/batch": {
                "post": {
                    "summary": "Batch statistics update",
                    "description": "Submit multiple statistics updates in a single request",
                    "tags": ["Statistics"],
                    "security": [{"bearerAuth": []}],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/BatchStatsUpdate"
                                }
                            }
                        }
                    },
                    "responses": {
                        "201": {
                            "description": "Statistics updated successfully"
                        },
                        "400": {
                            "description": "Invalid batch update"
                        },
                        "401": {
                            "description": "Unauthorized"
                        }
                    }
                }
            },
            "/stats/cache": {
                "get": {
                    "summary": "Get cache statistics",
                    "description": "Retrieve cache performance statistics",
                    "tags": ["Statistics"],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/CacheStats"
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "/stats/performance": {
                "get": {
                    "summary": "Get performance metrics",
                    "description": "Retrieve operational performance metrics",
                    "tags": ["Statistics"],
                    "responses": {
                        "200": {
                            "description": "Successful response",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/OperationStats"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        if let Some(paths_obj) = spec.get_mut("paths") {
            *paths_obj = paths;
        }
    }

    /// Generate OpenAPI spec as JSON string.
    ///
    /// # Errors
    ///
    /// Returns error if JSON serialization fails
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.build())
    }

    /// Generate OpenAPI spec as YAML string (using JSON as intermediate).
    #[must_use]
    pub fn to_yaml(&self) -> String {
        // Simple YAML conversion (for production, use a proper YAML library)
        let json = self.build();
        format!(
            "# OpenAPI 3.0 Specification for CHIE Protocol\n{}",
            serde_json::to_string_pretty(&json).unwrap_or_default()
        )
    }

    /// Write OpenAPI spec to a file.
    ///
    /// # Errors
    ///
    /// Returns error if file write or JSON serialization fails
    pub fn write_to_file(
        &self,
        path: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = self.to_json()?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

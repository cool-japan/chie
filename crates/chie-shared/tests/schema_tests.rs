//! Tests for JSON Schema and OpenAPI generation.
//!
//! These tests are only run when the `schema` feature is enabled.

#![cfg(feature = "schema")]

use chie_shared::*;

#[test]
fn test_json_schema_generation() {
    // Test that we can generate JSON schemas for all types
    let schemas = SchemaDefinitions::all();

    assert!(schemas.contains_key("ContentMetadata"));
    assert!(schemas.contains_key("BandwidthProof"));
    assert!(schemas.contains_key("ChunkRequest"));
    assert!(schemas.contains_key("ChunkResponse"));
    assert!(schemas.contains_key("User"));
    assert!(schemas.contains_key("NodeStats"));
    assert!(schemas.contains_key("BandwidthStats"));
    assert!(schemas.contains_key("ContentStats"));
    assert!(schemas.contains_key("PlatformStats"));
    assert!(schemas.contains_key("NetworkHealth"));

    // Verify we have at least 14 schemas
    assert!(schemas.len() >= 14);
}

#[test]
fn test_individual_schema_generation() {
    // Test individual schema generation (schemars 1.x: Schema is a JSON value wrapper)
    let content_schema = SchemaDefinitions::content_metadata();
    let content_json = serde_json::to_value(&content_schema).unwrap();
    assert!(content_json.get("properties").is_some() || content_json.get("type").is_some());

    let bandwidth_schema = SchemaDefinitions::bandwidth_proof();
    let bandwidth_json = serde_json::to_value(&bandwidth_schema).unwrap();
    assert!(bandwidth_json.get("properties").is_some() || bandwidth_json.get("type").is_some());

    let user_schema = SchemaDefinitions::user();
    let user_json = serde_json::to_value(&user_schema).unwrap();
    assert!(user_json.get("properties").is_some() || user_json.get("type").is_some());
}

#[test]
fn test_schema_json_serialization() {
    // Test that schemas can be serialized to JSON
    let schema = SchemaDefinitions::content_metadata();
    let json = serde_json::to_string_pretty(&schema).unwrap();

    assert!(!json.is_empty());
    assert!(json.contains("properties") || json.contains("type"));
}

#[test]
fn test_openapi_spec_generation() {
    // Test OpenAPI spec generation
    let spec = OpenApiSpec::new().build();

    // Verify OpenAPI version
    assert_eq!(spec["openapi"], "3.0.3");

    // Verify info section
    assert_eq!(spec["info"]["title"], "CHIE Protocol API");
    assert_eq!(spec["info"]["version"], "0.1.0");
    assert!(
        spec["info"]["description"]
            .as_str()
            .unwrap()
            .contains("CHIE")
    );

    // Verify servers
    assert!(spec["servers"].is_array());
    assert!(spec["servers"].as_array().unwrap().len() >= 2);

    // Verify components
    assert!(spec["components"]["schemas"].is_object());
    assert!(spec["components"]["securitySchemes"].is_object());

    // Verify paths exist
    assert!(spec["paths"].is_object());
}

#[test]
fn test_openapi_spec_has_required_schemas() {
    let spec = OpenApiSpec::new().build();
    let schemas = &spec["components"]["schemas"];

    // Verify key schemas are present
    assert!(schemas["ContentMetadata"].is_object());
    assert!(schemas["BandwidthProof"].is_object());
    assert!(schemas["User"].is_object());
    assert!(schemas["NodeStats"].is_object());
}

#[test]
fn test_openapi_spec_has_api_paths() {
    let spec = OpenApiSpec::new().build();
    let paths = &spec["paths"];

    // Verify key API paths
    assert!(paths["/content"].is_object());
    assert!(paths["/content/{cid}"].is_object());
    assert!(paths["/bandwidth/proof"].is_object());
    assert!(paths["/stats/bandwidth"].is_object());
    assert!(paths["/stats/platform"].is_object());
    assert!(paths["/health"].is_object());
    assert!(paths["/users/{id}"].is_object());
    assert!(paths["/leaderboard"].is_object());
}

#[test]
fn test_openapi_spec_content_endpoint() {
    let spec = OpenApiSpec::new().build();
    let content_get = &spec["paths"]["/content"]["get"];

    // Verify GET /content endpoint
    assert_eq!(content_get["summary"], "List content");
    assert!(content_get["parameters"].is_array());
    assert!(content_get["responses"]["200"].is_object());

    // Verify POST /content endpoint
    let content_post = &spec["paths"]["/content"]["post"];
    assert_eq!(content_post["summary"], "Create content");
    assert!(content_post["requestBody"].is_object());
    assert!(content_post["security"].is_array());
}

#[test]
fn test_openapi_spec_bandwidth_endpoint() {
    let spec = OpenApiSpec::new().build();
    let bandwidth_post = &spec["paths"]["/bandwidth/proof"]["post"];

    assert_eq!(bandwidth_post["summary"], "Submit bandwidth proof");
    assert!(bandwidth_post["requestBody"]["required"].as_bool().unwrap());
    assert_eq!(
        bandwidth_post["requestBody"]["content"]["application/json"]["schema"]["$ref"],
        "#/components/schemas/BandwidthProof"
    );
}

#[test]
fn test_openapi_spec_builder_pattern() {
    let spec = OpenApiSpec::new()
        .title("Custom CHIE API")
        .version("1.0.0")
        .description("Custom description")
        .build();

    assert_eq!(spec["info"]["title"], "Custom CHIE API");
    assert_eq!(spec["info"]["version"], "1.0.0");
    assert_eq!(spec["info"]["description"], "Custom description");
}

#[test]
fn test_openapi_spec_to_json() {
    let spec = OpenApiSpec::new();
    let json = spec.to_json().unwrap();

    assert!(!json.is_empty());
    assert!(json.contains("openapi"));
    assert!(json.contains("3.0.3"));
    assert!(json.contains("CHIE Protocol"));
}

#[test]
fn test_openapi_spec_security_schemes() {
    let spec = OpenApiSpec::new().build();
    let security = &spec["components"]["securitySchemes"]["bearerAuth"];

    assert_eq!(security["type"], "http");
    assert_eq!(security["scheme"], "bearer");
    assert_eq!(security["bearerFormat"], "JWT");
}

#[test]
fn test_openapi_spec_tags() {
    let spec = OpenApiSpec::new().build();

    // Verify tags are used in endpoints
    assert_eq!(spec["paths"]["/content"]["get"]["tags"][0], "Content");
    assert_eq!(
        spec["paths"]["/bandwidth/proof"]["post"]["tags"][0],
        "Bandwidth"
    );
    assert_eq!(
        spec["paths"]["/stats/bandwidth"]["get"]["tags"][0],
        "Statistics"
    );
    assert_eq!(spec["paths"]["/health"]["get"]["tags"][0], "System");
    assert_eq!(spec["paths"]["/users/{id}"]["get"]["tags"][0], "Users");
    assert_eq!(
        spec["paths"]["/leaderboard"]["get"]["tags"][0],
        "Leaderboard"
    );
}

#[test]
fn test_schema_write_to_directory() {
    // Test writing schemas to a temp directory
    let temp_dir = std::env::temp_dir().join("chie_schema_test");

    // Clean up if it exists
    let _ = std::fs::remove_dir_all(&temp_dir);

    // Write schemas
    let result = SchemaDefinitions::write_to_directory(&temp_dir);
    assert!(result.is_ok());

    // Verify files were created
    assert!(temp_dir.join("ContentMetadata.json").exists());
    assert!(temp_dir.join("BandwidthProof.json").exists());
    assert!(temp_dir.join("User.json").exists());

    // Clean up
    std::fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_openapi_write_to_file() {
    // Test writing OpenAPI spec to a temp file
    let temp_file = std::env::temp_dir().join("chie_openapi_test.json");

    // Clean up if it exists
    let _ = std::fs::remove_file(&temp_file);

    // Write spec
    let spec = OpenApiSpec::new();
    let result = spec.write_to_file(&temp_file);
    assert!(result.is_ok());

    // Verify file was created and contains valid JSON
    assert!(temp_file.exists());
    let content = std::fs::read_to_string(&temp_file).unwrap();
    assert!(content.contains("openapi"));
    assert!(serde_json::from_str::<serde_json::Value>(&content).is_ok());

    // Clean up
    std::fs::remove_file(&temp_file).unwrap();
}

#[test]
fn test_all_enums_have_schemas() {
    let schemas = SchemaDefinitions::all();

    // Verify all enum types have schemas
    assert!(schemas.contains_key("ContentCategory"));
    assert!(schemas.contains_key("ContentStatus"));
    assert!(schemas.contains_key("NodeStatus"));
    assert!(schemas.contains_key("UserRole"));
    assert!(schemas.contains_key("DemandLevel"));
}

#[test]
fn test_schema_references_in_openapi() {
    let spec = OpenApiSpec::new().build();

    // Verify schema references are properly formatted
    let content_ref = &spec["paths"]["/content"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"]["$ref"];
    assert_eq!(content_ref, "#/components/schemas/ContentMetadata");

    let bandwidth_ref = &spec["paths"]["/bandwidth/proof"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"]["$ref"];
    assert_eq!(bandwidth_ref, "#/components/schemas/BandwidthProof");
}

#[test]
fn test_openapi_response_codes() {
    let spec = OpenApiSpec::new().build();

    // Verify appropriate response codes
    assert!(spec["paths"]["/content"]["get"]["responses"]["200"].is_object());
    assert!(spec["paths"]["/content"]["post"]["responses"]["201"].is_object());
    assert!(spec["paths"]["/content/{cid}"]["get"]["responses"]["404"].is_object());
    assert!(spec["paths"]["/bandwidth/proof"]["post"]["responses"]["400"].is_object());
}

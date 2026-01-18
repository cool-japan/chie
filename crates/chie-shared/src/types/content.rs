//! Content metadata types for CHIE Protocol.

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::core::*;
use super::enums::{ContentCategory, ContentStatus};
use super::validation::ValidationError;

/// Content metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ContentMetadata {
    pub id: uuid::Uuid,
    pub cid: ContentCid,
    pub title: String,
    pub description: String,
    pub category: ContentCategory,
    pub tags: Vec<String>,
    pub size_bytes: Bytes,
    pub chunk_count: u64,
    pub price: Points,
    pub creator_id: uuid::Uuid,
    pub status: ContentStatus,
    pub preview_images: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl ContentMetadata {
    /// Validate content metadata.
    ///
    /// # Errors
    ///
    /// Returns `Vec<ValidationError>` with all validation errors found
    pub fn validate(&self) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        // Validate CID
        if self.cid.is_empty() {
            errors.push(ValidationError::EmptyCid);
        }

        // Validate title
        if self.title.len() > MAX_TITLE_LENGTH {
            errors.push(ValidationError::TitleTooLong {
                length: self.title.len(),
                max: MAX_TITLE_LENGTH,
            });
        }

        // Validate description
        if self.description.len() > MAX_DESCRIPTION_LENGTH {
            errors.push(ValidationError::DescriptionTooLong {
                length: self.description.len(),
                max: MAX_DESCRIPTION_LENGTH,
            });
        }

        // Validate tags
        if self.tags.len() > MAX_TAGS_COUNT {
            errors.push(ValidationError::TooManyTags {
                count: self.tags.len(),
                max: MAX_TAGS_COUNT,
            });
        }
        for tag in &self.tags {
            if tag.len() > MAX_TAG_LENGTH {
                errors.push(ValidationError::TagTooLong {
                    tag: tag.clone(),
                    length: tag.len(),
                    max: MAX_TAG_LENGTH,
                });
            }
        }

        // Validate size
        if self.size_bytes < MIN_CONTENT_SIZE || self.size_bytes > MAX_CONTENT_SIZE {
            errors.push(ValidationError::ContentSizeOutOfBounds {
                size: self.size_bytes,
                min: MIN_CONTENT_SIZE,
                max: MAX_CONTENT_SIZE,
            });
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check if metadata is valid.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }

    /// Calculate expected chunk count from size.
    #[inline]
    pub fn expected_chunk_count(&self) -> u64 {
        self.size_bytes.div_ceil(CHUNK_SIZE as u64)
    }

    /// Get the content size in megabytes.
    #[inline]
    pub fn size_mb(&self) -> f64 {
        self.size_bytes as f64 / (1024.0 * 1024.0)
    }

    /// Get the content size in gigabytes.
    #[inline]
    pub fn size_gb(&self) -> f64 {
        self.size_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Check if the content is active and available.
    #[inline]
    pub fn is_active(&self) -> bool {
        self.status == ContentStatus::Active
    }

    /// Check if the content is being processed.
    #[inline]
    pub fn is_processing(&self) -> bool {
        self.status == ContentStatus::Processing
    }

    /// Check if the content has been removed or rejected.
    #[inline]
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self.status,
            ContentStatus::Removed | ContentStatus::Rejected
        )
    }
}

/// Builder for ContentMetadata.
#[derive(Debug, Default)]
pub struct ContentMetadataBuilder {
    id: Option<uuid::Uuid>,
    cid: Option<ContentCid>,
    title: Option<String>,
    description: String,
    category: ContentCategory,
    tags: Vec<String>,
    size_bytes: Bytes,
    chunk_count: Option<u64>,
    price: Points,
    creator_id: Option<uuid::Uuid>,
    status: ContentStatus,
    preview_images: Vec<String>,
}

impl ContentMetadataBuilder {
    /// Create a new builder.
    pub fn new() -> Self {
        Self {
            category: ContentCategory::Other,
            status: ContentStatus::Processing,
            ..Default::default()
        }
    }

    /// Set the ID (auto-generated if not set).
    pub fn id(mut self, id: uuid::Uuid) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the CID.
    pub fn cid(mut self, cid: impl Into<String>) -> Self {
        self.cid = Some(cid.into());
        self
    }

    /// Set the title.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the category.
    pub fn category(mut self, category: ContentCategory) -> Self {
        self.category = category;
        self
    }

    /// Set the tags.
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Add a tag.
    pub fn add_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set the size in bytes.
    pub fn size_bytes(mut self, size: Bytes) -> Self {
        self.size_bytes = size;
        self
    }

    /// Set the chunk count (auto-calculated if not set).
    pub fn chunk_count(mut self, count: u64) -> Self {
        self.chunk_count = Some(count);
        self
    }

    /// Set the price.
    pub fn price(mut self, price: Points) -> Self {
        self.price = price;
        self
    }

    /// Set the creator ID.
    pub fn creator_id(mut self, creator_id: uuid::Uuid) -> Self {
        self.creator_id = Some(creator_id);
        self
    }

    /// Set the status.
    pub fn status(mut self, status: ContentStatus) -> Self {
        self.status = status;
        self
    }

    /// Set preview images.
    pub fn preview_images(mut self, images: Vec<String>) -> Self {
        self.preview_images = images;
        self
    }

    /// Build the ContentMetadata.
    ///
    /// # Errors
    ///
    /// Returns error if required fields (cid, title) are missing
    pub fn build(self) -> Result<ContentMetadata, &'static str> {
        let now = chrono::Utc::now();
        let size_bytes = self.size_bytes;
        let chunk_count = self
            .chunk_count
            .unwrap_or_else(|| size_bytes.div_ceil(CHUNK_SIZE as u64));

        Ok(ContentMetadata {
            id: self.id.unwrap_or_else(uuid::Uuid::new_v4),
            cid: self.cid.ok_or("cid is required")?,
            title: self.title.ok_or("title is required")?,
            description: self.description,
            category: self.category,
            tags: self.tags,
            size_bytes,
            chunk_count,
            price: self.price,
            creator_id: self.creator_id.ok_or("creator_id is required")?,
            status: self.status,
            preview_images: self.preview_images,
            created_at: now,
            updated_at: now,
        })
    }
}

/// Content investment recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ContentInvestment {
    pub content_id: uuid::Uuid,
    pub cid: ContentCid,
    pub title: String,
    pub current_seeders: u64,
    pub demand_level: super::enums::DemandLevel,
    pub predicted_revenue_per_gb: f64,
    pub recommended_allocation_gb: f64,
}

/// Content statistics for creators.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
pub struct ContentStats {
    /// Content ID.
    pub content_id: uuid::Uuid,
    /// Total downloads.
    pub download_count: u64,
    /// Total bandwidth served (bytes).
    pub bandwidth_served: Bytes,
    /// Number of active seeders.
    pub active_seeders: u64,
    /// Total earnings from this content.
    pub total_earnings: Points,
    /// Views count.
    pub views: u64,
    /// Unique downloaders.
    pub unique_downloaders: u64,
    /// Average rating (0.0-5.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub average_rating: Option<f64>,
    /// Statistics last updated.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_metadata_builder() {
        let creator_id = uuid::Uuid::new_v4();
        let metadata = ContentMetadataBuilder::new()
            .cid("QmTestContent")
            .title("Test Content")
            .description("A test content item")
            .category(ContentCategory::ThreeDModels)
            .add_tag("blender")
            .add_tag("lowpoly")
            .size_bytes(1024 * 1024)
            .price(100)
            .creator_id(creator_id)
            .build()
            .unwrap();

        assert_eq!(metadata.cid, "QmTestContent");
        assert_eq!(metadata.title, "Test Content");
        assert_eq!(metadata.category, ContentCategory::ThreeDModels);
        assert_eq!(metadata.tags.len(), 2);
        assert_eq!(metadata.chunk_count, metadata.expected_chunk_count());
        assert!(metadata.is_valid());
    }

    #[test]
    fn test_content_metadata_validation_title_too_long() {
        let creator_id = uuid::Uuid::new_v4();
        let long_title = "a".repeat(MAX_TITLE_LENGTH + 1);
        let metadata = ContentMetadataBuilder::new()
            .cid("QmTest")
            .title(long_title)
            .creator_id(creator_id)
            .size_bytes(10000)
            .build()
            .unwrap();

        let result = metadata.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::TitleTooLong { .. }))
        );
    }

    #[test]
    fn test_content_metadata_validation_too_many_tags() {
        let creator_id = uuid::Uuid::new_v4();
        let mut builder = ContentMetadataBuilder::new()
            .cid("QmTest")
            .title("Test")
            .creator_id(creator_id)
            .size_bytes(10000);

        for i in 0..(MAX_TAGS_COUNT + 1) {
            builder = builder.add_tag(format!("tag{}", i));
        }

        let metadata = builder.build().unwrap();
        let result = metadata.validate();
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ValidationError::TooManyTags { .. }))
        );
    }

    #[test]
    fn test_content_metadata_validation_size_out_of_bounds() {
        let creator_id = uuid::Uuid::new_v4();

        // Too small
        let metadata_small = ContentMetadataBuilder::new()
            .cid("QmTest")
            .title("Test")
            .creator_id(creator_id)
            .size_bytes(100) // Below MIN_CONTENT_SIZE
            .build()
            .unwrap();

        let result = metadata_small.validate();
        assert!(result.is_err());

        // Too large
        let metadata_large = ContentMetadataBuilder::new()
            .cid("QmTest")
            .title("Test")
            .creator_id(creator_id)
            .size_bytes(MAX_CONTENT_SIZE + 1)
            .build()
            .unwrap();

        let result = metadata_large.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_content_metadata_expected_chunk_count() {
        let creator_id = uuid::Uuid::new_v4();
        let size = CHUNK_SIZE as u64 * 5 + 1000; // 5 full chunks + partial
        let metadata = ContentMetadataBuilder::new()
            .cid("QmTest")
            .title("Test")
            .creator_id(creator_id)
            .size_bytes(size)
            .build()
            .unwrap();

        assert_eq!(metadata.expected_chunk_count(), 6);
    }

    #[test]
    fn test_content_metadata_serialization() {
        let metadata = ContentMetadataBuilder::new()
            .cid("QmTest")
            .title("Test")
            .creator_id(uuid::Uuid::new_v4())
            .size_bytes(10000)
            .build()
            .unwrap();

        let json = serde_json::to_string(&metadata).unwrap();
        let deserialized: ContentMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(metadata.cid, deserialized.cid);
        assert_eq!(metadata.title, deserialized.title);
    }
}

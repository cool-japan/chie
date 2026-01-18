//! Content and file utility functions.

/// Detect common file types from MIME type strings.
/// Returns a category hint that can help with content classification.
///
/// # Examples
///
/// ```
/// use chie_shared::mime_to_category_hint;
///
/// // Classify different MIME types
/// assert_eq!(mime_to_category_hint("video/mp4"), "video");
/// assert_eq!(mime_to_category_hint("audio/mpeg"), "audio");
/// assert_eq!(mime_to_category_hint("image/png"), "image");
/// assert_eq!(mime_to_category_hint("text/plain"), "document");
/// assert_eq!(mime_to_category_hint("application/pdf"), "document");
/// assert_eq!(mime_to_category_hint("application/zip"), "software");
///
/// // Case insensitive
/// assert_eq!(mime_to_category_hint("VIDEO/MP4"), "video");
///
/// // Unknown types
/// assert_eq!(mime_to_category_hint("unknown/type"), "other");
/// ```
#[must_use]
pub fn mime_to_category_hint(mime_type: &str) -> &'static str {
    let mime_lower = mime_type.to_lowercase();

    if mime_lower.starts_with("video/") {
        "video"
    } else if mime_lower.starts_with("audio/") {
        "audio"
    } else if mime_lower.starts_with("image/") {
        "image"
    } else if mime_lower.starts_with("text/") || mime_lower.contains("document") {
        "document"
    } else if mime_lower.contains("application/") {
        if mime_lower.contains("pdf") {
            "document"
        } else if mime_lower.contains("zip") || mime_lower.contains("archive") {
            "software"
        } else {
            "other"
        }
    } else {
        "other"
    }
}

/// Get file extension from filename.
/// Returns the extension without the dot, or empty string if no extension.
///
/// # Examples
///
/// ```
/// use chie_shared::get_file_extension;
///
/// // Extract extensions
/// assert_eq!(get_file_extension("document.pdf"), "pdf");
/// assert_eq!(get_file_extension("video.mp4"), "mp4");
/// assert_eq!(get_file_extension("archive.tar.gz"), "gz"); // Gets last extension
///
/// // Files without extensions
/// assert_eq!(get_file_extension("README"), "");
/// assert_eq!(get_file_extension("noextension"), "");
///
/// // Hidden files
/// assert_eq!(get_file_extension(".gitignore"), "gitignore");
/// ```
#[must_use]
pub fn get_file_extension(filename: &str) -> &str {
    filename
        .rfind('.')
        .map(|pos| &filename[pos + 1..])
        .unwrap_or("")
}

/// Check if a filename has a valid extension (non-empty and alphanumeric).
#[must_use]
pub fn has_valid_extension(filename: &str) -> bool {
    if let Some(ext) = filename.rfind('.').map(|pos| &filename[pos + 1..]) {
        !ext.is_empty() && ext.chars().all(|c| c.is_alphanumeric())
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mime_to_category_hint() {
        assert_eq!(mime_to_category_hint("video/mp4"), "video");
        assert_eq!(mime_to_category_hint("VIDEO/MPEG"), "video");
        assert_eq!(mime_to_category_hint("audio/mpeg"), "audio");
        assert_eq!(mime_to_category_hint("AUDIO/WAV"), "audio");
        assert_eq!(mime_to_category_hint("image/png"), "image");
        assert_eq!(mime_to_category_hint("IMAGE/JPEG"), "image");
        assert_eq!(mime_to_category_hint("text/plain"), "document");
        assert_eq!(mime_to_category_hint("application/pdf"), "document");
        assert_eq!(mime_to_category_hint("application/zip"), "software");
        assert_eq!(mime_to_category_hint("application/json"), "other");
        assert_eq!(mime_to_category_hint("unknown/type"), "other");
    }

    #[test]
    fn test_get_file_extension() {
        assert_eq!(get_file_extension("file.txt"), "txt");
        assert_eq!(get_file_extension("document.pdf"), "pdf");
        assert_eq!(get_file_extension("archive.tar.gz"), "gz");
        assert_eq!(get_file_extension("noext"), "");
        assert_eq!(get_file_extension(".hidden"), "hidden");
        assert_eq!(get_file_extension("path/to/file.mp4"), "mp4");
    }

    #[test]
    fn test_has_valid_extension() {
        assert!(has_valid_extension("file.txt"));
        assert!(has_valid_extension("document.pdf"));
        assert!(has_valid_extension("archive.tar"));
        assert!(!has_valid_extension("noext"));
        assert!(!has_valid_extension("file."));
        assert!(!has_valid_extension("file.tx t")); // Space in extension
        assert!(has_valid_extension("file.mp4"));
    }
}

//! Generic result type with error context for better error handling
//!
//! This module provides a `ChieResult<T>` type that wraps errors with additional context,
//! making it easier to debug and understand where errors occurred.

use std::fmt;
use std::sync::OnceLock;

/// Global telemetry handler for error reporting
///
/// This is a thread-safe, lazy-initialized global handler that can be set once
/// to report errors to external monitoring systems (e.g., `Sentry`, `DataDog`, `CloudWatch`).
static TELEMETRY_HANDLER: OnceLock<fn(&ChieError)> = OnceLock::new();

/// Set the global error telemetry handler
///
/// This function sets a global handler that will be called whenever an error
/// is reported via `report_telemetry()` or `new_with_telemetry()`.
///
/// The handler can only be set once. Subsequent calls will be ignored.
///
/// # Example
///
/// ```
/// use chie_shared::{set_telemetry_handler, ChieError};
///
/// fn my_telemetry_handler(error: &ChieError) {
///     // Report to monitoring system
///     eprintln!("Telemetry: {} - {}", error.kind, error.message);
/// }
///
/// set_telemetry_handler(my_telemetry_handler);
/// ```
pub fn set_telemetry_handler(handler: fn(&ChieError)) {
    let _ = TELEMETRY_HANDLER.set(handler);
}

/// Generic result type for CHIE operations
///
/// This type provides consistent error handling across the crate with
/// optional error context for better debugging.
pub type ChieResult<T> = Result<T, ChieError>;

/// Enhanced error type with context information
///
/// This error type wraps the underlying error with additional context
/// about where and why the error occurred.
#[derive(Debug, Clone)]
pub struct ChieError {
    /// The kind of error that occurred
    pub kind: ErrorKind,
    /// Human-readable error message
    pub message: String,
    /// Optional context about where/why the error occurred
    pub context: Vec<String>,
}

/// Categories of errors in the CHIE protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// Validation errors (invalid input, constraint violations)
    Validation,
    /// Network errors (connection failures, timeouts)
    Network,
    /// Serialization/deserialization errors
    Serialization,
    /// Cryptographic errors (signing, verification failures)
    Cryptographic,
    /// Storage errors (disk I/O, database issues)
    Storage,
    /// Resource exhaustion (quota exceeded, rate limited)
    ResourceExhausted,
    /// Not found errors (missing content, peer, etc.)
    NotFound,
    /// Already exists errors (duplicate content, etc.)
    AlreadyExists,
    /// Permission denied errors
    PermissionDenied,
    /// Internal errors (bugs, unexpected state)
    Internal,
}

impl ChieError {
    /// Create a new error with the specified kind and message
    #[must_use]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            context: Vec::new(),
        }
    }

    /// Create a validation error
    #[must_use]
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Validation, message)
    }

    /// Create a network error
    #[must_use]
    pub fn network(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Network, message)
    }

    /// Create a serialization error
    #[must_use]
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Serialization, message)
    }

    /// Create a cryptographic error
    #[must_use]
    pub fn cryptographic(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Cryptographic, message)
    }

    /// Create a storage error
    #[must_use]
    pub fn storage(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Storage, message)
    }

    /// Create a resource exhausted error
    #[must_use]
    pub fn resource_exhausted(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ResourceExhausted, message)
    }

    /// Create a not found error
    #[must_use]
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    /// Create an already exists error
    #[must_use]
    pub fn already_exists(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::AlreadyExists, message)
    }

    /// Create a permission denied error
    #[must_use]
    pub fn permission_denied(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PermissionDenied, message)
    }

    /// Create an internal error
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, message)
    }

    /// Add context to the error
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::ChieError;
    ///
    /// let err = ChieError::validation("Invalid CID")
    ///     .context("While validating content metadata")
    ///     .context("In upload handler");
    /// ```
    #[must_use]
    pub fn context(mut self, ctx: impl Into<String>) -> Self {
        self.context.push(ctx.into());
        self
    }

    /// Check if this is a transient error that might succeed on retry
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(
            self.kind,
            ErrorKind::Network | ErrorKind::ResourceExhausted | ErrorKind::Storage
        )
    }

    /// Check if this is a permanent error that won't succeed on retry
    #[must_use]
    pub fn is_permanent(&self) -> bool {
        !self.is_transient()
    }

    /// Get the full error message with context
    #[must_use]
    pub fn full_message(&self) -> String {
        if self.context.is_empty() {
            self.message.clone()
        } else {
            let context = self.context.join(" -> ");
            format!("{}: {}", context, self.message)
        }
    }

    /// Report this error to telemetry if a handler is set
    ///
    /// This allows errors to be reported to external monitoring systems.
    /// The global telemetry handler must be set using `set_telemetry_handler`.
    pub fn report_telemetry(&self) {
        if let Some(handler) = TELEMETRY_HANDLER.get() {
            handler(self);
        }
    }

    /// Create an error and immediately report it to telemetry
    #[must_use]
    pub fn new_with_telemetry(kind: ErrorKind, message: impl Into<String>) -> Self {
        let error = Self::new(kind, message);
        error.report_telemetry();
        error
    }
}

impl fmt::Display for ChieError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.full_message())
    }
}

impl std::error::Error for ChieError {}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation => write!(f, "Validation"),
            Self::Network => write!(f, "Network"),
            Self::Serialization => write!(f, "Serialization"),
            Self::Cryptographic => write!(f, "Cryptographic"),
            Self::Storage => write!(f, "Storage"),
            Self::ResourceExhausted => write!(f, "ResourceExhausted"),
            Self::NotFound => write!(f, "NotFound"),
            Self::AlreadyExists => write!(f, "AlreadyExists"),
            Self::PermissionDenied => write!(f, "PermissionDenied"),
            Self::Internal => write!(f, "Internal"),
        }
    }
}

/// Extension trait to add context to any result
pub trait ResultExt<T> {
    /// Add context to an error
    ///
    /// # Errors
    ///
    /// Returns the error with additional context if the result is `Err`
    fn context(self, ctx: impl Into<String>) -> ChieResult<T>;

    /// Add context using a closure (lazy evaluation)
    ///
    /// # Errors
    ///
    /// Returns the error with additional context if the result is `Err`
    fn with_context<F>(self, f: F) -> ChieResult<T>
    where
        F: FnOnce() -> String;
}

impl<T> ResultExt<T> for ChieResult<T> {
    fn context(self, ctx: impl Into<String>) -> ChieResult<T> {
        self.map_err(|e| e.context(ctx))
    }

    fn with_context<F>(self, f: F) -> ChieResult<T>
    where
        F: FnOnce() -> String,
    {
        self.map_err(|e| e.context(f()))
    }
}

/// Panic recovery utilities for safer error handling
pub struct PanicRecovery;

impl PanicRecovery {
    /// Catch panics and convert them to `ChieError`
    ///
    /// # Errors
    ///
    /// Returns `ChieError` with `ErrorKind::Internal` if the function panics
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::{PanicRecovery, ErrorKind};
    ///
    /// let result = PanicRecovery::catch_unwind(|| {
    ///     // This would normally panic
    ///     if false {
    ///         panic!("Something went wrong!");
    ///     }
    ///     42
    /// });
    ///
    /// assert!(result.is_ok());
    /// assert_eq!(result.unwrap(), 42);
    /// ```
    pub fn catch_unwind<F, T>(f: F) -> ChieResult<T>
    where
        F: FnOnce() -> T + std::panic::UnwindSafe,
    {
        std::panic::catch_unwind(f).map_err(|panic_info| {
            let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };

            ChieError::internal(format!("Panic caught: {panic_msg}"))
        })
    }

    /// Catch panics with custom error context
    ///
    /// # Errors
    ///
    /// Returns `ChieError` with the provided context if the function panics
    pub fn catch_unwind_with_context<F, T>(f: F, context: impl Into<String>) -> ChieResult<T>
    where
        F: FnOnce() -> T + std::panic::UnwindSafe,
    {
        Self::catch_unwind(f).map_err(|e| e.context(context))
    }

    /// Retry a function that might panic, up to `max_attempts` times
    ///
    /// # Errors
    ///
    /// Returns `ChieError` if all attempts fail with panics
    ///
    /// # Examples
    ///
    /// ```
    /// use chie_shared::PanicRecovery;
    /// use std::sync::atomic::{AtomicUsize, Ordering};
    ///
    /// let attempt = AtomicUsize::new(0);
    /// let result = PanicRecovery::retry_on_panic(3, || {
    ///     let current = attempt.fetch_add(1, Ordering::SeqCst) + 1;
    ///     if current < 3 {
    ///         panic!("Not yet!");
    ///     }
    ///     "success"
    /// });
    ///
    /// assert!(result.is_ok());
    /// ```
    pub fn retry_on_panic<F, T>(max_attempts: usize, mut f: F) -> ChieResult<T>
    where
        F: FnMut() -> T + std::panic::UnwindSafe,
    {
        let mut last_error = None;

        for attempt in 1..=max_attempts {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(&mut f)) {
                Ok(value) => return Ok(value),
                Err(panic_info) => {
                    let panic_msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                        (*s).to_string()
                    } else if let Some(s) = panic_info.downcast_ref::<String>() {
                        s.clone()
                    } else {
                        "Unknown panic".to_string()
                    };

                    last_error = Some(ChieError::internal(format!(
                        "Panic on attempt {attempt}/{max_attempts}: {panic_msg}"
                    )));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| ChieError::internal("All retry attempts failed")))
    }

    /// Execute function with panic barrier - isolates panics from caller
    pub fn with_barrier<F, T>(f: F, fallback: T) -> T
    where
        F: FnOnce() -> T + std::panic::UnwindSafe,
        T: Clone,
    {
        std::panic::catch_unwind(f).unwrap_or(fallback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chie_error_creation() {
        let err = ChieError::validation("Invalid CID");
        assert_eq!(err.kind, ErrorKind::Validation);
        assert_eq!(err.message, "Invalid CID");
        assert!(err.context.is_empty());
    }

    #[test]
    fn test_chie_error_with_context() {
        let err = ChieError::validation("Invalid CID")
            .context("While validating content")
            .context("In upload handler");

        assert_eq!(err.context.len(), 2);
        assert_eq!(err.context[0], "While validating content");
        assert_eq!(err.context[1], "In upload handler");
    }

    #[test]
    fn test_error_full_message() {
        let err = ChieError::validation("Invalid CID")
            .context("While validating content")
            .context("In upload handler");

        let msg = err.full_message();
        assert!(msg.contains("While validating content"));
        assert!(msg.contains("In upload handler"));
        assert!(msg.contains("Invalid CID"));
    }

    #[test]
    fn test_error_display() {
        let err = ChieError::validation("Invalid CID");
        assert_eq!(err.to_string(), "Invalid CID");

        let err_with_ctx = err.context("In validator");
        assert_eq!(err_with_ctx.to_string(), "In validator: Invalid CID");
    }

    #[test]
    fn test_is_transient() {
        assert!(ChieError::network("Connection failed").is_transient());
        assert!(ChieError::resource_exhausted("Quota exceeded").is_transient());
        assert!(ChieError::storage("Disk full").is_transient());
        assert!(!ChieError::validation("Invalid input").is_transient());
        assert!(!ChieError::permission_denied("Access denied").is_transient());
    }

    #[test]
    fn test_is_permanent() {
        assert!(ChieError::validation("Invalid input").is_permanent());
        assert!(ChieError::permission_denied("Access denied").is_permanent());
        assert!(!ChieError::network("Connection failed").is_permanent());
    }

    #[test]
    fn test_error_kinds() {
        assert_eq!(ChieError::validation("").kind, ErrorKind::Validation);
        assert_eq!(ChieError::network("").kind, ErrorKind::Network);
        assert_eq!(ChieError::serialization("").kind, ErrorKind::Serialization);
        assert_eq!(ChieError::cryptographic("").kind, ErrorKind::Cryptographic);
        assert_eq!(ChieError::storage("").kind, ErrorKind::Storage);
        assert_eq!(
            ChieError::resource_exhausted("").kind,
            ErrorKind::ResourceExhausted
        );
        assert_eq!(ChieError::not_found("").kind, ErrorKind::NotFound);
        assert_eq!(ChieError::already_exists("").kind, ErrorKind::AlreadyExists);
        assert_eq!(
            ChieError::permission_denied("").kind,
            ErrorKind::PermissionDenied
        );
        assert_eq!(ChieError::internal("").kind, ErrorKind::Internal);
    }

    #[test]
    fn test_result_ext_context() {
        let result: ChieResult<i32> = Err(ChieError::validation("Invalid value"));
        let result_with_ctx = result.context("In function foo");

        assert!(result_with_ctx.is_err());
        let err = result_with_ctx.unwrap_err();
        assert_eq!(err.context.len(), 1);
        assert_eq!(err.context[0], "In function foo");
    }

    #[test]
    fn test_result_ext_with_context() {
        let result: ChieResult<i32> = Err(ChieError::validation("Invalid value"));
        let result_with_ctx = result.with_context(|| format!("Value was {}", 42));

        assert!(result_with_ctx.is_err());
        let err = result_with_ctx.unwrap_err();
        assert_eq!(err.context.len(), 1);
        assert_eq!(err.context[0], "Value was 42");
    }

    #[test]
    fn test_error_kind_display() {
        assert_eq!(ErrorKind::Validation.to_string(), "Validation");
        assert_eq!(ErrorKind::Network.to_string(), "Network");
        assert_eq!(ErrorKind::NotFound.to_string(), "NotFound");
    }

    #[test]
    fn test_result_ok_preserves_value() {
        let result: ChieResult<i32> = Ok(42);
        let result_with_ctx = result.context("Should not be called");

        assert!(result_with_ctx.is_ok());
        assert_eq!(result_with_ctx.unwrap(), 42);
    }

    // Telemetry tests
    #[test]
    fn test_telemetry_report() {
        // This test just ensures the method exists and doesn't panic
        let error = ChieError::validation("Test error");
        error.report_telemetry(); // Should not panic even if handler not set
    }

    #[test]
    fn test_new_with_telemetry() {
        // Create error with telemetry (will call handler if set)
        let error = ChieError::new_with_telemetry(ErrorKind::Network, "Network failure");
        assert_eq!(error.kind, ErrorKind::Network);
        assert_eq!(error.message, "Network failure");
    }

    #[test]
    fn test_set_telemetry_handler() {
        // Define a simple handler function
        fn test_handler(error: &ChieError) {
            // Just verify the error has expected structure
            let _ = &error.kind;
            let _ = &error.message;
        }

        // Should not panic
        set_telemetry_handler(test_handler);
    }

    // Panic recovery tests
    #[test]
    fn test_catch_unwind_success() {
        let result = PanicRecovery::catch_unwind(|| 42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_catch_unwind_panic() {
        let result = PanicRecovery::catch_unwind(|| {
            panic!("Test panic");
        });
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Internal);
        assert!(err.message.contains("Panic caught"));
    }

    #[test]
    fn test_catch_unwind_with_context() {
        let result = PanicRecovery::catch_unwind_with_context(
            || panic!("Oops"),
            "During database operation",
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.context.is_empty());
    }

    #[test]
    fn test_retry_on_panic_success_first_try() {
        let result = PanicRecovery::retry_on_panic(3, || "success");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }

    #[test]
    fn test_retry_on_panic_success_after_retries() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let attempt = AtomicUsize::new(0);
        let result = PanicRecovery::retry_on_panic(3, || {
            let current = attempt.fetch_add(1, Ordering::SeqCst) + 1;
            if current < 3 {
                panic!("Not yet");
            }
            "success"
        });
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(attempt.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_retry_on_panic_all_fail() {
        let result = PanicRecovery::retry_on_panic(2, || {
            panic!("Always fails");
        });
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message.contains("attempt 2/2"));
    }

    #[test]
    fn test_with_barrier_success() {
        let result = PanicRecovery::with_barrier(|| 42, 0);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_with_barrier_panic_fallback() {
        let result = PanicRecovery::with_barrier(
            || {
                panic!("Panic!");
            },
            999,
        );
        assert_eq!(result, 999);
    }
}

//! Logging configuration with configurable verbosity.
//!
//! This module provides a flexible logging system with configurable verbosity levels
//! and filtering capabilities.
//!
//! # Features
//!
//! - Multiple verbosity levels (Error, Warn, Info, Debug, Trace)
//! - Module-level filtering
//! - Structured logging support
//! - Performance metrics logging
//! - Conditional compilation for zero-cost when disabled
//!
//! # Example
//!
//! ```
//! use chie_core::logging::{LogConfig, LogLevel, Logger};
//!
//! // Create a logger with Info level
//! let config = LogConfig {
//!     level: LogLevel::Info,
//!     include_timestamps: true,
//!     include_module_path: true,
//!     include_line_numbers: false,
//!     filter_modules: vec![],
//! };
//!
//! let logger = Logger::new(config);
//!
//! // Log messages at different levels
//! logger.info("chie_core::storage", "Storage initialized");
//! logger.debug("chie_core::cache", "Cache size: 1024 entries");
//! logger.error("chie_core::network", "Connection failed");
//! ```

use std::collections::HashSet;
use std::fmt;
use std::time::SystemTime;

/// Log verbosity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LogLevel {
    /// Critical errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// Informational messages, warnings, and errors.
    Info,
    /// Debug messages and above.
    Debug,
    /// All messages including trace.
    Trace,
}

impl LogLevel {
    /// Get the string representation of the log level.
    #[must_use]
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }

    /// Get a colored version of the log level (ANSI codes).
    #[must_use]
    #[inline]
    pub const fn colored(&self) -> &'static str {
        match self {
            Self::Error => "\x1b[31mERROR\x1b[0m", // Red
            Self::Warn => "\x1b[33mWARN\x1b[0m",   // Yellow
            Self::Info => "\x1b[32mINFO\x1b[0m",   // Green
            Self::Debug => "\x1b[36mDEBUG\x1b[0m", // Cyan
            Self::Trace => "\x1b[90mTRACE\x1b[0m", // Gray
        }
    }

    /// Check if this level should be logged given the configured level.
    #[must_use]
    #[inline]
    pub const fn should_log(&self, configured_level: &Self) -> bool {
        (*self as u8) <= (*configured_level as u8)
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Logging configuration.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// Minimum log level to display.
    pub level: LogLevel,
    /// Include timestamps in log messages.
    pub include_timestamps: bool,
    /// Include module path in log messages.
    pub include_module_path: bool,
    /// Include line numbers in log messages.
    pub include_line_numbers: bool,
    /// Modules to filter (only log these modules if non-empty).
    pub filter_modules: Vec<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            include_timestamps: true,
            include_module_path: true,
            include_line_numbers: false,
            filter_modules: Vec::new(),
        }
    }
}

impl LogConfig {
    /// Create a new configuration with the specified level.
    #[must_use]
    #[inline]
    pub const fn new(level: LogLevel) -> Self {
        Self {
            level,
            include_timestamps: true,
            include_module_path: true,
            include_line_numbers: false,
            filter_modules: Vec::new(),
        }
    }

    /// Create a minimal configuration (no timestamps, no module paths).
    #[must_use]
    #[inline]
    pub const fn minimal(level: LogLevel) -> Self {
        Self {
            level,
            include_timestamps: false,
            include_module_path: false,
            include_line_numbers: false,
            filter_modules: Vec::new(),
        }
    }

    /// Create a verbose configuration (all metadata included).
    #[must_use]
    #[inline]
    pub const fn verbose(level: LogLevel) -> Self {
        Self {
            level,
            include_timestamps: true,
            include_module_path: true,
            include_line_numbers: true,
            filter_modules: Vec::new(),
        }
    }

    /// Add a module filter.
    #[must_use]
    pub fn with_module_filter(mut self, module: String) -> Self {
        self.filter_modules.push(module);
        self
    }
}

/// Logger instance with configuration.
pub struct Logger {
    config: LogConfig,
    filter_set: HashSet<String>,
    use_color: bool,
}

impl Logger {
    /// Create a new logger with the given configuration.
    #[must_use]
    pub fn new(config: LogConfig) -> Self {
        let filter_set: HashSet<String> = config.filter_modules.iter().cloned().collect();

        Self {
            config,
            filter_set,
            use_color: is_terminal(),
        }
    }

    /// Create a logger with default configuration.
    #[must_use]
    #[inline]
    pub fn default_config() -> Self {
        Self::new(LogConfig::default())
    }

    /// Check if a module should be logged.
    #[must_use]
    #[inline]
    fn should_log_module(&self, module: &str) -> bool {
        if self.filter_set.is_empty() {
            return true;
        }

        self.filter_set
            .iter()
            .any(|filter| module.starts_with(filter) || filter.starts_with(module))
    }

    /// Log a message at the specified level.
    pub fn log(&self, level: LogLevel, module: &str, message: &str, line: Option<u32>) {
        if !level.should_log(&self.config.level) {
            return;
        }

        if !self.should_log_module(module) {
            return;
        }

        let mut parts = Vec::new();

        // Timestamp
        if self.config.include_timestamps {
            let timestamp = format_timestamp();
            parts.push(timestamp);
        }

        // Level
        let level_str = if self.use_color {
            level.colored().to_string()
        } else {
            level.as_str().to_string()
        };
        parts.push(format!("[{}]", level_str));

        // Module path
        if self.config.include_module_path {
            parts.push(format!("[{}]", module));
        }

        // Line number
        if self.config.include_line_numbers {
            if let Some(line_num) = line {
                parts.push(format!("[L{}]", line_num));
            }
        }

        // Message
        parts.push(message.to_string());

        println!("{}", parts.join(" "));
    }

    /// Log an error message.
    #[inline]
    pub fn error(&self, module: &str, message: &str) {
        self.log(LogLevel::Error, module, message, None);
    }

    /// Log a warning message.
    #[inline]
    pub fn warn(&self, module: &str, message: &str) {
        self.log(LogLevel::Warn, module, message, None);
    }

    /// Log an info message.
    #[inline]
    pub fn info(&self, module: &str, message: &str) {
        self.log(LogLevel::Info, module, message, None);
    }

    /// Log a debug message.
    #[inline]
    pub fn debug(&self, module: &str, message: &str) {
        self.log(LogLevel::Debug, module, message, None);
    }

    /// Log a trace message.
    #[inline]
    pub fn trace(&self, module: &str, message: &str) {
        self.log(LogLevel::Trace, module, message, None);
    }

    /// Log an error message with line number.
    #[inline]
    pub fn error_at(&self, module: &str, message: &str, line: u32) {
        self.log(LogLevel::Error, module, message, Some(line));
    }

    /// Log a warning message with line number.
    #[inline]
    pub fn warn_at(&self, module: &str, message: &str, line: u32) {
        self.log(LogLevel::Warn, module, message, Some(line));
    }

    /// Log a structured message with key-value pairs.
    pub fn structured(
        &self,
        level: LogLevel,
        module: &str,
        message: &str,
        fields: &[(&str, &str)],
    ) {
        if !level.should_log(&self.config.level) {
            return;
        }

        if !self.should_log_module(module) {
            return;
        }

        let fields_str: Vec<String> = fields.iter().map(|(k, v)| format!("{}={}", k, v)).collect();

        let full_message = if fields_str.is_empty() {
            message.to_string()
        } else {
            format!("{} {}", message, fields_str.join(" "))
        };

        self.log(level, module, &full_message, None);
    }

    /// Log performance metrics.
    #[inline]
    pub fn perf(&self, module: &str, operation: &str, duration_ms: u64) {
        let message = format!("{} completed in {}ms", operation, duration_ms);
        self.structured(
            LogLevel::Debug,
            module,
            &message,
            &[
                ("operation", operation),
                ("duration_ms", &duration_ms.to_string()),
            ],
        );
    }

    /// Get the current log level.
    #[must_use]
    #[inline]
    pub const fn level(&self) -> LogLevel {
        self.config.level
    }

    /// Set the log level.
    pub fn set_level(&mut self, level: LogLevel) {
        self.config.level = level;
    }

    /// Enable or disable colored output.
    #[inline]
    pub fn set_color(&mut self, use_color: bool) {
        self.use_color = use_color;
    }
}

/// Format a timestamp for logging.
#[must_use]
fn format_timestamp() -> String {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();

    let secs = now.as_secs();
    let millis = now.subsec_millis();

    // Simple ISO-like format: HH:MM:SS.mmm
    let hours = (secs / 3600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;

    format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, millis)
}

/// Check if stdout is a terminal (for color support).
#[must_use]
#[inline]
fn is_terminal() -> bool {
    // Simple heuristic: check if TERM environment variable is set
    std::env::var("TERM").is_ok()
}

/// Macro for logging with automatic module path.
#[macro_export]
macro_rules! log_error {
    ($logger:expr, $($arg:tt)*) => {
        $logger.error(module_path!(), &format!($($arg)*))
    };
}

/// Macro for logging warnings with automatic module path.
#[macro_export]
macro_rules! log_warn {
    ($logger:expr, $($arg:tt)*) => {
        $logger.warn(module_path!(), &format!($($arg)*))
    };
}

/// Macro for logging info with automatic module path.
#[macro_export]
macro_rules! log_info {
    ($logger:expr, $($arg:tt)*) => {
        $logger.info(module_path!(), &format!($($arg)*))
    };
}

/// Macro for logging debug with automatic module path.
#[macro_export]
macro_rules! log_debug {
    ($logger:expr, $($arg:tt)*) => {
        $logger.debug(module_path!(), &format!($($arg)*))
    };
}

/// Macro for logging trace with automatic module path.
#[macro_export]
macro_rules! log_trace {
    ($logger:expr, $($arg:tt)*) => {
        $logger.trace(module_path!(), &format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_ordering() {
        assert!(LogLevel::Error < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Trace);
    }

    #[test]
    fn test_should_log() {
        let configured_level = LogLevel::Info;

        assert!(LogLevel::Error.should_log(&configured_level));
        assert!(LogLevel::Warn.should_log(&configured_level));
        assert!(LogLevel::Info.should_log(&configured_level));
        assert!(!LogLevel::Debug.should_log(&configured_level));
        assert!(!LogLevel::Trace.should_log(&configured_level));
    }

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.level, LogLevel::Info);
        assert!(config.include_timestamps);
        assert!(config.include_module_path);
        assert!(!config.include_line_numbers);
    }

    #[test]
    fn test_log_config_minimal() {
        let config = LogConfig::minimal(LogLevel::Debug);
        assert_eq!(config.level, LogLevel::Debug);
        assert!(!config.include_timestamps);
        assert!(!config.include_module_path);
        assert!(!config.include_line_numbers);
    }

    #[test]
    fn test_log_config_verbose() {
        let config = LogConfig::verbose(LogLevel::Trace);
        assert_eq!(config.level, LogLevel::Trace);
        assert!(config.include_timestamps);
        assert!(config.include_module_path);
        assert!(config.include_line_numbers);
    }

    #[test]
    fn test_logger_creation() {
        let config = LogConfig::default();
        let logger = Logger::new(config);
        assert_eq!(logger.level(), LogLevel::Info);
    }

    #[test]
    fn test_module_filtering() {
        let config = LogConfig::default().with_module_filter("chie_core::storage".to_string());
        let logger = Logger::new(config);

        assert!(logger.should_log_module("chie_core::storage"));
        assert!(logger.should_log_module("chie_core::storage::chunk"));
        assert!(!logger.should_log_module("chie_core::network"));
    }

    #[test]
    fn test_logger_level_change() {
        let mut logger = Logger::default_config();
        assert_eq!(logger.level(), LogLevel::Info);

        logger.set_level(LogLevel::Debug);
        assert_eq!(logger.level(), LogLevel::Debug);
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Error.to_string(), "ERROR");
        assert_eq!(LogLevel::Warn.to_string(), "WARN");
        assert_eq!(LogLevel::Info.to_string(), "INFO");
        assert_eq!(LogLevel::Debug.to_string(), "DEBUG");
        assert_eq!(LogLevel::Trace.to_string(), "TRACE");
    }
}

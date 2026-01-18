//! Benchmarks for logging configuration and operations.

use chie_core::logging::{LogConfig, LogLevel, Logger};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_log_config_creation(c: &mut Criterion) {
    c.bench_function("log_config_default", |b| {
        b.iter(|| black_box(LogConfig::default()));
    });

    c.bench_function("log_config_new", |b| {
        b.iter(|| black_box(LogConfig::new(LogLevel::Info)));
    });

    c.bench_function("log_config_minimal", |b| {
        b.iter(|| black_box(LogConfig::minimal(LogLevel::Debug)));
    });

    c.bench_function("log_config_verbose", |b| {
        b.iter(|| black_box(LogConfig::verbose(LogLevel::Trace)));
    });
}

fn bench_log_config_builder(c: &mut Criterion) {
    c.bench_function("log_config_with_filter_single", |b| {
        b.iter(|| {
            black_box(LogConfig::default().with_module_filter("chie_core::storage".to_string()))
        });
    });

    c.bench_function("log_config_with_filter_multiple", |b| {
        b.iter(|| {
            black_box(
                LogConfig::default()
                    .with_module_filter("chie_core::storage".to_string())
                    .with_module_filter("chie_core::network".to_string())
                    .with_module_filter("chie_core::cache".to_string()),
            )
        });
    });
}

fn bench_logger_creation(c: &mut Criterion) {
    let config = LogConfig::default();

    c.bench_function("logger_new", |b| {
        b.iter(|| {
            black_box(Logger::new(config.clone()));
        });
    });

    c.bench_function("logger_default_config", |b| {
        b.iter(|| black_box(Logger::default_config()));
    });
}

fn bench_logger_level_operations(c: &mut Criterion) {
    c.bench_function("logger_level_get", |b| {
        let logger = Logger::default_config();
        b.iter(|| black_box(logger.level()));
    });

    c.bench_function("logger_set_level", |b| {
        b.iter(|| {
            let mut logger = Logger::default_config();
            logger.set_level(black_box(LogLevel::Debug));
            black_box(logger);
        });
    });

    c.bench_function("logger_set_color", |b| {
        b.iter(|| {
            let mut logger = Logger::default_config();
            logger.set_color(black_box(true));
            black_box(logger);
        });
    });
}

fn bench_log_level_operations(c: &mut Criterion) {
    c.bench_function("log_level_as_str", |b| {
        let level = LogLevel::Info;
        b.iter(|| black_box(level.as_str()));
    });

    c.bench_function("log_level_colored", |b| {
        let level = LogLevel::Error;
        b.iter(|| black_box(level.colored()));
    });

    c.bench_function("log_level_should_log", |b| {
        let level = LogLevel::Debug;
        let configured = LogLevel::Info;
        b.iter(|| black_box(level.should_log(&configured)));
    });

    c.bench_function("log_level_to_string", |b| {
        let level = LogLevel::Warn;
        b.iter(|| black_box(level.to_string()));
    });
}

fn bench_logging_operations(c: &mut Criterion) {
    let logger = Logger::new(LogConfig::minimal(LogLevel::Trace));

    c.bench_function("logger_error", |b| {
        b.iter(|| {
            logger.error(
                black_box("chie_core::test"),
                black_box("Test error message"),
            );
        });
    });

    c.bench_function("logger_warn", |b| {
        b.iter(|| {
            logger.warn(black_box("chie_core::test"), black_box("Test warning"));
        });
    });

    c.bench_function("logger_info", |b| {
        b.iter(|| {
            logger.info(black_box("chie_core::test"), black_box("Test info"));
        });
    });

    c.bench_function("logger_debug", |b| {
        b.iter(|| {
            logger.debug(black_box("chie_core::test"), black_box("Test debug"));
        });
    });

    c.bench_function("logger_trace", |b| {
        b.iter(|| {
            logger.trace(black_box("chie_core::test"), black_box("Test trace"));
        });
    });
}

fn bench_logging_with_line_numbers(c: &mut Criterion) {
    let logger = Logger::new(LogConfig::verbose(LogLevel::Trace));

    c.bench_function("logger_error_at", |b| {
        b.iter(|| {
            logger.error_at(
                black_box("chie_core::test"),
                black_box("Error at line"),
                black_box(42),
            );
        });
    });

    c.bench_function("logger_warn_at", |b| {
        b.iter(|| {
            logger.warn_at(
                black_box("chie_core::test"),
                black_box("Warning at line"),
                black_box(100),
            );
        });
    });
}

fn bench_structured_logging(c: &mut Criterion) {
    let logger = Logger::default_config();

    c.bench_function("logger_structured_no_fields", |b| {
        b.iter(|| {
            logger.structured(
                LogLevel::Info,
                black_box("chie_core::test"),
                black_box("Structured message"),
                black_box(&[]),
            );
        });
    });

    c.bench_function("logger_structured_single_field", |b| {
        b.iter(|| {
            logger.structured(
                LogLevel::Info,
                black_box("chie_core::test"),
                black_box("Structured message"),
                black_box(&[("key1", "value1")]),
            );
        });
    });

    c.bench_function("logger_structured_multiple_fields", |b| {
        b.iter(|| {
            logger.structured(
                LogLevel::Info,
                black_box("chie_core::test"),
                black_box("Structured message"),
                black_box(&[
                    ("key1", "value1"),
                    ("key2", "value2"),
                    ("key3", "value3"),
                    ("key4", "value4"),
                ]),
            );
        });
    });

    c.bench_function("logger_perf", |b| {
        b.iter(|| {
            logger.perf(
                black_box("chie_core::storage"),
                black_box("chunk_read"),
                black_box(15),
            );
        });
    });
}

fn bench_module_filtering(c: &mut Criterion) {
    let config_no_filter = LogConfig::default();
    let logger_no_filter = Logger::new(config_no_filter);

    c.bench_function("logger_no_filter_match", |b| {
        b.iter(|| {
            logger_no_filter.info(black_box("chie_core::storage"), black_box("Test message"));
        });
    });

    let config_with_filter = LogConfig::default()
        .with_module_filter("chie_core::storage".to_string())
        .with_module_filter("chie_core::cache".to_string());
    let logger_with_filter = Logger::new(config_with_filter);

    c.bench_function("logger_with_filter_match", |b| {
        b.iter(|| {
            logger_with_filter.info(black_box("chie_core::storage"), black_box("Test message"));
        });
    });

    c.bench_function("logger_with_filter_no_match", |b| {
        b.iter(|| {
            logger_with_filter.info(black_box("chie_core::network"), black_box("Test message"));
        });
    });
}

fn bench_logging_different_levels(c: &mut Criterion) {
    // Logger configured at Info level (Debug and Trace should be filtered)
    let logger = Logger::new(LogConfig::new(LogLevel::Info));

    c.bench_function("logger_above_threshold_error", |b| {
        b.iter(|| {
            logger.error(black_box("chie_core::test"), black_box("Error message"));
        });
    });

    c.bench_function("logger_at_threshold_info", |b| {
        b.iter(|| {
            logger.info(black_box("chie_core::test"), black_box("Info message"));
        });
    });

    c.bench_function("logger_below_threshold_debug", |b| {
        b.iter(|| {
            logger.debug(black_box("chie_core::test"), black_box("Debug message"));
        });
    });

    c.bench_function("logger_below_threshold_trace", |b| {
        b.iter(|| {
            logger.trace(black_box("chie_core::test"), black_box("Trace message"));
        });
    });
}

criterion_group!(
    benches,
    bench_log_config_creation,
    bench_log_config_builder,
    bench_logger_creation,
    bench_logger_level_operations,
    bench_log_level_operations,
    bench_logging_operations,
    bench_logging_with_line_numbers,
    bench_structured_logging,
    bench_module_filtering,
    bench_logging_different_levels,
);
criterion_main!(benches);

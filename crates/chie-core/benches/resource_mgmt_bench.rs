use chie_core::resource_mgmt::{ResourceLimits, ResourceMonitor, ResourceType};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

/// Benchmark ResourceMonitor creation.
fn bench_resource_monitor_creation(c: &mut Criterion) {
    c.bench_function("resource_monitor_creation", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let monitor = ResourceMonitor::new(black_box(limits));
            black_box(monitor);
        });
    });
}

/// Benchmark ResourceMonitor creation with custom limits.
fn bench_resource_monitor_custom_creation(c: &mut Criterion) {
    c.bench_function("resource_monitor_custom_creation", |b| {
        b.iter(|| {
            let limits = ResourceLimits {
                max_cpu_percent: 90,
                max_memory_bytes: 8 * 1024 * 1024 * 1024, // 8 GB
                max_disk_io_bps: 500 * 1024 * 1024,       // 500 MB/s
                max_network_bps: 1024 * 1024 * 1024,      // 1 GB/s
                auto_throttle: true,
                throttle_threshold: 0.85,
            };
            let monitor = ResourceMonitor::new(black_box(limits));
            black_box(monitor);
        });
    });
}

/// Benchmark can_allocate checks.
fn bench_can_allocate(c: &mut Criterion) {
    let mut group = c.benchmark_group("resource_can_allocate");

    for &resource_type in &[
        ResourceType::Memory,
        ResourceType::DiskIo,
        ResourceType::NetworkBandwidth,
    ] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", resource_type)),
            &resource_type,
            |b, &rt| {
                b.iter(|| {
                    let limits = ResourceLimits::default();
                    let monitor = ResourceMonitor::new(limits);
                    let result = monitor.can_allocate(black_box(rt), black_box(1024 * 1024));
                    black_box(result);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark record_allocation operations.
fn bench_record_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("resource_record_allocation");

    for &size_mb in &[1, 10, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}MB", size_mb)),
            &(size_mb * 1024 * 1024),
            |b, &size| {
                b.iter(|| {
                    let limits = ResourceLimits::default();
                    let mut monitor = ResourceMonitor::new(limits);
                    monitor.record_allocation(black_box(ResourceType::Memory), black_box(size));
                    black_box(monitor);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark record_deallocation operations.
fn bench_record_deallocation(c: &mut Criterion) {
    c.bench_function("resource_record_deallocation", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);

            // Allocate first
            let size = 100 * 1024 * 1024; // 100 MB
            monitor.record_allocation(ResourceType::Memory, size);

            // Then deallocate
            monitor.record_deallocation(black_box(ResourceType::Memory), black_box(size));
            black_box(monitor);
        });
    });
}

/// Benchmark update_usage operations.
fn bench_update_usage(c: &mut Criterion) {
    c.bench_function("resource_update_usage", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);
            monitor.update_usage(
                black_box(ResourceType::Memory),
                black_box(2 * 1024 * 1024 * 1024), // 2 GB
            );
            black_box(monitor);
        });
    });
}

/// Benchmark is_throttled checks.
fn bench_is_throttled(c: &mut Criterion) {
    c.bench_function("resource_is_throttled", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let threshold_bytes = (limits.max_memory_bytes as f64 * 0.85) as u64;
            let mut monitor = ResourceMonitor::new(limits);

            // Push to threshold
            monitor.record_allocation(ResourceType::Memory, threshold_bytes);

            let result = monitor.is_throttled(black_box(ResourceType::Memory));
            black_box(result);
        });
    });
}

/// Benchmark get_stats queries.
fn bench_get_stats(c: &mut Criterion) {
    c.bench_function("resource_get_stats", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);
            monitor.record_allocation(ResourceType::Memory, 1024 * 1024 * 1024);
            let stats = monitor.get_stats(black_box(ResourceType::Memory));
            black_box(stats);
        });
    });
}

/// Benchmark get_all_stats queries.
fn bench_get_all_stats(c: &mut Criterion) {
    c.bench_function("resource_get_all_stats", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);

            // Record some allocations
            monitor.record_allocation(ResourceType::Memory, 1024 * 1024 * 1024);
            monitor.record_allocation(ResourceType::DiskIo, 50 * 1024 * 1024);
            monitor.record_allocation(ResourceType::NetworkBandwidth, 75 * 1024 * 1024);

            let all_stats = monitor.get_all_stats();
            black_box(all_stats);
        });
    });
}

/// Benchmark get_allocation_rate calculations.
fn bench_get_allocation_rate(c: &mut Criterion) {
    c.bench_function("resource_get_allocation_rate", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);

            // Record some allocations
            for _ in 0..10 {
                monitor.record_allocation(ResourceType::Memory, 10 * 1024 * 1024);
            }

            let rate = monitor.get_allocation_rate(
                black_box(ResourceType::Memory),
                black_box(Duration::from_secs(60)),
            );
            black_box(rate);
        });
    });
}

/// Benchmark health_score calculations.
fn bench_health_score(c: &mut Criterion) {
    c.bench_function("resource_health_score", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);

            // Simulate various resource usage
            monitor.update_usage(ResourceType::Cpu, 60);
            monitor.update_usage(ResourceType::Memory, 2 * 1024 * 1024 * 1024);
            monitor.update_usage(ResourceType::DiskIo, 50 * 1024 * 1024);
            monitor.update_usage(ResourceType::NetworkBandwidth, 60 * 1024 * 1024);

            let score = monitor.health_score();
            black_box(score);
        });
    });
}

/// Benchmark is_over_limit checks.
fn bench_is_over_limit(c: &mut Criterion) {
    c.bench_function("resource_is_over_limit", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);

            // Push memory usage high
            monitor.record_allocation(ResourceType::Memory, 5 * 1024 * 1024 * 1024); // 5 GB

            let result = monitor.is_over_limit();
            black_box(result);
        });
    });
}

/// Benchmark calculate_degradation_level.
fn bench_calculate_degradation_level(c: &mut Criterion) {
    let mut group = c.benchmark_group("resource_degradation_level");

    // Test different resource pressure scenarios
    let scenarios = vec![
        ("normal", 40),   // 40% CPU
        ("minor", 65),    // 65% CPU
        ("moderate", 75), // 75% CPU
        ("severe", 85),   // 85% CPU
        ("critical", 95), // 95% CPU
    ];

    for (name, cpu_percent) in scenarios {
        group.bench_with_input(
            BenchmarkId::from_parameter(name),
            &cpu_percent,
            |b, &cpu| {
                b.iter(|| {
                    let limits = ResourceLimits {
                        max_cpu_percent: 100,
                        ..ResourceLimits::default()
                    };
                    let mut monitor = ResourceMonitor::new(limits);
                    monitor.update_usage(ResourceType::Cpu, black_box(cpu));
                    let level = monitor.calculate_degradation_level();
                    black_box(level);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark update_degradation_level.
fn bench_update_degradation_level(c: &mut Criterion) {
    c.bench_function("resource_update_degradation_level", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);

            // Simulate high resource usage
            monitor.update_usage(ResourceType::Cpu, 85);
            monitor.update_usage(ResourceType::Memory, 3 * 1024 * 1024 * 1024);

            monitor.update_degradation_level();
            black_box(monitor);
        });
    });
}

/// Benchmark degradation_level query.
fn bench_degradation_level_query(c: &mut Criterion) {
    c.bench_function("resource_degradation_level_query", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);
            monitor.update_degradation_level();
            let level = monitor.degradation_level();
            black_box(level);
        });
    });
}

/// Benchmark should_accept_requests.
fn bench_should_accept_requests(c: &mut Criterion) {
    c.bench_function("resource_should_accept_requests", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);
            monitor.update_degradation_level();
            let result = monitor.should_accept_requests();
            black_box(result);
        });
    });
}

/// Benchmark should_run_background_tasks.
fn bench_should_run_background_tasks(c: &mut Criterion) {
    c.bench_function("resource_should_run_background_tasks", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);
            monitor.update_degradation_level();
            let result = monitor.should_run_background_tasks();
            black_box(result);
        });
    });
}

/// Benchmark recommended_cache_size calculations.
fn bench_recommended_cache_size(c: &mut Criterion) {
    c.bench_function("resource_recommended_cache_size", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);
            monitor.update_usage(ResourceType::Memory, 2 * 1024 * 1024 * 1024);
            monitor.update_degradation_level();
            let size = monitor.recommended_cache_size(black_box(1000));
            black_box(size);
        });
    });
}

/// Benchmark recommended_concurrency calculations.
fn bench_recommended_concurrency(c: &mut Criterion) {
    c.bench_function("resource_recommended_concurrency", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);
            monitor.update_usage(ResourceType::Cpu, 70);
            monitor.update_degradation_level();
            let concurrency = monitor.recommended_concurrency(black_box(10));
            black_box(concurrency);
        });
    });
}

/// Benchmark cleanup_old_records.
fn bench_cleanup_old_records(c: &mut Criterion) {
    c.bench_function("resource_cleanup_old_records", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);

            // Create many allocation records
            for _ in 0..100 {
                monitor.record_allocation(ResourceType::Memory, 1024 * 1024);
            }

            monitor.cleanup_old_records(black_box(Duration::from_secs(3600)));
            black_box(monitor);
        });
    });
}

/// Benchmark reset_stats.
fn bench_reset_stats(c: &mut Criterion) {
    c.bench_function("resource_reset_stats", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);

            // Record some stats
            monitor.record_allocation(ResourceType::Memory, 1024 * 1024 * 1024);
            monitor.record_allocation(ResourceType::DiskIo, 50 * 1024 * 1024);

            monitor.reset_stats();
            black_box(monitor);
        });
    });
}

/// Benchmark realistic scenario: web server resource tracking.
fn bench_realistic_web_server(c: &mut Criterion) {
    c.bench_function("resource_realistic_web_server", |b| {
        b.iter(|| {
            let limits = ResourceLimits::default();
            let mut monitor = ResourceMonitor::new(limits);

            // Simulate web server handling requests
            for i in 0..100 {
                // Each request allocates memory
                if monitor.can_allocate(ResourceType::Memory, 10 * 1024 * 1024) {
                    monitor.record_allocation(ResourceType::Memory, 10 * 1024 * 1024);
                }

                // Network bandwidth usage
                monitor.update_usage(ResourceType::NetworkBandwidth, (i % 50) * 1024 * 1024);

                // Check if throttling needed
                if monitor.is_throttled(ResourceType::Memory) {
                    // Would trigger graceful degradation
                }
            }

            // Update degradation level
            monitor.update_degradation_level();

            // Check if can accept more requests
            let can_accept = monitor.should_accept_requests();
            let health = monitor.health_score();

            black_box((can_accept, health, monitor));
        });
    });
}

/// Benchmark realistic scenario: video processing with resource limits.
fn bench_realistic_video_processing(c: &mut Criterion) {
    c.bench_function("resource_realistic_video_processing", |b| {
        b.iter(|| {
            let limits = ResourceLimits {
                max_cpu_percent: 90,
                max_memory_bytes: 8 * 1024 * 1024 * 1024,
                max_disk_io_bps: 500 * 1024 * 1024,
                ..ResourceLimits::default()
            };
            let mut monitor = ResourceMonitor::new(limits);

            // Simulate video processing job
            // 1. Check resources
            let can_start = monitor.can_allocate(ResourceType::Memory, 2 * 1024 * 1024 * 1024);

            if can_start {
                // 2. Allocate memory for video buffer
                monitor.record_allocation(ResourceType::Memory, 2 * 1024 * 1024 * 1024);

                // 3. Update CPU usage (high during processing)
                monitor.update_usage(ResourceType::Cpu, 85);

                // 4. Update disk I/O (reading/writing video)
                monitor.update_usage(ResourceType::DiskIo, 400 * 1024 * 1024);

                // 5. Check degradation level
                monitor.update_degradation_level();
                let level = monitor.degradation_level();

                // 6. Adjust concurrency based on resources
                let concurrency = monitor.recommended_concurrency(8);

                black_box((level, concurrency));
            }

            black_box(monitor);
        });
    });
}

criterion_group!(
    benches,
    bench_resource_monitor_creation,
    bench_resource_monitor_custom_creation,
    bench_can_allocate,
    bench_record_allocation,
    bench_record_deallocation,
    bench_update_usage,
    bench_is_throttled,
    bench_get_stats,
    bench_get_all_stats,
    bench_get_allocation_rate,
    bench_health_score,
    bench_is_over_limit,
    bench_calculate_degradation_level,
    bench_update_degradation_level,
    bench_degradation_level_query,
    bench_should_accept_requests,
    bench_should_run_background_tasks,
    bench_recommended_cache_size,
    bench_recommended_concurrency,
    bench_cleanup_old_records,
    bench_reset_stats,
    bench_realistic_web_server,
    bench_realistic_video_processing,
);
criterion_main!(benches);

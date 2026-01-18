//! Benchmarks for graceful degradation operations.
//!
//! Measures performance of:
//! - Degradation manager creation and updates
//! - Pressure score calculation
//! - Degradation level determination
//! - Action queries and decision making

use chie_core::degradation::{
    DegradationActions, DegradationManager, ResourcePressure, ServiceDegradationLevel,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;

/// Benchmark creating degradation managers.
fn bench_manager_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("manager_creation");

    group.bench_function("new_manager", |b| {
        b.iter(|| {
            let manager = DegradationManager::new();
            black_box(manager)
        });
    });

    group.bench_function("default_manager", |b| {
        b.iter(|| {
            let manager = DegradationManager::default();
            black_box(manager)
        });
    });

    group.finish();
}

/// Benchmark resource pressure calculations.
fn bench_pressure_calculations(c: &mut Criterion) {
    let mut group = c.benchmark_group("pressure_calculations");

    let pressures = vec![
        (
            "low_pressure",
            ResourcePressure {
                cpu_usage: 0.3,
                memory_usage: 0.4,
                disk_usage: 0.3,
                bandwidth_usage: 0.2,
            },
        ),
        (
            "moderate_pressure",
            ResourcePressure {
                cpu_usage: 0.7,
                memory_usage: 0.7,
                disk_usage: 0.6,
                bandwidth_usage: 0.5,
            },
        ),
        (
            "high_pressure",
            ResourcePressure {
                cpu_usage: 0.9,
                memory_usage: 0.9,
                disk_usage: 0.9,
                bandwidth_usage: 0.8,
            },
        ),
    ];

    for (name, pressure) in pressures {
        group.bench_function(format!("{}_overall_score", name), |b| {
            b.iter(|| {
                let score = pressure.overall_score();
                black_box(score)
            });
        });

        group.bench_function(format!("{}_critical_check", name), |b| {
            b.iter(|| {
                let critical = pressure.has_critical_resource();
                black_box(critical)
            });
        });
    }

    group.finish();
}

/// Benchmark degradation level determination.
fn bench_level_determination(c: &mut Criterion) {
    let mut group = c.benchmark_group("level_determination");

    let scores = vec![
        ("normal", 0.5),
        ("light", 0.75),
        ("moderate", 0.85),
        ("severe", 0.95),
    ];

    for (name, score) in scores {
        group.bench_function(name, |b| {
            b.iter(|| {
                let level = ServiceDegradationLevel::from_pressure_score(black_box(score));
                black_box(level)
            });
        });
    }

    group.finish();
}

/// Benchmark degradation level methods.
fn bench_level_methods(c: &mut Criterion) {
    let mut group = c.benchmark_group("level_methods");

    let levels = vec![
        ServiceDegradationLevel::Normal,
        ServiceDegradationLevel::LightDegradation,
        ServiceDegradationLevel::ModerateDegradation,
        ServiceDegradationLevel::SevereDegradation,
    ];

    for level in levels {
        let name = format!("{:?}", level);

        group.bench_function(format!("{}_description", name), |b| {
            b.iter(|| {
                let desc = level.description();
                black_box(desc)
            });
        });

        group.bench_function(format!("{}_is_degraded", name), |b| {
            b.iter(|| {
                let degraded = level.is_degraded();
                black_box(degraded)
            });
        });
    }

    group.finish();
}

/// Benchmark degradation actions.
fn bench_degradation_actions(c: &mut Criterion) {
    let mut group = c.benchmark_group("degradation_actions");

    let levels = vec![
        ("normal", ServiceDegradationLevel::Normal),
        ("light", ServiceDegradationLevel::LightDegradation),
        ("moderate", ServiceDegradationLevel::ModerateDegradation),
        ("severe", ServiceDegradationLevel::SevereDegradation),
    ];

    for (name, level) in levels {
        group.bench_function(format!("{}_actions", name), |b| {
            b.iter(|| {
                let actions = DegradationActions::for_level(black_box(level));
                black_box(actions)
            });
        });
    }

    group.finish();
}

/// Benchmark updating pressure.
fn bench_update_pressure(c: &mut Criterion) {
    let mut group = c.benchmark_group("update_pressure");

    let pressures = vec![
        (
            "low",
            ResourcePressure {
                cpu_usage: 0.3,
                memory_usage: 0.3,
                disk_usage: 0.3,
                bandwidth_usage: 0.3,
            },
        ),
        (
            "high",
            ResourcePressure {
                cpu_usage: 0.9,
                memory_usage: 0.9,
                disk_usage: 0.9,
                bandwidth_usage: 0.9,
            },
        ),
    ];

    for (name, pressure) in pressures {
        group.bench_function(name, |b| {
            let mut manager = DegradationManager::new();

            b.iter(|| {
                manager.update_pressure(black_box(pressure));
            });
        });
    }

    group.finish();
}

/// Benchmark multiple pressure updates.
fn bench_multiple_updates(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiple_updates");

    let counts = vec![10, 100, 1000];

    for count in counts {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_updates", count)),
            &count,
            |b, &count| {
                b.iter(|| {
                    let mut manager = DegradationManager::new();

                    for i in 0..count {
                        let usage = (i as f64 / count as f64) * 0.9; // Ramp up from 0 to 0.9
                        let pressure = ResourcePressure {
                            cpu_usage: usage,
                            memory_usage: usage * 0.9,
                            disk_usage: usage * 0.8,
                            bandwidth_usage: usage * 0.7,
                        };
                        manager.update_pressure(black_box(pressure));
                    }

                    black_box(manager)
                });
            },
        );
    }

    group.finish();
}

/// Benchmark current level queries.
fn bench_current_level(c: &mut Criterion) {
    let mut group = c.benchmark_group("current_level");

    group.bench_function("get_level", |b| {
        let manager = DegradationManager::new();

        b.iter(|| {
            let level = manager.current_level();
            black_box(level)
        });
    });

    group.finish();
}

/// Benchmark current pressure queries.
fn bench_current_pressure(c: &mut Criterion) {
    let mut group = c.benchmark_group("current_pressure");

    group.bench_function("get_pressure", |b| {
        let mut manager = DegradationManager::new();
        manager.update_pressure(ResourcePressure {
            cpu_usage: 0.7,
            memory_usage: 0.7,
            disk_usage: 0.7,
            bandwidth_usage: 0.7,
        });

        b.iter(|| {
            let pressure = manager.current_pressure();
            black_box(pressure)
        });
    });

    group.finish();
}

/// Benchmark action queries.
fn bench_action_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("action_queries");

    let mut manager = DegradationManager::new();
    manager.update_pressure(ResourcePressure {
        cpu_usage: 0.9,
        memory_usage: 0.9,
        disk_usage: 0.9,
        bandwidth_usage: 0.9,
    });

    group.bench_function("get_actions", |b| {
        b.iter(|| {
            let actions = manager.get_actions();
            black_box(actions)
        });
    });

    group.bench_function("should_disable_prefetching", |b| {
        b.iter(|| {
            let should_disable = manager.should_disable_prefetching();
            black_box(should_disable)
        });
    });

    group.bench_function("should_reduce_cache_size", |b| {
        b.iter(|| {
            let should_reduce = manager.should_reduce_cache_size();
            black_box(should_reduce)
        });
    });

    group.bench_function("should_disable_analytics", |b| {
        b.iter(|| {
            let should_disable = manager.should_disable_analytics();
            black_box(should_disable)
        });
    });

    group.bench_function("should_throttle_bandwidth", |b| {
        b.iter(|| {
            let should_throttle = manager.should_throttle_bandwidth();
            black_box(should_throttle)
        });
    });

    group.bench_function("should_pause_gc", |b| {
        b.iter(|| {
            let should_pause = manager.should_pause_gc();
            black_box(should_pause)
        });
    });

    group.bench_function("should_reject_new_pins", |b| {
        b.iter(|| {
            let should_reject = manager.should_reject_new_pins();
            black_box(should_reject)
        });
    });

    group.finish();
}

/// Benchmark time-based queries.
fn bench_time_queries(c: &mut Criterion) {
    let mut group = c.benchmark_group("time_queries");

    let mut manager = DegradationManager::new();
    manager.update_pressure(ResourcePressure::default());

    group.bench_function("time_since_update", |b| {
        b.iter(|| {
            let time = manager.time_since_update();
            black_box(time)
        });
    });

    group.bench_function("average_pressure_1min", |b| {
        b.iter(|| {
            let avg = manager.average_pressure_score(black_box(Duration::from_secs(60)));
            black_box(avg)
        });
    });

    group.bench_function("average_pressure_5min", |b| {
        b.iter(|| {
            let avg = manager.average_pressure_score(black_box(Duration::from_secs(300)));
            black_box(avg)
        });
    });

    group.finish();
}

/// Benchmark realistic degradation scenarios.
fn bench_realistic_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_scenarios");

    group.bench_function("gradual_pressure_increase", |b| {
        b.iter(|| {
            let mut manager = DegradationManager::new();

            // Simulate gradual pressure increase
            for i in 0..50 {
                let usage = (i as f64 / 50.0) * 0.95;
                manager.update_pressure(ResourcePressure {
                    cpu_usage: usage,
                    memory_usage: usage,
                    disk_usage: usage,
                    bandwidth_usage: usage,
                });
            }

            black_box(manager)
        });
    });

    group.bench_function("pressure_spike_and_recovery", |b| {
        b.iter(|| {
            let mut manager = DegradationManager::new();

            // Normal operation
            for _ in 0..10 {
                manager.update_pressure(ResourcePressure {
                    cpu_usage: 0.5,
                    memory_usage: 0.5,
                    disk_usage: 0.5,
                    bandwidth_usage: 0.5,
                });
            }

            // Spike
            for _ in 0..5 {
                manager.update_pressure(ResourcePressure {
                    cpu_usage: 0.95,
                    memory_usage: 0.95,
                    disk_usage: 0.95,
                    bandwidth_usage: 0.95,
                });
            }

            // Recovery
            for _ in 0..10 {
                manager.update_pressure(ResourcePressure {
                    cpu_usage: 0.5,
                    memory_usage: 0.5,
                    disk_usage: 0.5,
                    bandwidth_usage: 0.5,
                });
            }

            black_box(manager)
        });
    });

    group.bench_function("decision_making_loop", |b| {
        let mut manager = DegradationManager::new();
        manager.update_pressure(ResourcePressure {
            cpu_usage: 0.85,
            memory_usage: 0.85,
            disk_usage: 0.85,
            bandwidth_usage: 0.85,
        });

        b.iter(|| {
            // Simulate checking all degradation actions in a hot loop
            let disable_prefetch = manager.should_disable_prefetching();
            let reduce_cache = manager.should_reduce_cache_size();
            let disable_analytics = manager.should_disable_analytics();
            let throttle_bw = manager.should_throttle_bandwidth();
            let pause_gc = manager.should_pause_gc();
            let reject_pins = manager.should_reject_new_pins();

            black_box((
                disable_prefetch,
                reduce_cache,
                disable_analytics,
                throttle_bw,
                pause_gc,
                reject_pins,
            ))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_manager_creation,
    bench_pressure_calculations,
    bench_level_determination,
    bench_level_methods,
    bench_degradation_actions,
    bench_update_pressure,
    bench_multiple_updates,
    bench_current_level,
    bench_current_pressure,
    bench_action_queries,
    bench_time_queries,
    bench_realistic_scenarios,
);
criterion_main!(benches);

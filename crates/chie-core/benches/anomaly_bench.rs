#![allow(clippy::unit_arg)]

use chie_core::anomaly::{AnomalyDetector, AnomalyType, BehaviorSample, DetectionConfig};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::{Duration, SystemTime};

fn bench_detector_creation(c: &mut Criterion) {
    c.bench_function("anomaly_detector_new", |b| {
        b.iter(|| {
            let config = DetectionConfig::default();
            black_box(AnomalyDetector::new(black_box(config)))
        })
    });
}

fn bench_record_sample_new_peer(c: &mut Criterion) {
    c.bench_function("record_sample_new_peer", |b| {
        let mut detector = AnomalyDetector::new(DetectionConfig::default());
        let mut counter = 0u64;

        b.iter(|| {
            let peer_id = format!("peer_{}", counter);
            counter += 1;
            let sample = BehaviorSample {
                value: 1000.0,
                timestamp: SystemTime::now(),
                metric_type: "bandwidth".to_string(),
            };
            black_box(detector.record_sample(black_box(&peer_id), black_box(sample)))
        })
    });
}

fn bench_record_sample_existing_peer(c: &mut Criterion) {
    let mut detector = AnomalyDetector::new(DetectionConfig::default());
    let peer_id = "test_peer";

    // Pre-populate with normal samples
    for i in 0..50 {
        let sample = BehaviorSample {
            value: 1000.0 + i as f64 * 10.0,
            timestamp: SystemTime::now(),
            metric_type: "bandwidth".to_string(),
        };
        detector.record_sample(peer_id, sample);
    }

    c.bench_function("record_sample_existing_peer", |b| {
        b.iter(|| {
            let sample = BehaviorSample {
                value: 1050.0,
                timestamp: SystemTime::now(),
                metric_type: "bandwidth".to_string(),
            };
            black_box(detector.record_sample(black_box(peer_id), black_box(sample)))
        })
    });
}

fn bench_is_anomalous(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_anomalous");

    for peer_count in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(peer_count),
            peer_count,
            |b, &count| {
                let mut detector = AnomalyDetector::new(DetectionConfig::default());

                // Setup: Add normal samples for multiple peers
                for i in 0..count {
                    let peer_id = format!("peer_{}", i);
                    for j in 0..40 {
                        let sample = BehaviorSample {
                            value: 1000.0 + j as f64 * 10.0,
                            timestamp: SystemTime::now(),
                            metric_type: "bandwidth".to_string(),
                        };
                        detector.record_sample(&peer_id, sample);
                    }
                }

                b.iter(|| {
                    let sample = BehaviorSample {
                        value: 10000.0, // Anomaly value
                        timestamp: SystemTime::now(),
                        metric_type: "bandwidth".to_string(),
                    };
                    black_box(detector.is_anomalous(black_box("peer_0"), black_box(&sample)))
                })
            },
        );
    }

    group.finish();
}

fn bench_get_peer_anomalies(c: &mut Criterion) {
    let mut detector = AnomalyDetector::new(DetectionConfig::default());

    // Setup: Add anomalies for multiple peers
    for i in 0..10 {
        let peer_id = format!("peer_{}", i);
        for j in 0..40 {
            let sample = BehaviorSample {
                value: 1000.0 + j as f64 * 10.0,
                timestamp: SystemTime::now(),
                metric_type: "bandwidth".to_string(),
            };
            detector.record_sample(&peer_id, sample);
        }
        // Add anomaly
        let anomaly_sample = BehaviorSample {
            value: 10000.0,
            timestamp: SystemTime::now(),
            metric_type: "bandwidth".to_string(),
        };
        let _ = detector.is_anomalous(&peer_id, &anomaly_sample);
    }

    c.bench_function("get_peer_anomalies", |b| {
        b.iter(|| black_box(detector.get_peer_anomalies(black_box("peer_0"))))
    });
}

fn bench_get_recent_anomalies(c: &mut Criterion) {
    let mut detector = AnomalyDetector::new(DetectionConfig::default());

    // Setup: Add anomalies
    for i in 0..50 {
        let peer_id = format!("peer_{}", i);
        for j in 0..40 {
            let sample = BehaviorSample {
                value: 1000.0 + j as f64 * 10.0,
                timestamp: SystemTime::now(),
                metric_type: "bandwidth".to_string(),
            };
            detector.record_sample(&peer_id, sample);
        }
        // Add anomaly
        let anomaly_sample = BehaviorSample {
            value: 10000.0,
            timestamp: SystemTime::now(),
            metric_type: "bandwidth".to_string(),
        };
        let _ = detector.is_anomalous(&peer_id, &anomaly_sample);
    }

    c.bench_function("get_recent_anomalies", |b| {
        b.iter(|| black_box(detector.get_recent_anomalies(black_box(20))))
    });
}

fn bench_get_anomalies_by_type(c: &mut Criterion) {
    let mut detector = AnomalyDetector::new(DetectionConfig::default());

    // Setup: Add anomalies
    for i in 0..30 {
        let peer_id = format!("peer_{}", i);
        for j in 0..40 {
            let sample = BehaviorSample {
                value: 1000.0 + j as f64 * 10.0,
                timestamp: SystemTime::now(),
                metric_type: "bandwidth".to_string(),
            };
            detector.record_sample(&peer_id, sample);
        }
        // Add anomaly
        let anomaly_sample = BehaviorSample {
            value: 10000.0,
            timestamp: SystemTime::now(),
            metric_type: "bandwidth".to_string(),
        };
        let _ = detector.is_anomalous(&peer_id, &anomaly_sample);
    }

    c.bench_function("get_anomalies_by_type", |b| {
        b.iter(|| {
            black_box(detector.get_anomalies_by_type(black_box(AnomalyType::StatisticalOutlier)))
        })
    });
}

fn bench_get_statistics(c: &mut Criterion) {
    let mut detector = AnomalyDetector::new(DetectionConfig::default());

    // Setup: Add data
    for i in 0..100 {
        let peer_id = format!("peer_{}", i);
        for j in 0..40 {
            let sample = BehaviorSample {
                value: 1000.0 + j as f64 * 10.0,
                timestamp: SystemTime::now(),
                metric_type: "bandwidth".to_string(),
            };
            detector.record_sample(&peer_id, sample);
        }
        // Add anomaly
        let anomaly_sample = BehaviorSample {
            value: 10000.0,
            timestamp: SystemTime::now(),
            metric_type: "bandwidth".to_string(),
        };
        let _ = detector.is_anomalous(&peer_id, &anomaly_sample);
    }

    c.bench_function("get_statistics", |b| {
        b.iter(|| black_box(detector.get_statistics()))
    });
}

fn bench_has_recent_anomalies(c: &mut Criterion) {
    let mut detector = AnomalyDetector::new(DetectionConfig::default());

    // Setup: Add anomalies
    for i in 0..50 {
        let peer_id = format!("peer_{}", i);
        for j in 0..40 {
            let sample = BehaviorSample {
                value: 1000.0 + j as f64 * 10.0,
                timestamp: SystemTime::now(),
                metric_type: "bandwidth".to_string(),
            };
            detector.record_sample(&peer_id, sample);
        }
        // Add anomaly
        let anomaly_sample = BehaviorSample {
            value: 10000.0,
            timestamp: SystemTime::now(),
            metric_type: "bandwidth".to_string(),
        };
        let _ = detector.is_anomalous(&peer_id, &anomaly_sample);
    }

    c.bench_function("has_recent_anomalies", |b| {
        b.iter(|| {
            black_box(
                detector.has_recent_anomalies(
                    black_box("peer_0"),
                    black_box(Duration::from_secs(3600)),
                ),
            )
        })
    });
}

fn bench_get_anomaly_rate(c: &mut Criterion) {
    let mut detector = AnomalyDetector::new(DetectionConfig::default());

    // Setup: Add samples and anomalies
    let peer_id = "test_peer";
    for j in 0..100 {
        let sample = BehaviorSample {
            value: 1000.0 + (j % 50) as f64 * 10.0,
            timestamp: SystemTime::now(),
            metric_type: "bandwidth".to_string(),
        };
        detector.record_sample(peer_id, sample.clone());

        // Every 10th is anomaly
        if j % 10 == 0 {
            let anomaly_sample = BehaviorSample {
                value: 10000.0,
                timestamp: SystemTime::now(),
                metric_type: "bandwidth".to_string(),
            };
            let _ = detector.is_anomalous(peer_id, &anomaly_sample);
        }
    }

    c.bench_function("get_anomaly_rate", |b| {
        b.iter(|| black_box(detector.get_anomaly_rate(black_box(peer_id))))
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    c.bench_function("mixed_operations", |b| {
        let mut detector = AnomalyDetector::new(DetectionConfig::default());
        let mut counter = 0u64;

        b.iter(|| {
            let peer_id = format!("peer_{}", counter % 10);
            counter += 1;

            // Record sample
            let sample = BehaviorSample {
                value: 1000.0 + (counter % 100) as f64,
                timestamp: SystemTime::now(),
                metric_type: "bandwidth".to_string(),
            };
            detector.record_sample(&peer_id, sample.clone());

            // Occasionally check for anomaly
            if counter % 5 == 0 {
                let _ = detector.is_anomalous(&peer_id, &sample);
            }

            // Occasionally query
            if counter % 10 == 0 {
                let _ = detector.get_peer_anomalies(&peer_id);
            }

            black_box(())
        })
    });
}

criterion_group!(
    benches,
    bench_detector_creation,
    bench_record_sample_new_peer,
    bench_record_sample_existing_peer,
    bench_is_anomalous,
    bench_get_peer_anomalies,
    bench_get_recent_anomalies,
    bench_get_anomalies_by_type,
    bench_get_statistics,
    bench_has_recent_anomalies,
    bench_get_anomaly_rate,
    bench_mixed_operations,
);
criterion_main!(benches);

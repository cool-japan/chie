use chie_core::{ContentNode, NodeConfig, PinnedContent};
use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use std::path::PathBuf;

fn bench_node_config_creation(c: &mut Criterion) {
    c.bench_function("node_config_new", |b| {
        b.iter(|| {
            let config = NodeConfig {
                max_storage_bytes: black_box(50 * 1024 * 1024 * 1024),
                max_bandwidth_bps: black_box(100 * 1024 * 1024 / 8),
                coordinator_url: black_box("https://coordinator.chie.network".to_string()),
                storage_path: black_box(PathBuf::from("/tmp/chie-storage")),
            };
            black_box(config);
        });
    });

    c.bench_function("node_config_default", |b| {
        b.iter(|| {
            let config = NodeConfig::default();
            black_box(config);
        });
    });
}

fn bench_node_config_operations(c: &mut Criterion) {
    let config = NodeConfig::default();

    c.bench_function("node_config_clone", |b| {
        b.iter(|| {
            let cloned = config.clone();
            black_box(cloned);
        });
    });
}

fn bench_pinned_content_creation(c: &mut Criterion) {
    c.bench_function("node_pinned_content_new", |b| {
        b.iter(|| {
            let content = PinnedContent {
                cid: black_box("QmTest123456789".to_string()),
                size_bytes: black_box(1024 * 1024),
                encryption_key: black_box([42u8; 32]),
                predicted_revenue_per_gb: black_box(10.0),
            };
            black_box(content);
        });
    });

    c.bench_function("node_pinned_content_clone", |b| {
        let content = PinnedContent {
            cid: "QmTest123".to_string(),
            size_bytes: 1024,
            encryption_key: [0u8; 32],
            predicted_revenue_per_gb: 10.0,
        };
        b.iter(|| {
            let cloned = content.clone();
            black_box(cloned);
        });
    });
}

fn bench_content_node_creation(c: &mut Criterion) {
    c.bench_function("node_content_node_new", |b| {
        b.iter(|| {
            let config = NodeConfig::default();
            let node = ContentNode::new(config);
            black_box(node);
        });
    });

    c.bench_function("node_content_node_new_custom", |b| {
        b.iter(|| {
            let config = NodeConfig {
                max_storage_bytes: 100 * 1024 * 1024 * 1024,
                max_bandwidth_bps: 1000 * 1024 * 1024 / 8,
                coordinator_url: "https://test.example.com".to_string(),
                storage_path: PathBuf::from("/custom/path"),
            };
            let node = ContentNode::new(config);
            black_box(node);
        });
    });
}

fn bench_content_node_accessors(c: &mut Criterion) {
    let config = NodeConfig::default();
    let node = ContentNode::new(config);

    c.bench_function("node_public_key", |b| {
        b.iter(|| {
            let pk = node.public_key();
            black_box(pk);
        });
    });

    c.bench_function("node_earnings", |b| {
        b.iter(|| {
            let earnings = node.earnings();
            black_box(earnings);
        });
    });

    c.bench_function("node_config_getter", |b| {
        b.iter(|| {
            let cfg = node.config();
            black_box(cfg);
        });
    });

    c.bench_function("node_storage_getter", |b| {
        b.iter(|| {
            let storage = node.storage();
            black_box(storage);
        });
    });

    c.bench_function("node_pinned_count", |b| {
        b.iter(|| {
            let count = node.pinned_count();
            black_box(count);
        });
    });
}

fn bench_content_pinning_operations(c: &mut Criterion) {
    c.bench_function("node_pin_content_single", |b| {
        b.iter_batched(
            || {
                let config = NodeConfig::default();
                ContentNode::new(config)
            },
            |mut node| {
                let content = PinnedContent {
                    cid: "QmTest123".to_string(),
                    size_bytes: 1024,
                    encryption_key: [0u8; 32],
                    predicted_revenue_per_gb: 10.0,
                };
                node.pin_content(content);
                black_box(node);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("node_pin_content_multiple", |b| {
        b.iter_batched(
            || {
                let config = NodeConfig::default();
                ContentNode::new(config)
            },
            |mut node| {
                for i in 0..10 {
                    let content = PinnedContent {
                        cid: format!("QmTest{}", i),
                        size_bytes: 1024 * (i + 1),
                        encryption_key: [i as u8; 32],
                        predicted_revenue_per_gb: 10.0 + i as f64,
                    };
                    node.pin_content(content);
                }
                black_box(node);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_content_operations(c: &mut Criterion) {
    c.bench_function("node_has_content_hit", |b| {
        b.iter_batched(
            || {
                let config = NodeConfig::default();
                let mut node = ContentNode::new(config);
                let content = PinnedContent {
                    cid: "QmTest123".to_string(),
                    size_bytes: 1024,
                    encryption_key: [0u8; 32],
                    predicted_revenue_per_gb: 10.0,
                };
                node.pin_content(content);
                node
            },
            |node| {
                let has = node.has_content(&"QmTest123".to_string());
                black_box(has);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("node_has_content_miss", |b| {
        b.iter_batched(
            || {
                let config = NodeConfig::default();
                ContentNode::new(config)
            },
            |node| {
                let has = node.has_content(&"QmNonExistent".to_string());
                black_box(has);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("node_unpin_content", |b| {
        b.iter_batched(
            || {
                let config = NodeConfig::default();
                let mut node = ContentNode::new(config);
                let content = PinnedContent {
                    cid: "QmTest123".to_string(),
                    size_bytes: 1024,
                    encryption_key: [0u8; 32],
                    predicted_revenue_per_gb: 10.0,
                };
                node.pin_content(content);
                node
            },
            |mut node| {
                let result = node.unpin_content(&"QmTest123".to_string());
                black_box(result);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn bench_content_node_with_many_pins(c: &mut Criterion) {
    c.bench_function("node_pin_100_contents", |b| {
        b.iter_batched(
            || {
                let config = NodeConfig::default();
                ContentNode::new(config)
            },
            |mut node| {
                for i in 0..100 {
                    let content = PinnedContent {
                        cid: format!("QmTest{:06}", i),
                        size_bytes: 1024 * 1024,
                        encryption_key: [i as u8; 32],
                        predicted_revenue_per_gb: 10.0,
                    };
                    node.pin_content(content);
                }
                black_box(node);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("node_has_content_100_pins", |b| {
        b.iter_batched(
            || {
                let config = NodeConfig::default();
                let mut node = ContentNode::new(config);
                for i in 0..100 {
                    let content = PinnedContent {
                        cid: format!("QmTest{:06}", i),
                        size_bytes: 1024 * 1024,
                        encryption_key: [i as u8; 32],
                        predicted_revenue_per_gb: 10.0,
                    };
                    node.pin_content(content);
                }
                node
            },
            |node| {
                let has = node.has_content(&"QmTest000050".to_string());
                black_box(has);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("node_unpin_from_100", |b| {
        b.iter_batched(
            || {
                let config = NodeConfig::default();
                let mut node = ContentNode::new(config);
                for i in 0..100 {
                    let content = PinnedContent {
                        cid: format!("QmTest{:06}", i),
                        size_bytes: 1024 * 1024,
                        encryption_key: [i as u8; 32],
                        predicted_revenue_per_gb: 10.0,
                    };
                    node.pin_content(content);
                }
                node
            },
            |mut node| {
                let result = node.unpin_content(&"QmTest000050".to_string());
                black_box(result);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function("node_pinned_count_100", |b| {
        b.iter_batched(
            || {
                let config = NodeConfig::default();
                let mut node = ContentNode::new(config);
                for i in 0..100 {
                    let content = PinnedContent {
                        cid: format!("QmTest{:06}", i),
                        size_bytes: 1024 * 1024,
                        encryption_key: [i as u8; 32],
                        predicted_revenue_per_gb: 10.0,
                    };
                    node.pin_content(content);
                }
                node
            },
            |node| {
                let count = node.pinned_count();
                black_box(count);
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    benches,
    bench_node_config_creation,
    bench_node_config_operations,
    bench_pinned_content_creation,
    bench_content_node_creation,
    bench_content_node_accessors,
    bench_content_pinning_operations,
    bench_content_operations,
    bench_content_node_with_many_pins,
);
criterion_main!(benches);

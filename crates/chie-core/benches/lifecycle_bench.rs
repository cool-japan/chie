use chie_core::lifecycle::{ContentEvent, LifecycleEventManager, LifecycleEventType};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use tokio::runtime::Runtime;

/// Helper to create a simple event.
fn create_simple_event(cid: &str, event_type: LifecycleEventType) -> ContentEvent {
    ContentEvent::simple(cid.to_string(), event_type)
}

/// Helper to create an event with size.
fn create_event_with_size(cid: &str, event_type: LifecycleEventType, size: u64) -> ContentEvent {
    ContentEvent::with_size(cid.to_string(), event_type, size)
}

/// Helper to create an event with peer.
fn create_event_with_peer(cid: &str, event_type: LifecycleEventType, peer: &str) -> ContentEvent {
    ContentEvent::with_peer(cid.to_string(), event_type, peer.to_string())
}

/// Benchmark LifecycleEventManager creation.
fn bench_manager_creation(c: &mut Criterion) {
    c.bench_function("lifecycle_manager_creation", |b| {
        b.iter(|| {
            let manager = LifecycleEventManager::new();
            black_box(manager);
        });
    });
}

/// Benchmark LifecycleEventManager creation with custom history size.
fn bench_manager_with_history_creation(c: &mut Criterion) {
    c.bench_function("lifecycle_manager_with_history_creation", |b| {
        b.iter(|| {
            let manager = LifecycleEventManager::with_history_size(black_box(10000));
            black_box(manager);
        });
    });
}

/// Benchmark ContentEvent creation (simple).
fn bench_event_simple_creation(c: &mut Criterion) {
    c.bench_function("lifecycle_event_simple_creation", |b| {
        b.iter(|| {
            let event = create_simple_event(
                black_box("QmExample"),
                black_box(LifecycleEventType::ContentAdded),
            );
            black_box(event);
        });
    });
}

/// Benchmark ContentEvent creation (with size).
fn bench_event_with_size_creation(c: &mut Criterion) {
    c.bench_function("lifecycle_event_with_size_creation", |b| {
        b.iter(|| {
            let event = create_event_with_size(
                black_box("QmExample"),
                black_box(LifecycleEventType::ContentAdded),
                black_box(1024 * 1024),
            );
            black_box(event);
        });
    });
}

/// Benchmark ContentEvent creation (with peer).
fn bench_event_with_peer_creation(c: &mut Criterion) {
    c.bench_function("lifecycle_event_with_peer_creation", |b| {
        b.iter(|| {
            let event = create_event_with_peer(
                black_box("QmExample"),
                black_box(LifecycleEventType::ChunkTransferred),
                black_box("12D3KooWExample"),
            );
            black_box(event);
        });
    });
}

/// Benchmark ContentEvent creation with metadata.
fn bench_event_with_metadata_creation(c: &mut Criterion) {
    c.bench_function("lifecycle_event_with_metadata_creation", |b| {
        b.iter(|| {
            let event = create_simple_event("QmExample", LifecycleEventType::ContentAdded)
                .with_metadata("key1".to_string(), "value1".to_string())
                .with_metadata("key2".to_string(), "value2".to_string())
                .with_metadata("key3".to_string(), "value3".to_string());
            black_box(event);
        });
    });
}

/// Benchmark event handler registration.
fn bench_handler_registration(c: &mut Criterion) {
    c.bench_function("lifecycle_handler_registration", |b| {
        b.iter(|| {
            let mut manager = LifecycleEventManager::new();
            manager.on(black_box(LifecycleEventType::ContentAdded), |_event| {
                // Handler logic
            });
            black_box(manager);
        });
    });
}

/// Benchmark multiple handler registrations.
fn bench_multiple_handler_registration(c: &mut Criterion) {
    c.bench_function("lifecycle_multiple_handler_registration", |b| {
        b.iter(|| {
            let mut manager = LifecycleEventManager::new();

            // Register handlers for different event types
            manager.on(LifecycleEventType::ContentAdded, |_event| {});
            manager.on(LifecycleEventType::ContentAccessed, |_event| {});
            manager.on(LifecycleEventType::ContentRemoved, |_event| {});
            manager.on(LifecycleEventType::ContentPinned, |_event| {});
            manager.on(LifecycleEventType::ChunkTransferred, |_event| {});

            black_box(manager);
        });
    });
}

/// Benchmark event emission.
fn bench_event_emit(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_event_emit", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();

                // Register a simple handler
                manager.on(LifecycleEventType::ContentAdded, |_event| {});

                // Emit event
                let event = create_simple_event("QmExample", LifecycleEventType::ContentAdded);
                manager.emit(black_box(event)).await;

                black_box(manager);
            });
        });
    });
}

/// Benchmark event emission by type.
fn bench_event_emit_by_type(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("lifecycle_event_emit_by_type");

    let event_types = vec![
        ("ContentAdded", LifecycleEventType::ContentAdded),
        ("ContentAccessed", LifecycleEventType::ContentAccessed),
        ("ContentRemoved", LifecycleEventType::ContentRemoved),
        ("ChunkTransferred", LifecycleEventType::ChunkTransferred),
        ("ProofGenerated", LifecycleEventType::ProofGenerated),
    ];

    for (name, event_type) in event_types {
        group.bench_with_input(BenchmarkId::from_parameter(name), &event_type, |b, &et| {
            b.iter(|| {
                rt.block_on(async {
                    let mut manager = LifecycleEventManager::new();
                    manager.on(et, |_event| {});

                    let event = create_simple_event("QmExample", et);
                    manager.emit(black_box(event)).await;
                });
            });
        });
    }

    group.finish();
}

/// Benchmark bulk event emissions.
fn bench_bulk_event_emit(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("lifecycle_bulk_event_emit");

    for &count in &[10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_events", count)),
            &count,
            |b, &n| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut manager = LifecycleEventManager::new();
                        manager.on(LifecycleEventType::ContentAdded, |_event| {});

                        for i in 0..n {
                            let event = create_event_with_size(
                                &format!("QmExample{}", i),
                                LifecycleEventType::ContentAdded,
                                1024,
                            );
                            manager.emit(event).await;
                        }

                        black_box(manager);
                    });
                });
            },
        );
    }

    group.finish();
}

/// Benchmark get_history queries.
fn bench_get_history(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_get_history", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();
                manager.on(LifecycleEventType::ContentAdded, |_event| {});

                // Emit some events
                for i in 0..50 {
                    let event = create_simple_event(
                        &format!("QmExample{}", i),
                        LifecycleEventType::ContentAdded,
                    );
                    manager.emit(event).await;
                }

                // Query history
                let history = manager.get_history(Some(LifecycleEventType::ContentAdded));
                black_box(history);
            });
        });
    });
}

/// Benchmark get_recent queries.
fn bench_get_recent(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_get_recent", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();
                manager.on(LifecycleEventType::ContentAdded, |_event| {});

                // Emit many events
                for i in 0..100 {
                    let event = create_simple_event(
                        &format!("QmExample{}", i),
                        LifecycleEventType::ContentAdded,
                    );
                    manager.emit(event).await;
                }

                // Query recent events
                let recent = manager.get_recent(black_box(20));
                black_box(recent);
            });
        });
    });
}

/// Benchmark get_event_count queries.
fn bench_get_event_count(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_get_event_count", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();
                manager.on(LifecycleEventType::ContentAdded, |_event| {});
                manager.on(LifecycleEventType::ContentAccessed, |_event| {});

                // Emit events
                for i in 0..50 {
                    if i % 2 == 0 {
                        let event = create_simple_event(
                            &format!("Qm{}", i),
                            LifecycleEventType::ContentAdded,
                        );
                        manager.emit(event).await;
                    } else {
                        let event = create_simple_event(
                            &format!("Qm{}", i),
                            LifecycleEventType::ContentAccessed,
                        );
                        manager.emit(event).await;
                    }
                }

                // Query counts
                let added_count = manager.get_event_count(LifecycleEventType::ContentAdded);
                let accessed_count = manager.get_event_count(LifecycleEventType::ContentAccessed);
                black_box((added_count, accessed_count));
            });
        });
    });
}

/// Benchmark get_total_event_count.
fn bench_get_total_event_count(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_get_total_event_count", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();
                manager.on(LifecycleEventType::ContentAdded, |_event| {});

                // Emit events
                for i in 0..100 {
                    let event =
                        create_simple_event(&format!("Qm{}", i), LifecycleEventType::ContentAdded);
                    manager.emit(event).await;
                }

                let total = manager.get_total_event_count();
                black_box(total);
            });
        });
    });
}

/// Benchmark get_stats queries.
fn bench_get_stats(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_get_stats", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();

                // Register handlers for multiple event types
                manager.on(LifecycleEventType::ContentAdded, |_event| {});
                manager.on(LifecycleEventType::ContentAccessed, |_event| {});
                manager.on(LifecycleEventType::ChunkTransferred, |_event| {});

                // Emit various events
                for i in 0..60 {
                    let event_type = match i % 3 {
                        0 => LifecycleEventType::ContentAdded,
                        1 => LifecycleEventType::ContentAccessed,
                        _ => LifecycleEventType::ChunkTransferred,
                    };
                    let event = create_simple_event(&format!("Qm{}", i), event_type);
                    manager.emit(event).await;
                }

                let stats = manager.get_stats();
                black_box(stats);
            });
        });
    });
}

/// Benchmark clear_history.
fn bench_clear_history(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_clear_history", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();
                manager.on(LifecycleEventType::ContentAdded, |_event| {});

                // Emit many events
                for i in 0..100 {
                    let event =
                        create_simple_event(&format!("Qm{}", i), LifecycleEventType::ContentAdded);
                    manager.emit(event).await;
                }

                // Clear history
                manager.clear_history();
                black_box(manager);
            });
        });
    });
}

/// Benchmark reset_stats.
fn bench_reset_stats(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_reset_stats", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();
                manager.on(LifecycleEventType::ContentAdded, |_event| {});

                // Emit events
                for i in 0..100 {
                    let event =
                        create_simple_event(&format!("Qm{}", i), LifecycleEventType::ContentAdded);
                    manager.emit(event).await;
                }

                // Reset stats
                manager.reset_stats();
                black_box(manager);
            });
        });
    });
}

/// Benchmark realistic scenario: content storage tracking.
fn bench_realistic_content_storage(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_realistic_content_storage", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();

                // Register handlers for content lifecycle
                manager.on(LifecycleEventType::ContentAdded, |_event| {
                    // Would log/track new content
                });
                manager.on(LifecycleEventType::ContentAccessed, |_event| {
                    // Would update access metrics
                });
                manager.on(LifecycleEventType::ContentPinned, |_event| {
                    // Would track pinned content
                });

                // Simulate content operations
                // 1. Add new content
                for i in 0..20 {
                    let event = create_event_with_size(
                        &format!("QmContent{}", i),
                        LifecycleEventType::ContentAdded,
                        (i + 1) * 1024 * 1024,
                    );
                    manager.emit(event).await;
                }

                // 2. Access some content multiple times
                for i in 0..50 {
                    let event = create_simple_event(
                        &format!("QmContent{}", i % 20),
                        LifecycleEventType::ContentAccessed,
                    );
                    manager.emit(event).await;
                }

                // 3. Pin popular content
                for i in 0..5 {
                    let event = create_simple_event(
                        &format!("QmContent{}", i),
                        LifecycleEventType::ContentPinned,
                    );
                    manager.emit(event).await;
                }

                // Check statistics
                let stats = manager.get_stats();
                let recent = manager.get_recent(10);

                black_box((stats, recent, manager));
            });
        });
    });
}

/// Benchmark realistic scenario: P2P transfer monitoring.
fn bench_realistic_p2p_monitoring(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("lifecycle_realistic_p2p_monitoring", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut manager = LifecycleEventManager::new();

                // Register handlers for P2P events
                manager.on(LifecycleEventType::PeerConnected, |_event| {});
                manager.on(LifecycleEventType::ChunkTransferred, |_event| {});
                manager.on(LifecycleEventType::ProofGenerated, |_event| {});
                manager.on(LifecycleEventType::PeerDisconnected, |_event| {});

                // Simulate P2P activity
                // 1. Peers connect
                for i in 0..10 {
                    let event = create_event_with_peer(
                        "",
                        LifecycleEventType::PeerConnected,
                        &format!("12D3KooPeer{}", i),
                    );
                    manager.emit(event).await;
                }

                // 2. Chunk transfers
                for i in 0..100 {
                    let event = create_event_with_peer(
                        &format!("QmChunk{}", i),
                        LifecycleEventType::ChunkTransferred,
                        &format!("12D3KooPeer{}", i % 10),
                    )
                    .with_metadata("transfer_time_ms".to_string(), "150".to_string());
                    manager.emit(event).await;
                }

                // 3. Proofs generated
                for i in 0..80 {
                    let event = create_event_with_peer(
                        &format!("QmChunk{}", i),
                        LifecycleEventType::ProofGenerated,
                        &format!("12D3KooPeer{}", i % 10),
                    );
                    manager.emit(event).await;
                }

                // 4. Some peers disconnect
                for i in 0..3 {
                    let event = create_event_with_peer(
                        "",
                        LifecycleEventType::PeerDisconnected,
                        &format!("12D3KooPeer{}", i),
                    );
                    manager.emit(event).await;
                }

                // Get statistics
                let stats = manager.get_stats();
                let transfer_count = manager.get_event_count(LifecycleEventType::ChunkTransferred);

                black_box((stats, transfer_count, manager));
            });
        });
    });
}

criterion_group!(
    benches,
    bench_manager_creation,
    bench_manager_with_history_creation,
    bench_event_simple_creation,
    bench_event_with_size_creation,
    bench_event_with_peer_creation,
    bench_event_with_metadata_creation,
    bench_handler_registration,
    bench_multiple_handler_registration,
    bench_event_emit,
    bench_event_emit_by_type,
    bench_bulk_event_emit,
    bench_get_history,
    bench_get_recent,
    bench_get_event_count,
    bench_get_total_event_count,
    bench_get_stats,
    bench_clear_history,
    bench_reset_stats,
    bench_realistic_content_storage,
    bench_realistic_p2p_monitoring,
);
criterion_main!(benches);

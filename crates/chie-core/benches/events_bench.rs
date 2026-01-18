use chie_core::{
    AsyncEventBus, Event, EventBatch, EventBus, EventFilter, EventType, PayloadFilter,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn bench_event_bus_creation(c: &mut Criterion) {
    c.bench_function("event_bus_new", |b| {
        b.iter(|| black_box(EventBus::new()));
    });
}

fn bench_event_creation_helpers(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_creation");

    group.bench_function("content_added", |b| {
        b.iter(|| {
            black_box(Event::content_added(
                black_box("QmTest123".to_string()),
                black_box(1024 * 1024),
            ))
        });
    });

    group.bench_function("content_removed", |b| {
        b.iter(|| {
            black_box(Event::content_removed(
                black_box("QmTest123".to_string()),
                black_box(1024 * 1024),
            ))
        });
    });

    group.bench_function("peer_connected", |b| {
        b.iter(|| black_box(Event::peer_connected(black_box("12D3KooWTest".to_string()))));
    });

    group.bench_function("peer_disconnected", |b| {
        b.iter(|| {
            black_box(Event::peer_disconnected(black_box(
                "12D3KooWTest".to_string(),
            )))
        });
    });

    group.bench_function("content_requested", |b| {
        b.iter(|| {
            black_box(Event::content_requested(
                black_box("QmTest123".to_string()),
                black_box(1024 * 1024),
            ))
        });
    });

    group.bench_function("proof_submitted", |b| {
        b.iter(|| {
            black_box(Event::proof_submitted(
                black_box("QmTest123".to_string()),
                black_box(1024 * 1024),
            ))
        });
    });

    group.bench_function("reputation_changed", |b| {
        b.iter(|| {
            black_box(Event::reputation_changed(
                black_box("12D3KooWTest".to_string()),
                black_box(0.5),
                black_box(0.75),
            ))
        });
    });

    group.bench_function("quota_exceeded", |b| {
        b.iter(|| {
            black_box(Event::quota_exceeded(
                black_box(90 * 1024 * 1024 * 1024),
                black_box(100 * 1024 * 1024 * 1024),
            ))
        });
    });

    group.finish();
}

fn bench_subscribe(c: &mut Criterion) {
    c.bench_function("event_bus_subscribe", |b| {
        b.iter(|| {
            let bus = EventBus::new();
            black_box(bus.subscribe(black_box(EventType::ContentAdded)))
        });
    });
}

fn bench_publish(c: &mut Criterion) {
    c.bench_function("event_bus_publish_no_subscribers", |b| {
        let bus = EventBus::new();
        b.iter(|| {
            bus.publish(black_box(Event::content_added(
                "QmTest123".to_string(),
                1024 * 1024,
            )));
        });
    });
}

fn bench_publish_with_subscribers(c: &mut Criterion) {
    let mut group = c.benchmark_group("publish_with_subscribers");

    for sub_count in [1, 5, 10, 50].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(sub_count),
            sub_count,
            |b, &count| {
                let bus = EventBus::new();
                let _subscribers: Vec<_> = (0..count)
                    .map(|_| bus.subscribe(EventType::ContentAdded))
                    .collect();

                b.iter(|| {
                    bus.publish(black_box(Event::content_added(
                        "QmTest123".to_string(),
                        1024 * 1024,
                    )));
                });
            },
        );
    }
    group.finish();
}

fn bench_publish_different_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("publish_different_types");
    let bus = EventBus::new();
    let _sub1 = bus.subscribe(EventType::ContentAdded);
    let _sub2 = bus.subscribe(EventType::PeerConnected);
    let _sub3 = bus.subscribe(EventType::ProofSubmitted);

    group.bench_function("content_added", |b| {
        b.iter(|| {
            bus.publish(black_box(Event::content_added(
                "QmTest123".to_string(),
                1024 * 1024,
            )));
        });
    });

    group.bench_function("peer_connected", |b| {
        b.iter(|| {
            bus.publish(black_box(Event::peer_connected("12D3KooWTest".to_string())));
        });
    });

    group.bench_function("proof_submitted", |b| {
        b.iter(|| {
            bus.publish(black_box(Event::proof_submitted(
                "QmTest123".to_string(),
                1024 * 1024,
            )));
        });
    });

    group.finish();
}

fn bench_subscriber_count(c: &mut Criterion) {
    c.bench_function("event_bus_subscriber_count", |b| {
        let bus = EventBus::new();
        let _sub1 = bus.subscribe(EventType::ContentAdded);
        let _sub2 = bus.subscribe(EventType::ContentAdded);
        let _sub3 = bus.subscribe(EventType::PeerConnected);

        b.iter(|| black_box(bus.subscriber_count(EventType::ContentAdded)));
    });
}

fn bench_stats(c: &mut Criterion) {
    c.bench_function("event_bus_stats", |b| {
        let bus = EventBus::new();
        bus.publish(Event::content_added("QmTest1".to_string(), 1024));
        bus.publish(Event::peer_connected("12D3Test1".to_string()));
        bus.publish(Event::proof_submitted("QmTest2".to_string(), 2048));

        b.iter(|| black_box(bus.stats()));
    });
}

fn bench_stats_event_count(c: &mut Criterion) {
    c.bench_function("event_stats_event_count", |b| {
        let bus = EventBus::new();
        for _ in 0..100 {
            bus.publish(Event::content_added("QmTest".to_string(), 1024));
        }
        for _ in 0..50 {
            bus.publish(Event::peer_connected("12D3Test".to_string()));
        }

        let stats = bus.stats();
        b.iter(|| black_box(stats.event_count(EventType::ContentAdded)));
    });
}

fn bench_stats_most_common_event(c: &mut Criterion) {
    c.bench_function("event_stats_most_common_event", |b| {
        let bus = EventBus::new();
        for _ in 0..100 {
            bus.publish(Event::content_added("QmTest".to_string(), 1024));
        }
        for _ in 0..50 {
            bus.publish(Event::peer_connected("12D3Test".to_string()));
        }

        let stats = bus.stats();
        b.iter(|| black_box(stats.most_common_event()));
    });
}

fn bench_clear_subscribers(c: &mut Criterion) {
    c.bench_function("event_bus_clear_subscribers", |b| {
        b.iter(|| {
            let bus = EventBus::new();
            let _sub1 = bus.subscribe(EventType::ContentAdded);
            let _sub2 = bus.subscribe(EventType::PeerConnected);
            bus.clear_subscribers();
            black_box(bus.subscriber_count(EventType::ContentAdded))
        });
    });
}

fn bench_reset_stats(c: &mut Criterion) {
    c.bench_function("event_bus_reset_stats", |b| {
        let bus = EventBus::new();
        for _ in 0..100 {
            bus.publish(Event::content_added("QmTest".to_string(), 1024));
        }

        b.iter(|| {
            bus.reset_stats();
            black_box(bus.stats().total_events)
        });
    });
}

fn bench_mixed_operations(c: &mut Criterion) {
    c.bench_function("event_bus_mixed_operations", |b| {
        b.iter(|| {
            let bus = EventBus::new();
            let _sub1 = bus.subscribe(EventType::ContentAdded);
            let _sub2 = bus.subscribe(EventType::PeerConnected);
            bus.publish(Event::content_added("QmTest1".to_string(), 1024));
            bus.publish(Event::peer_connected("12D3Test1".to_string()));
            bus.publish(Event::proof_submitted("QmTest2".to_string(), 2048));
            let _stats = bus.stats();
            let _count = bus.subscriber_count(EventType::ContentAdded);
            black_box(bus)
        });
    });
}

fn bench_async_event_bus(c: &mut Criterion) {
    let mut group = c.benchmark_group("async_event_bus");

    for num_receivers in [1, 10, 50] {
        group.throughput(Throughput::Elements(num_receivers));
        group.bench_with_input(
            BenchmarkId::new("publish", num_receivers),
            &num_receivers,
            |b, &n| {
                let bus = AsyncEventBus::new(1000);
                let _receivers: Vec<_> = (0..n)
                    .map(|_| bus.subscribe(EventType::ContentAdded))
                    .collect();

                b.iter(|| {
                    let _ = bus.publish(black_box(Event::content_added("QmTest", 1024)));
                });
            },
        );
    }

    group.finish();
}

fn bench_event_filter(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_filter");

    group.bench_function("filter_by_type", |b| {
        let filter = EventFilter::new().with_types(vec![EventType::ContentAdded]);
        let event = Event::content_added("QmTest", 1024);

        b.iter(|| {
            black_box(filter.matches(black_box(&event)));
        });
    });

    group.bench_function("filter_by_cid_prefix", |b| {
        let filter =
            EventFilter::new().with_payload_filter(PayloadFilter::CidPrefix("Qm".to_string()));
        let event = Event::content_added("QmTest123", 1024);

        b.iter(|| {
            black_box(filter.matches(black_box(&event)));
        });
    });

    group.bench_function("filter_by_min_bytes", |b| {
        let filter = EventFilter::new().with_payload_filter(PayloadFilter::MinBytes(512));
        let event = Event::content_added("QmTest", 1024);

        b.iter(|| {
            black_box(filter.matches(black_box(&event)));
        });
    });

    group.bench_function("filter_complex", |b| {
        let filter = EventFilter::new()
            .with_types(vec![EventType::ContentAdded, EventType::ProofGenerated])
            .with_min_timestamp(0)
            .with_payload_filter(PayloadFilter::MinBytes(512));
        let event = Event::content_added("QmTest", 1024);

        b.iter(|| {
            black_box(filter.matches(black_box(&event)));
        });
    });

    group.finish();
}

fn bench_event_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_batch");

    for batch_size in [10, 100, 1000] {
        group.throughput(Throughput::Elements(batch_size));
        group.bench_with_input(
            BenchmarkId::new("add_events", batch_size),
            &batch_size,
            |b, &n| {
                b.iter(|| {
                    let mut batch = EventBatch::new();
                    for i in 0..n {
                        batch.add(Event::content_added(format!("QmTest{}", i), 1024));
                    }
                    black_box(batch);
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("total_bytes", batch_size),
            &batch_size,
            |b, &n| {
                let mut batch = EventBatch::new();
                for i in 0..n {
                    batch.add(Event::content_added(format!("QmTest{}", i), 1024));
                }

                b.iter(|| {
                    black_box(batch.total_bytes());
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("filter_batch", batch_size),
            &batch_size,
            |b, &n| {
                let mut batch = EventBatch::new();
                for i in 0..n {
                    batch.add(Event::content_added(format!("QmTest{}", i), 1024 * i));
                }
                let filter = EventFilter::new().with_payload_filter(PayloadFilter::MinBytes(5000));

                b.iter(|| {
                    black_box(batch.filter(&filter));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_event_bus_creation,
    bench_event_creation_helpers,
    bench_subscribe,
    bench_publish,
    bench_publish_with_subscribers,
    bench_publish_different_types,
    bench_subscriber_count,
    bench_stats,
    bench_stats_event_count,
    bench_stats_most_common_event,
    bench_clear_subscribers,
    bench_reset_stats,
    bench_mixed_operations,
    bench_async_event_bus,
    bench_event_filter,
    bench_event_batch,
);
criterion_main!(benches);

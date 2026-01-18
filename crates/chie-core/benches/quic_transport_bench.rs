use chie_core::quic_transport::{QuicConfig, QuicEndpoint};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;
use std::time::Duration;
use tokio::runtime::Runtime;

fn bench_config_creation(c: &mut Criterion) {
    c.bench_function("quic_config_default", |b| {
        b.iter(|| {
            let _ = black_box(QuicConfig::default());
        });
    });

    c.bench_function("quic_config_builder", |b| {
        b.iter(|| {
            let _ = black_box(
                QuicConfig::builder()
                    .with_max_concurrent_streams(200)
                    .with_max_idle_timeout(Duration::from_secs(60))
                    .with_keep_alive_interval(Duration::from_secs(10))
                    .with_migration(false)
                    .with_0rtt(true)
                    .build(),
            );
        });
    });
}

fn bench_endpoint_creation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("quic_server_endpoint", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QuicConfig::default();
                black_box(QuicEndpoint::server("127.0.0.1:0", config).await.unwrap());
            });
        });
    });

    c.bench_function("quic_client_endpoint", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QuicConfig::default();
                black_box(QuicEndpoint::client(config).await.unwrap());
            });
        });
    });
}

fn bench_connection_establishment(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Setup server
    let config = QuicConfig::default();
    let mut server =
        rt.block_on(async { QuicEndpoint::server("127.0.0.1:0", config).await.unwrap() });
    let server_addr = server.local_addr().unwrap();

    // Spawn server task
    rt.spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                let _ = incoming.accept().await;
            });
        }
    });

    // Give server time to start
    std::thread::sleep(Duration::from_millis(100));

    c.bench_function("quic_connection_establish", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = QuicConfig::default();
                let client = QuicEndpoint::client(config).await.unwrap();
                black_box(
                    client
                        .connect(&server_addr.to_string(), "localhost")
                        .await
                        .unwrap(),
                );
            });
        });
    });
}

fn bench_stream_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Setup server
    let config = QuicConfig::default();
    let mut server =
        rt.block_on(async { QuicEndpoint::server("127.0.0.1:0", config).await.unwrap() });
    let server_addr = server.local_addr().unwrap();

    // Spawn server task that echoes data
    rt.spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                if let Ok(connection) = incoming.accept().await {
                    while let Some(mut stream) = connection.accept_bidirectional_stream().await {
                        tokio::spawn(async move {
                            let mut buffer = vec![0u8; 8192];
                            if let Ok(len) = stream.receive(&mut buffer).await {
                                let _ = stream.send(&buffer[..len]).await;
                                let _ = stream.finish().await;
                            }
                        });
                    }
                }
            });
        }
    });

    std::thread::sleep(Duration::from_millis(100));

    // Create client connection
    let config = QuicConfig::default();
    let client = rt.block_on(async { QuicEndpoint::client(config).await.unwrap() });
    let connection = rt.block_on(async {
        client
            .connect(&server_addr.to_string(), "localhost")
            .await
            .unwrap()
    });

    c.bench_function("quic_stream_open", |b| {
        b.iter(|| {
            rt.block_on(async {
                black_box(connection.open_bidirectional_stream().await.unwrap());
            });
        });
    });
}

fn bench_data_transfer(c: &mut Criterion) {
    let mut group = c.benchmark_group("quic_data_transfer");
    let rt = Runtime::new().unwrap();

    // Setup server
    let config = QuicConfig::default();
    let mut server =
        rt.block_on(async { QuicEndpoint::server("127.0.0.1:0", config).await.unwrap() });
    let server_addr = server.local_addr().unwrap();

    // Spawn server task
    rt.spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                if let Ok(connection) = incoming.accept().await {
                    while let Some(mut stream) = connection.accept_bidirectional_stream().await {
                        tokio::spawn(async move {
                            let mut buffer = vec![0u8; 1024 * 1024]; // 1 MB buffer
                            while let Ok(len) = stream.receive(&mut buffer).await {
                                if len == 0 {
                                    break;
                                }
                                let _ = stream.send(&buffer[..len]).await;
                            }
                            let _ = stream.finish().await;
                        });
                    }
                }
            });
        }
    });

    std::thread::sleep(Duration::from_millis(100));

    // Create client connection
    let config = QuicConfig::default();
    let client = rt.block_on(async { QuicEndpoint::client(config).await.unwrap() });
    let connection = rt.block_on(async {
        client
            .connect(&server_addr.to_string(), "localhost")
            .await
            .unwrap()
    });

    // Benchmark different payload sizes
    for size in [1024, 4096, 16384, 65536] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            let data = vec![0u8; size];
            b.iter(|| {
                rt.block_on(async {
                    let mut stream = connection.open_bidirectional_stream().await.unwrap();
                    stream.send(&data).await.unwrap();
                    stream.finish().await.unwrap();
                    let response = stream.receive_all().await.unwrap();
                    black_box(response);
                });
            });
        });
    }

    group.finish();
}

fn bench_multiple_streams(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Setup server
    let config = QuicConfig::builder()
        .with_max_concurrent_streams(1000)
        .build();
    let mut server =
        rt.block_on(async { QuicEndpoint::server("127.0.0.1:0", config).await.unwrap() });
    let server_addr = server.local_addr().unwrap();

    // Spawn server task
    rt.spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                if let Ok(connection) = incoming.accept().await {
                    while let Some(mut stream) = connection.accept_bidirectional_stream().await {
                        tokio::spawn(async move {
                            let mut buffer = vec![0u8; 1024];
                            let _ = stream.receive(&mut buffer).await;
                            let _ = stream.send(b"OK").await;
                            let _ = stream.finish().await;
                        });
                    }
                }
            });
        }
    });

    std::thread::sleep(Duration::from_millis(100));

    // Create client connection
    let config = QuicConfig::builder()
        .with_max_concurrent_streams(1000)
        .build();
    let client = rt.block_on(async { QuicEndpoint::client(config).await.unwrap() });
    let connection = rt.block_on(async {
        client
            .connect(&server_addr.to_string(), "localhost")
            .await
            .unwrap()
    });

    c.bench_function("quic_10_concurrent_streams", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut futures = Vec::new();
                for _ in 0..10 {
                    futures.push(async {
                        let mut stream = connection.open_bidirectional_stream().await.unwrap();
                        stream.send(b"test").await.unwrap();
                        stream.finish().await.unwrap();
                        stream.receive_all().await.unwrap()
                    });
                }

                for future in futures {
                    black_box(future.await);
                }
            });
        });
    });

    c.bench_function("quic_100_concurrent_streams", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut futures = Vec::new();
                for _ in 0..100 {
                    futures.push(async {
                        let mut stream = connection.open_bidirectional_stream().await.unwrap();
                        stream.send(b"test").await.unwrap();
                        stream.finish().await.unwrap();
                        stream.receive_all().await.unwrap()
                    });
                }

                for future in futures {
                    black_box(future.await);
                }
            });
        });
    });
}

fn bench_stats_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let config = QuicConfig::default();
    let endpoint = rt.block_on(async { QuicEndpoint::client(config).await.unwrap() });

    c.bench_function("quic_stats_access", |b| {
        b.iter(|| {
            black_box(endpoint.stats());
        });
    });

    let stats = endpoint.stats();

    c.bench_function("quic_stats_calculations", |b| {
        b.iter(|| {
            black_box(stats.active_connections());
            black_box(stats.active_streams());
            black_box(stats.total_bytes());
        });
    });
}

criterion_group!(
    benches,
    bench_config_creation,
    bench_endpoint_creation,
    bench_connection_establishment,
    bench_stream_operations,
    bench_data_transfer,
    bench_multiple_streams,
    bench_stats_operations
);
criterion_main!(benches);

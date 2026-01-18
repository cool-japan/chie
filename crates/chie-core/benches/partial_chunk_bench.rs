//! Benchmark suite for partial chunk module (HTTP range requests).
//!
//! This file benchmarks the performance of range request parsing and processing:
//! - ByteRange creation and normalization
//! - RangeRequest parsing from HTTP headers
//! - Multi-range request handling
//! - ChunkRange calculation for different content sizes
//! - RangeHandler operations
//!
//! Run with: cargo bench --bench partial_chunk_bench

use chie_core::partial_chunk::{ByteRange, RangeHandler, RangeRequest};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::hint::black_box;

// ============================================================================
// Constants
// ============================================================================

const SMALL_CONTENT: u64 = 1_048_576; // 1 MB
const MEDIUM_CONTENT: u64 = 100_000_000; // 100 MB
const LARGE_CONTENT: u64 = 1_000_000_000; // 1 GB
const CHUNK_SIZE: u64 = 262_144; // 256 KB

// ============================================================================
// ByteRange Benchmarks
// ============================================================================

fn bench_byterange_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("byterange_creation");

    group.bench_function("new", |b| {
        b.iter(|| {
            let _range = black_box(ByteRange::new(0, Some(1023)));
        });
    });

    group.bench_function("from_to", |b| {
        b.iter(|| {
            let _range = black_box(ByteRange::from_to(0, 1023));
        });
    });

    group.bench_function("from_start", |b| {
        b.iter(|| {
            let _range = black_box(ByteRange::from_start(1024));
        });
    });

    group.bench_function("suffix", |b| {
        b.iter(|| {
            let _range = black_box(ByteRange::suffix(500));
        });
    });

    group.finish();
}

fn bench_byterange_normalize(c: &mut Criterion) {
    let mut group = c.benchmark_group("byterange_normalize");

    let range = ByteRange::from_to(0, 1023);

    for content_length in [SMALL_CONTENT, MEDIUM_CONTENT, LARGE_CONTENT] {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}MB", content_length / 1_000_000)),
            &content_length,
            |b, &cl| {
                b.iter(|| {
                    let _normalized = black_box(range.normalize(cl).unwrap());
                });
            },
        );
    }

    group.finish();
}

fn bench_byterange_length(c: &mut Criterion) {
    let range = ByteRange::from_to(0, 1023);

    c.bench_function("byterange_length", |b| {
        b.iter(|| {
            let _len = black_box(range.length());
        });
    });
}

// ============================================================================
// RangeRequest Parsing Benchmarks
// ============================================================================

fn bench_range_request_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_request_parse");

    let test_cases = vec![
        ("single_range", "bytes=0-1023"),
        ("open_ended", "bytes=1024-"),
        ("suffix", "bytes=-500"),
        ("two_ranges", "bytes=0-1023,2048-4095"),
        ("three_ranges", "bytes=0-1023,2048-4095,8192-16383"),
        ("complex", "bytes=0-1023, 2048-4095, 8192-16383, 16384-"),
    ];

    for (name, header) in test_cases {
        group.bench_function(name, |b| {
            b.iter(|| {
                let _request = black_box(RangeRequest::parse(header).unwrap());
            });
        });
    }

    group.finish();
}

fn bench_range_request_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_request_creation");

    group.bench_function("new_single", |b| {
        b.iter(|| {
            let range = ByteRange::from_to(0, 1023);
            let _request = black_box(RangeRequest::new(range));
        });
    });

    group.bench_function("multi_3_ranges", |b| {
        b.iter(|| {
            let ranges = vec![
                ByteRange::from_to(0, 1023),
                ByteRange::from_to(2048, 4095),
                ByteRange::from_to(8192, 16383),
            ];
            let _request = black_box(RangeRequest::multi(ranges));
        });
    });

    group.finish();
}

fn bench_range_request_is_multi(c: &mut Criterion) {
    let single = RangeRequest::parse("bytes=0-1023").unwrap();
    let multi = RangeRequest::parse("bytes=0-1023,2048-4095").unwrap();

    let mut group = c.benchmark_group("range_request_is_multi");

    group.bench_function("single", |b| {
        b.iter(|| {
            let _is_multi = black_box(single.is_multi_range());
        });
    });

    group.bench_function("multi", |b| {
        b.iter(|| {
            let _is_multi = black_box(multi.is_multi_range());
        });
    });

    group.finish();
}

fn bench_range_request_total_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_request_total_bytes");

    let single = RangeRequest::parse("bytes=0-1023").unwrap();
    let multi = RangeRequest::parse("bytes=0-1023,2048-4095,8192-16383").unwrap();

    group.bench_function("single_range", |b| {
        b.iter(|| {
            let _total = black_box(single.total_bytes(MEDIUM_CONTENT).unwrap());
        });
    });

    group.bench_function("multi_range_3", |b| {
        b.iter(|| {
            let _total = black_box(multi.total_bytes(MEDIUM_CONTENT).unwrap());
        });
    });

    group.finish();
}

// ============================================================================
// RangeHandler Benchmarks
// ============================================================================

fn bench_range_handler_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_handler_creation");

    group.bench_function("new", |b| {
        b.iter(|| {
            let _handler = black_box(RangeHandler::new(MEDIUM_CONTENT, CHUNK_SIZE));
        });
    });

    group.bench_function("with_default_chunk_size", |b| {
        b.iter(|| {
            let _handler = black_box(RangeHandler::with_default_chunk_size(MEDIUM_CONTENT));
        });
    });

    group.finish();
}

fn bench_get_required_chunks(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_required_chunks");

    // Test different content sizes
    for (size_name, content_length) in [
        ("1MB", SMALL_CONTENT),
        ("100MB", MEDIUM_CONTENT),
        ("1GB", LARGE_CONTENT),
    ] {
        let handler = RangeHandler::new(content_length, CHUNK_SIZE);

        // Single small range (1 chunk)
        let small_range = RangeRequest::parse("bytes=0-1023").unwrap();
        group.bench_function(format!("{}_single_small_range", size_name), |b| {
            b.iter(|| {
                let _chunks = black_box(handler.get_required_chunks(&small_range).unwrap());
            });
        });

        // Medium range (multiple chunks)
        let medium_range = RangeRequest::parse("bytes=0-1048575").unwrap(); // 1 MB
        group.bench_function(format!("{}_medium_range", size_name), |b| {
            b.iter(|| {
                let _chunks = black_box(handler.get_required_chunks(&medium_range).unwrap());
            });
        });

        // Large range (many chunks)
        if content_length >= 10_000_000 {
            let large_range = RangeRequest::parse("bytes=0-9999999").unwrap(); // 10 MB
            group.bench_function(format!("{}_large_range", size_name), |b| {
                b.iter(|| {
                    let _chunks = black_box(handler.get_required_chunks(&large_range).unwrap());
                });
            });
        }
    }

    group.finish();
}

fn bench_get_required_chunks_multi_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_required_chunks_multi_range");

    let handler = RangeHandler::new(MEDIUM_CONTENT, CHUNK_SIZE);

    // 2 ranges
    let two_ranges = RangeRequest::parse("bytes=0-1048575,10485760-11534335").unwrap();
    group.bench_function("2_ranges", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&two_ranges).unwrap());
        });
    });

    // 5 ranges
    let five_ranges = RangeRequest::parse(
        "bytes=0-1048575,10485760-11534335,20971520-22019095,31457280-32504855,41943040-42990615",
    )
    .unwrap();
    group.bench_function("5_ranges", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&five_ranges).unwrap());
        });
    });

    group.finish();
}

fn bench_get_required_chunks_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_required_chunks_patterns");

    let handler = RangeHandler::new(MEDIUM_CONTENT, CHUNK_SIZE);

    // Beginning of content
    let beginning = RangeRequest::parse("bytes=0-262143").unwrap();
    group.bench_function("beginning", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&beginning).unwrap());
        });
    });

    // Middle of content
    let middle = RangeRequest::parse("bytes=50000000-50262143").unwrap();
    group.bench_function("middle", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&middle).unwrap());
        });
    });

    // End of content
    let end = RangeRequest::parse("bytes=99737856-99999999").unwrap();
    group.bench_function("end", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&end).unwrap());
        });
    });

    // Spanning multiple chunks
    let spanning = RangeRequest::parse("bytes=262000-524288").unwrap();
    group.bench_function("spanning_chunks", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&spanning).unwrap());
        });
    });

    group.finish();
}

// ============================================================================
// Realistic Workload Scenarios
// ============================================================================

fn bench_realistic_video_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_video_streaming");

    // Simulate a 500 MB video file
    let video_size = 500_000_000u64;
    let handler = RangeHandler::new(video_size, CHUNK_SIZE);

    // Initial buffering (first 5 MB)
    let initial_buffer = RangeRequest::parse("bytes=0-5242879").unwrap();
    group.bench_function("initial_buffering_5MB", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&initial_buffer).unwrap());
        });
    });

    // Seeking forward (random access)
    let seek_forward = RangeRequest::parse("bytes=250000000-255242879").unwrap();
    group.bench_function("seek_forward", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&seek_forward).unwrap());
        });
    });

    // Seeking backward
    let seek_backward = RangeRequest::parse("bytes=100000000-105242879").unwrap();
    group.bench_function("seek_backward", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&seek_backward).unwrap());
        });
    });

    // Progressive download (next chunk)
    let progressive = RangeRequest::parse("bytes=5242880-10485759").unwrap();
    group.bench_function("progressive_next_5MB", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&progressive).unwrap());
        });
    });

    group.finish();
}

fn bench_realistic_large_file_download(c: &mut Criterion) {
    let mut group = c.benchmark_group("realistic_large_file_download");

    // Simulate resumable download of 1 GB file
    let file_size = LARGE_CONTENT;
    let handler = RangeHandler::new(file_size, CHUNK_SIZE);

    // Resume from 30% complete
    let resume_30_percent = RangeRequest::parse("bytes=300000000-").unwrap();
    group.bench_function("resume_from_30_percent", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&resume_30_percent).unwrap());
        });
    });

    // Resume from 90% complete (almost done)
    let resume_90_percent = RangeRequest::parse("bytes=900000000-").unwrap();
    group.bench_function("resume_from_90_percent", |b| {
        b.iter(|| {
            let _chunks = black_box(handler.get_required_chunks(&resume_90_percent).unwrap());
        });
    });

    group.finish();
}

fn bench_range_header_parsing_real_world(c: &mut Criterion) {
    let mut group = c.benchmark_group("range_header_parsing_real_world");

    // Common patterns from real HTTP clients
    let headers = vec![
        ("chrome_video", "bytes=0-"),
        ("safari_pdf", "bytes=0-1023"),
        ("firefox_range", "bytes=1024-2047"),
        ("curl_partial", "bytes=500-999"),
        ("wget_resume", "bytes=123456789-"),
    ];

    for (name, header) in headers {
        group.bench_function(name, |b| {
            b.iter(|| {
                let _request = black_box(RangeRequest::parse(header).unwrap());
            });
        });
    }

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    byterange_benches,
    bench_byterange_creation,
    bench_byterange_normalize,
    bench_byterange_length,
);

criterion_group!(
    rangerequest_benches,
    bench_range_request_parse,
    bench_range_request_creation,
    bench_range_request_is_multi,
    bench_range_request_total_bytes,
);

criterion_group!(
    rangehandler_benches,
    bench_range_handler_creation,
    bench_get_required_chunks,
    bench_get_required_chunks_multi_range,
    bench_get_required_chunks_patterns,
);

criterion_group!(
    realistic_benches,
    bench_realistic_video_streaming,
    bench_realistic_large_file_download,
    bench_range_header_parsing_real_world,
);

criterion_main!(
    byterange_benches,
    rangerequest_benches,
    rangehandler_benches,
    realistic_benches,
);

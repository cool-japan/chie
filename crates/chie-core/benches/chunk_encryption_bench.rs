use chie_core::chunk_encryption::{
    ENCRYPTED_CHUNK_SIZE, EncryptedChunk, decrypt_chunk, derive_chunk_key, derive_chunk_nonce,
    encrypt_chunk_with_index,
};
use chie_crypto::generate_key;
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

fn generate_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn bench_derive_chunk_nonce(c: &mut Criterion) {
    let master_key = generate_key();
    let content_id = "QmTest123456789";

    c.bench_function("chunk_encryption_derive_nonce", |b| {
        let mut chunk_index = 0u64;
        b.iter(|| {
            let result = derive_chunk_nonce(
                black_box(&master_key),
                black_box(content_id),
                black_box(chunk_index),
            );
            chunk_index += 1;
            let _ = black_box(result);
        });
    });
}

fn bench_derive_chunk_key(c: &mut Criterion) {
    let master_key = generate_key();
    let content_id = "QmTest123456789";

    c.bench_function("chunk_encryption_derive_key", |b| {
        let mut chunk_index = 0u64;
        b.iter(|| {
            let result = derive_chunk_key(
                black_box(&master_key),
                black_box(content_id),
                black_box(chunk_index),
            );
            chunk_index += 1;
            let _ = black_box(result);
        });
    });
}

fn bench_encrypt_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_encryption_encrypt");
    let master_key = generate_key();
    let content_id = "QmTest123456789";

    for size in [1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("bytes", size), &size, |b, &s| {
            let data = generate_test_data(s);
            let mut chunk_index = 0u64;

            b.iter(|| {
                let result = encrypt_chunk_with_index(
                    black_box(&master_key),
                    black_box(content_id),
                    black_box(chunk_index),
                    black_box(&data),
                );
                chunk_index += 1;
                let _ = black_box(result);
            });
        });
    }

    group.finish();
}

fn bench_decrypt_chunk(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_encryption_decrypt");
    let master_key = generate_key();
    let content_id = "QmTest123456789";

    for size in [1024, 16 * 1024, 64 * 1024, 256 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("bytes", size), &size, |b, &s| {
            let data = generate_test_data(s);

            // Pre-encrypt the chunk
            let encrypted = encrypt_chunk_with_index(&master_key, content_id, 0, &data)
                .expect("encryption failed");

            b.iter(|| {
                let result = decrypt_chunk(
                    black_box(&master_key),
                    black_box(content_id),
                    black_box(&encrypted),
                );
                let _ = black_box(result);
            });
        });
    }

    group.finish();
}

fn bench_encrypt_decrypt_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_encryption_roundtrip");
    let master_key = generate_key();
    let content_id = "QmTest123456789";

    for size in [1024, 64 * 1024, 256 * 1024] {
        group.throughput(Throughput::Bytes(size as u64 * 2)); // Encrypt + decrypt
        group.bench_with_input(BenchmarkId::new("bytes", size), &size, |b, &s| {
            let data = generate_test_data(s);
            let mut chunk_index = 0u64;

            b.iter(|| {
                let encrypted = encrypt_chunk_with_index(
                    black_box(&master_key),
                    black_box(content_id),
                    black_box(chunk_index),
                    black_box(&data),
                )
                .expect("encryption failed");

                let decrypted = decrypt_chunk(
                    black_box(&master_key),
                    black_box(content_id),
                    black_box(&encrypted),
                )
                .expect("decryption failed");

                chunk_index += 1;
                black_box(decrypted);
            });
        });
    }

    group.finish();
}

fn bench_encrypted_chunk_size(c: &mut Criterion) {
    let master_key = generate_key();
    let content_id = "QmTest123456789";
    let data = generate_test_data(ENCRYPTED_CHUNK_SIZE);
    let encrypted =
        encrypt_chunk_with_index(&master_key, content_id, 0, &data).expect("encryption failed");

    c.bench_function("chunk_encryption_size", |b| {
        b.iter(|| {
            black_box(encrypted.size());
        });
    });
}

fn bench_encrypted_chunk_to_bytes(c: &mut Criterion) {
    let master_key = generate_key();
    let content_id = "QmTest123456789";
    let data = generate_test_data(ENCRYPTED_CHUNK_SIZE);
    let encrypted =
        encrypt_chunk_with_index(&master_key, content_id, 0, &data).expect("encryption failed");

    c.bench_function("chunk_encryption_to_bytes", |b| {
        b.iter(|| {
            black_box(encrypted.to_bytes());
        });
    });
}

fn bench_encrypted_chunk_from_bytes(c: &mut Criterion) {
    let master_key = generate_key();
    let content_id = "QmTest123456789";
    let data = generate_test_data(ENCRYPTED_CHUNK_SIZE);
    let encrypted =
        encrypt_chunk_with_index(&master_key, content_id, 0, &data).expect("encryption failed");
    let bytes = encrypted.to_bytes();

    c.bench_function("chunk_encryption_from_bytes", |b| {
        b.iter(|| {
            let _ = black_box(EncryptedChunk::from_bytes(black_box(&bytes)));
        });
    });
}

fn bench_serialize_deserialize_roundtrip(c: &mut Criterion) {
    let master_key = generate_key();
    let content_id = "QmTest123456789";
    let data = generate_test_data(ENCRYPTED_CHUNK_SIZE);
    let encrypted =
        encrypt_chunk_with_index(&master_key, content_id, 0, &data).expect("encryption failed");

    c.bench_function("chunk_encryption_serialize_roundtrip", |b| {
        b.iter(|| {
            let bytes = encrypted.to_bytes();
            let deserialized =
                EncryptedChunk::from_bytes(black_box(&bytes)).expect("deserialization failed");
            black_box(deserialized);
        });
    });
}

fn bench_multiple_chunks_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_encryption_multiple");
    let master_key = generate_key();
    let content_id = "QmTest123456789";

    for chunk_count in [10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("chunks", chunk_count),
            &chunk_count,
            |b, &count| {
                let data = generate_test_data(64 * 1024);

                b.iter(|| {
                    let mut encrypted_chunks = Vec::new();
                    for i in 0..count {
                        let encrypted = encrypt_chunk_with_index(
                            black_box(&master_key),
                            black_box(content_id),
                            black_box(i),
                            black_box(&data),
                        )
                        .expect("encryption failed");
                        encrypted_chunks.push(encrypted);
                    }
                    black_box(encrypted_chunks);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_derive_chunk_nonce,
    bench_derive_chunk_key,
    bench_encrypt_chunk,
    bench_decrypt_chunk,
    bench_encrypt_decrypt_roundtrip,
    bench_encrypted_chunk_size,
    bench_encrypted_chunk_to_bytes,
    bench_encrypted_chunk_from_bytes,
    bench_serialize_deserialize_roundtrip,
    bench_multiple_chunks_encryption
);

criterion_main!(benches);

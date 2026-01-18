//! Benchmarks for chie-crypto cryptographic operations.
//!
//! Run with: cargo bench -p chie-crypto

use chie_crypto::{self, *};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

// Avoid naming conflicts
use chie_crypto::signing::{verify_batch as verify_batch_signing, verify_batch_fast};

// ============================================================================
// Signing Benchmarks
// ============================================================================

fn bench_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing");

    // Key generation
    group.bench_function("keypair_generation", |b| {
        b.iter(|| {
            let keypair = KeyPair::generate();
            black_box(keypair)
        })
    });

    // Signing
    let keypair = KeyPair::generate();
    let message = b"Hello, CHIE Protocol! This is a test message for signing.";
    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = keypair.sign(black_box(message));
            black_box(signature)
        })
    });

    // Verification
    let signature = keypair.sign(message);
    let public_key = keypair.public_key();
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = verify(
                black_box(&public_key),
                black_box(message),
                black_box(&signature),
            );
            black_box(result)
        })
    });

    group.finish();
}

fn bench_batch_signing(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_signing");

    for batch_size in [10, 50, 100, 500].iter() {
        let mut items = Vec::new();
        for _ in 0..*batch_size {
            let keypair = KeyPair::generate();
            let message = b"Test message for batch verification";
            let signature = keypair.sign(message);
            items.push(BatchVerifyItem::new(
                keypair.public_key(),
                message.to_vec(),
                signature,
            ));
        }

        group.bench_with_input(
            BenchmarkId::new("verify_batch", batch_size),
            &items,
            |b, items| {
                b.iter(|| {
                    let result = verify_batch_signing(black_box(items));
                    black_box(result)
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("verify_batch_fast", batch_size),
            &items,
            |b, items| {
                b.iter(|| {
                    let result = verify_batch_fast(black_box(items));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Encryption Benchmarks
// ============================================================================

fn bench_encryption(c: &mut Criterion) {
    let mut group = c.benchmark_group("encryption");

    let key = generate_key();
    let nonce = generate_nonce();

    // Benchmark different data sizes
    for size in [1024, 4096, 65536, 1024 * 1024].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt", size), &data, |b, data| {
            b.iter(|| {
                let ciphertext = encrypt(black_box(data), black_box(&key), black_box(&nonce));
                black_box(ciphertext)
            })
        });

        let ciphertext = encrypt(&data, &key, &nonce).unwrap();
        group.bench_with_input(
            BenchmarkId::new("decrypt", size),
            &ciphertext,
            |b, ciphertext| {
                b.iter(|| {
                    let plaintext =
                        decrypt(black_box(ciphertext), black_box(&key), black_box(&nonce));
                    black_box(plaintext)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Streaming Encryption Benchmarks
// ============================================================================

fn bench_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming");

    let key = generate_key();
    let nonce = generate_nonce();

    // Benchmark chunk encryption
    let chunk = vec![0u8; STREAM_CHUNK_SIZE];
    let mut encryptor = StreamEncryptor::new(&key, &nonce);

    group.throughput(Throughput::Bytes(STREAM_CHUNK_SIZE as u64));
    group.bench_function("encrypt_chunk", |b| {
        b.iter(|| {
            encryptor.reset();
            let ciphertext = encryptor.encrypt_chunk(black_box(&chunk));
            black_box(ciphertext)
        })
    });

    // Benchmark chunked encryption of large data
    for size in [1024 * 1024, 10 * 1024 * 1024].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt_chunked", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let chunks = encrypt_chunked(
                        black_box(data),
                        black_box(&key),
                        black_box(&nonce),
                        STREAM_CHUNK_SIZE,
                    );
                    black_box(chunks)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Hashing Benchmarks
// ============================================================================

fn bench_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("hashing");

    // Benchmark different data sizes
    for size in [1024, 4096, 65536, 1024 * 1024, 10 * 1024 * 1024].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("hash", size), &data, |b, data| {
            b.iter(|| {
                let h = hash(black_box(data));
                black_box(h)
            })
        });

        group.bench_with_input(
            BenchmarkId::new("incremental_hash", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut hasher = IncrementalHasher::new();
                    hasher.update(black_box(data));
                    let h = hasher.finalize();
                    black_box(h)
                })
            },
        );
    }

    // Benchmark keyed hash
    let key = [0u8; 32];
    let data = vec![0u8; 1024];
    group.bench_function("keyed_hash", |b| {
        b.iter(|| {
            let h = keyed_hash(black_box(&key), black_box(&data));
            black_box(h)
        })
    });

    group.finish();
}

fn bench_chunk_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("chunk_hashing");

    for chunk_count in [10, 100, 1000].iter() {
        let chunk = vec![0u8; 4096];

        group.throughput(Throughput::Bytes((*chunk_count * 4096) as u64));
        group.bench_with_input(
            BenchmarkId::new("add_chunks", chunk_count),
            chunk_count,
            |b, count| {
                b.iter(|| {
                    let mut hasher = ChunkHasher::new();
                    for _ in 0..*count {
                        hasher.add_chunk(black_box(&chunk));
                    }
                    let result = hasher.finalize();
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Key Derivation Benchmarks
// ============================================================================

fn bench_kdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("kdf");

    let master_key = generate_key();

    group.bench_function("content_key_derivation", |b| {
        b.iter(|| {
            let key = derive_content_key(
                black_box(&master_key),
                black_box("QmTestContentId123"),
                black_box(0),
            );
            black_box(key)
        })
    });

    group.bench_function("chunk_nonce_derivation", |b| {
        b.iter(|| {
            let nonce = derive_chunk_nonce(
                black_box(&master_key),
                black_box("QmTestContentId123"),
                black_box(0),
            );
            black_box(nonce)
        })
    });

    // Batch key derivation
    for count in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("derive_chunk_keys", count),
            count,
            |b, count| {
                b.iter(|| {
                    let keys = derive_chunk_keys(
                        black_box(&master_key),
                        black_box("QmTestContentId123"),
                        black_box(0),
                        black_box(*count),
                    );
                    black_box(keys)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Key Rotation Benchmarks
// ============================================================================

fn bench_rotation(c: &mut Criterion) {
    let mut group = c.benchmark_group("rotation");

    let master_key = generate_key();
    let policy = RotationPolicy::default();

    group.bench_function("signing_key_ring_generate", |b| {
        b.iter(|| {
            let mut ring = SigningKeyRing::new(master_key, policy.clone());
            let result = ring.generate_key(None);
            black_box(result)
        })
    });

    group.bench_function("encryption_key_ring_generate", |b| {
        b.iter(|| {
            let mut ring = EncryptionKeyRing::new(master_key, policy.clone());
            let result = ring.generate_key(None);
            black_box(result)
        })
    });

    // Re-encryption benchmark
    let old_key = generate_key();
    let new_key = generate_key();
    let old_nonce = generate_nonce();
    let data = vec![0u8; 65536];
    let ciphertext = encrypt(&data, &old_key, &old_nonce).unwrap();
    let re_encryptor = ReEncryptor::new(old_key, new_key, &old_nonce);

    group.throughput(Throughput::Bytes(65536));
    group.bench_function("re_encrypt", |b| {
        b.iter(|| {
            let result = re_encryptor.re_encrypt(black_box(&ciphertext));
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Key Serialization Benchmarks
// ============================================================================

fn bench_keyserde(c: &mut Criterion) {
    let mut group = c.benchmark_group("keyserde");

    let keypair = KeyPair::generate();
    let secret = keypair.secret_key();

    // Hex encoding
    group.bench_function("secret_key_to_hex", |b| {
        b.iter(|| {
            let hex = KeySerializer::secret_key_to_hex(black_box(&secret));
            black_box(hex)
        })
    });

    let hex = KeySerializer::secret_key_to_hex(&secret);
    group.bench_function("secret_key_from_hex", |b| {
        b.iter(|| {
            let key = KeySerializer::secret_key_from_hex(black_box(&hex));
            black_box(key)
        })
    });

    // Base64 encoding
    group.bench_function("secret_key_to_base64", |b| {
        b.iter(|| {
            let b64 = KeySerializer::secret_key_to_base64(black_box(&secret));
            black_box(b64)
        })
    });

    let b64 = KeySerializer::secret_key_to_base64(&secret);
    group.bench_function("secret_key_from_base64", |b| {
        b.iter(|| {
            let key = KeySerializer::secret_key_from_base64(black_box(&b64));
            black_box(key)
        })
    });

    // PEM encoding
    group.bench_function("keypair_to_pem", |b| {
        b.iter(|| {
            let pem = KeySerializer::keypair_to_pem(black_box(&keypair));
            black_box(pem)
        })
    });

    let pem = KeySerializer::keypair_to_pem(&keypair);
    group.bench_function("keypair_from_pem", |b| {
        b.iter(|| {
            let kp = KeySerializer::keypair_from_pem(black_box(&pem));
            black_box(kp)
        })
    });

    group.finish();
}

// ============================================================================
// HSM Provider Benchmarks
// ============================================================================

fn bench_hsm(c: &mut Criterion) {
    let mut group = c.benchmark_group("hsm");

    let provider = SoftwareProvider::new();

    group.bench_function("software_generate_key", |b| {
        b.iter(|| {
            let key_id = provider.generate_key(black_box("bench-key"));
            black_box(key_id)
        })
    });

    let key_id = provider.generate_key("test-key").unwrap();
    let message = b"Test message for HSM signing";

    group.bench_function("software_sign", |b| {
        b.iter(|| {
            let signature = provider.sign(black_box(&key_id), black_box(message));
            black_box(signature)
        })
    });

    let signature = provider.sign(&key_id, message).unwrap();
    let public_key = provider.get_public_key(&key_id).unwrap();

    group.bench_function("software_verify", |b| {
        b.iter(|| {
            let result = provider.verify(
                black_box(&public_key),
                black_box(message),
                black_box(&signature),
            );
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Constant-Time Comparison Benchmarks
// ============================================================================

fn bench_ct(c: &mut Criterion) {
    let mut group = c.benchmark_group("constant_time");

    let arr_a = [42u8; 32];
    let arr_b = [42u8; 32];
    let arr_c = [43u8; 32];

    group.bench_function("ct_eq_equal", |b| {
        b.iter(|| {
            let result = ct_eq(black_box(&arr_a), black_box(&arr_b));
            black_box(result)
        })
    });

    group.bench_function("ct_eq_not_equal", |b| {
        b.iter(|| {
            let result = ct_eq(black_box(&arr_a), black_box(&arr_c));
            black_box(result)
        })
    });

    group.bench_function("ct_eq_32", |b| {
        b.iter(|| {
            let result = ct_eq_32(black_box(&arr_a), black_box(&arr_b));
            black_box(result)
        })
    });

    let secret_a = SecretBytes::new(vec![1, 2, 3, 4, 5]);
    let secret_b = SecretBytes::new(vec![1, 2, 3, 4, 5]);

    group.bench_function("secret_bytes_eq", |b| {
        b.iter(|| {
            let result = black_box(&secret_a) == black_box(&secret_b);
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Commitment Benchmarks
// ============================================================================

fn bench_commitments(c: &mut Criterion) {
    let mut group = c.benchmark_group("commitments");

    // Benchmark commitment on different data sizes
    for size in [1024, 256 * 1024].iter() {
        let data = vec![0u8; *size];

        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::new("commit", size), &data, |b, data| {
            b.iter(|| {
                let (commitment, opening) = commit(black_box(data));
                black_box((commitment, opening))
            })
        });

        let (commitment, opening) = commit(&data);
        group.bench_with_input(
            BenchmarkId::new("verify_commitment", size),
            &data,
            |b, _| {
                b.iter(|| {
                    let result = verify_commitment(black_box(&commitment), black_box(&opening));
                    black_box(result)
                })
            },
        );

        let challenge = generate_challenge();
        group.bench_with_input(
            BenchmarkId::new("possession_proof_generate", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let proof =
                        ChunkPossessionProof::generate(black_box(data), black_box(&challenge));
                    black_box(proof)
                })
            },
        );

        let proof = ChunkPossessionProof::generate(&data, &challenge);
        group.bench_with_input(
            BenchmarkId::new("possession_proof_verify", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let result = proof.verify(black_box(data));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Threshold Signature Benchmarks
// ============================================================================

fn bench_threshold(c: &mut Criterion) {
    let mut group = c.benchmark_group("threshold");

    let message = b"Threshold signature test message";

    // Benchmark different threshold configurations
    for (m, n) in [(2, 3), (3, 5), (5, 10)].iter() {
        let mut keypairs = Vec::new();
        let mut signers = Vec::new();

        for _ in 0..*n {
            let kp = KeyPair::generate();
            signers.push(kp.public_key());
            keypairs.push(kp);
        }

        // Threshold signature creation
        group.bench_with_input(
            BenchmarkId::new("threshold_sig_create", format!("{}_of_{}", m, n)),
            &(m, n, &signers),
            |b, (m, _, signers)| {
                b.iter(|| {
                    let threshold_sig =
                        ThresholdSig::new(black_box((*signers).clone()), black_box(**m));
                    black_box(threshold_sig)
                })
            },
        );

        // Threshold signature verification
        let mut threshold_sig = ThresholdSig::new(signers.clone(), *m).unwrap();
        for keypair in keypairs.iter().take(*m) {
            threshold_sig
                .add_signature(keypair.public_key(), keypair.sign(message))
                .unwrap();
        }

        group.bench_with_input(
            BenchmarkId::new("threshold_sig_verify", format!("{}_of_{}", m, n)),
            &threshold_sig,
            |b, threshold_sig| {
                b.iter(|| {
                    let result = threshold_sig.verify(black_box(message));
                    black_box(result)
                })
            },
        );

        // Multi-sig for all N signers
        let multi_sig_signatures: Vec<_> = keypairs.iter().map(|kp| kp.sign(message)).collect();
        let multi_sig = MultiSig::new(signers.clone(), multi_sig_signatures);

        group.bench_with_input(
            BenchmarkId::new("multi_sig_verify", n),
            &multi_sig,
            |b, multi_sig| {
                b.iter(|| {
                    let result = multi_sig.verify(black_box(message));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// HMAC Benchmarks
// ============================================================================

fn bench_hmac(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac");

    // Key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let key = HmacKey::generate();
            black_box(key)
        })
    });

    let key = HmacKey::generate();
    let message = b"Hello, CHIE Protocol! This is a test message for HMAC.";

    // HMAC-BLAKE3 computation
    group.bench_function("compute_hmac_blake3", |b| {
        b.iter(|| {
            let tag = compute_hmac_blake3(black_box(&key), black_box(message));
            black_box(tag)
        })
    });

    // HMAC-SHA256 computation
    group.bench_function("compute_hmac_sha256", |b| {
        b.iter(|| {
            let tag = compute_hmac_sha256(black_box(&key), black_box(message));
            black_box(tag)
        })
    });

    // HMAC verification
    let tag = compute_hmac(&key, message);
    group.bench_function("verify_hmac", |b| {
        b.iter(|| {
            let result = verify_hmac(black_box(&key), black_box(message), black_box(&tag));
            black_box(result)
        })
    });

    // Tagged HMAC
    let context = b"CHIE:BandwidthProof";
    group.bench_function("compute_tagged_hmac", |b| {
        b.iter(|| {
            let tag = compute_tagged_hmac(black_box(&key), black_box(context), black_box(message));
            black_box(tag)
        })
    });

    // Authenticated message creation
    group.bench_function("authenticated_message_new", |b| {
        b.iter(|| {
            let msg = AuthenticatedMessage::new(black_box(&key), black_box(message.to_vec()));
            black_box(msg)
        })
    });

    // Authenticated message verification
    let auth_msg = AuthenticatedMessage::new(&key, message.to_vec());
    group.bench_function("authenticated_message_verify", |b| {
        b.iter(|| {
            let msg = auth_msg.clone();
            let result = msg.verify(black_box(&key));
            black_box(result)
        })
    });

    // Throughput benchmarks for different message sizes
    for size in [64, 256, 1024, 4096, 16384].iter() {
        let large_message = vec![42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("compute_hmac_throughput", size),
            &large_message,
            |b, msg| {
                b.iter(|| {
                    let tag = compute_hmac(black_box(&key), black_box(msg));
                    black_box(tag)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Accumulator Benchmarks
// ============================================================================

fn bench_accumulator(c: &mut Criterion) {
    let mut group = c.benchmark_group("accumulator");

    // Hash element
    let element = b"peer_id_12345";
    group.bench_function("hash_element", |b| {
        b.iter(|| {
            let hash = hash_element(black_box(element));
            black_box(hash)
        })
    });

    // Add element
    group.bench_function("add_element", |b| {
        b.iter(|| {
            let mut acc = HashAccumulator::new();
            acc.add(black_box(element));
            black_box(acc)
        })
    });

    // Contains check
    let mut acc = HashAccumulator::new();
    acc.add(element);
    group.bench_function("contains", |b| {
        b.iter(|| {
            let result = acc.contains(black_box(element));
            black_box(result)
        })
    });

    // Proof generation
    group.bench_function("prove", |b| {
        b.iter(|| {
            let proof = acc.prove(black_box(element)).unwrap();
            black_box(proof)
        })
    });

    // Proof verification
    let proof = acc.prove(element).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = acc.verify(black_box(element), black_box(&proof));
            black_box(result)
        })
    });

    // Batch operations
    for batch_size in [10, 50, 100, 500].iter() {
        let elements: Vec<Vec<u8>> = (0..*batch_size)
            .map(|i| format!("peer_id_{}", i).into_bytes())
            .collect();
        let element_refs: Vec<&[u8]> = elements.iter().map(|e| e.as_slice()).collect();

        group.bench_with_input(
            BenchmarkId::new("add_batch", batch_size),
            &element_refs,
            |b, elems| {
                b.iter(|| {
                    let mut acc = HashAccumulator::new();
                    let count = acc.add_batch(black_box(elems));
                    black_box(count)
                })
            },
        );
    }

    // Bloom filter benchmarks
    group.bench_function("bloom_create", |b| {
        b.iter(|| {
            let bloom = BloomAccumulator::new(black_box(1000), black_box(0.01));
            black_box(bloom)
        })
    });

    let mut bloom = BloomAccumulator::new(1000, 0.01);
    group.bench_function("bloom_add", |b| {
        b.iter(|| {
            bloom.add(black_box(element));
        })
    });

    bloom.add(element);
    group.bench_function("bloom_might_contain", |b| {
        b.iter(|| {
            let result = bloom.might_contain(black_box(element));
            black_box(result)
        })
    });

    // Compact accumulator verification
    let mut full_acc = HashAccumulator::new();
    for i in 0..100 {
        full_acc.add(format!("peer_{}", i).as_bytes());
    }
    let compact = CompactAccumulator::from_accumulator(&full_acc);
    let test_proof = full_acc.prove(b"peer_50").unwrap();

    group.bench_function("compact_verify", |b| {
        b.iter(|| {
            let result = compact.verify(black_box(b"peer_50"), black_box(&test_proof));
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Bulletproofs Benchmarks (Phase 9)
// ============================================================================

fn bench_bulletproofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("bulletproofs");

    // Benchmark different bit lengths
    for bit_length in [8, 16, 32, 64].iter() {
        let params = chie_crypto::bulletproof::BulletproofParams::new(*bit_length);
        let value = (1u64 << (bit_length.min(&63))) - 1;

        group.bench_with_input(
            BenchmarkId::new("prove_range", bit_length),
            bit_length,
            |b, _| {
                b.iter(|| {
                    let result =
                        chie_crypto::bulletproof::prove_range(black_box(&params), black_box(value));
                    black_box(result)
                })
            },
        );

        let (commitment, proof) = chie_crypto::bulletproof::prove_range(&params, value).unwrap();
        group.bench_with_input(
            BenchmarkId::new("verify_range", bit_length),
            bit_length,
            |b, _| {
                b.iter(|| {
                    let result = chie_crypto::bulletproof::verify_range(
                        black_box(&params),
                        black_box(&commitment),
                        black_box(&proof),
                    );
                    black_box(result)
                })
            },
        );
    }

    // Aggregated proofs
    let params = chie_crypto::bulletproof::BulletproofParams::new(32);
    for count in [1, 5, 10, 50].iter() {
        let values: Vec<u64> = (0..*count).map(|i| 1000u64 + i as u64).collect();

        group.bench_with_input(
            BenchmarkId::new("prove_aggregated", count),
            count,
            |b, _| {
                b.iter(|| {
                    let result = chie_crypto::bulletproof::prove_range_aggregated(
                        black_box(&params),
                        black_box(&values),
                    );
                    black_box(result)
                })
            },
        );

        let aggregated =
            chie_crypto::bulletproof::prove_range_aggregated(&params, &values).unwrap();
        group.bench_with_input(
            BenchmarkId::new("verify_aggregated", count),
            count,
            |b, _| {
                b.iter(|| {
                    let result = chie_crypto::bulletproof::verify_aggregated(
                        black_box(&params),
                        black_box(&aggregated),
                    );
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// DKG Benchmarks (Phase 9)
// ============================================================================

fn bench_dkg(c: &mut Criterion) {
    let mut group = c.benchmark_group("dkg");

    for n in [3, 5, 7, 10].iter() {
        #[allow(clippy::manual_div_ceil)]
        let threshold = (n + 1) / 2; // Simple majority
        let params = chie_crypto::dkg::DkgParams::new(*n, threshold);

        group.bench_with_input(BenchmarkId::new("participant_init", n), n, |b, _| {
            b.iter(|| {
                let result =
                    chie_crypto::dkg::DkgParticipant::new(black_box(&params), black_box(0));
                black_box(result)
            })
        });

        // Generate shares for all participants
        let participants: Vec<_> = (0..*n)
            .map(|i| chie_crypto::dkg::DkgParticipant::new(&params, i))
            .collect();

        // Benchmark generating a share
        group.bench_with_input(BenchmarkId::new("generate_share", n), n, |b, _| {
            b.iter(|| {
                let result = participants[0].generate_share(black_box(1));
                black_box(result)
            })
        });

        // Collect commitments
        let commitments: Vec<_> = participants.iter().map(|p| p.get_commitments()).collect();

        group.bench_with_input(BenchmarkId::new("aggregate_public_key", n), n, |b, _| {
            b.iter(|| {
                let result = chie_crypto::dkg::aggregate_public_key(black_box(&commitments));
                black_box(result)
            })
        });
    }

    group.finish();
}

// ============================================================================
// Polynomial Commitment Benchmarks (Phase 9)
// ============================================================================

fn bench_polycommit(c: &mut Criterion) {
    use curve25519_dalek::scalar::Scalar;

    let mut group = c.benchmark_group("polycommit");

    for degree in [4, 8, 16, 32].iter() {
        let params = chie_crypto::polycommit::PolyCommitParams::new(*degree);
        let coefficients: Vec<Scalar> = (0..=*degree)
            .map(|i| Scalar::from((i as u64) * 100))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("commit_polynomial", degree),
            degree,
            |b, _| {
                b.iter(|| {
                    let result = chie_crypto::polycommit::commit_polynomial(
                        black_box(&params),
                        black_box(&coefficients),
                    );
                    black_box(result)
                })
            },
        );

        let (commitment, opening) =
            chie_crypto::polycommit::commit_polynomial(&params, &coefficients).unwrap();
        let point = Scalar::from(5u64);

        group.bench_with_input(
            BenchmarkId::new("prove_evaluation", degree),
            degree,
            |b, _| {
                b.iter(|| {
                    let result = chie_crypto::polycommit::prove_evaluation(
                        black_box(&params),
                        black_box(&coefficients),
                        black_box(&opening),
                        black_box(point),
                    );
                    black_box(result)
                })
            },
        );

        let proof =
            chie_crypto::polycommit::prove_evaluation(&params, &coefficients, &opening, point)
                .unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify_evaluation", degree),
            degree,
            |b, _| {
                b.iter(|| {
                    let result = chie_crypto::polycommit::verify_evaluation(
                        black_box(&params),
                        black_box(&commitment),
                        black_box(point),
                        black_box(&proof),
                    );
                    black_box(result)
                })
            },
        );

        // Batch evaluation
        let points: Vec<Scalar> = (0..4u64).map(|i| Scalar::from(i * 3)).collect();
        group.bench_with_input(
            BenchmarkId::new("prove_batch_evaluations", degree),
            degree,
            |b, _| {
                b.iter(|| {
                    let result = chie_crypto::polycommit::prove_batch_evaluations(
                        black_box(&params),
                        black_box(&coefficients),
                        black_box(&opening),
                        black_box(&points),
                    );
                    black_box(result)
                })
            },
        );

        let batch_proof = chie_crypto::polycommit::prove_batch_evaluations(
            &params,
            &coefficients,
            &opening,
            &points,
        )
        .unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify_batch_evaluations", degree),
            degree,
            |b, _| {
                b.iter(|| {
                    let result = chie_crypto::polycommit::verify_batch_evaluations(
                        black_box(&params),
                        black_box(&commitment),
                        black_box(&points),
                        black_box(&batch_proof),
                    );
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// VDF Benchmarks (Phase 9)
// ============================================================================

fn bench_vdf(c: &mut Criterion) {
    let mut group = c.benchmark_group("vdf");
    group.sample_size(10); // VDF is slow, reduce samples

    for iterations in [1000, 5000, 10000].iter() {
        let params = chie_crypto::vdf_delay::VdfParams::new(*iterations);
        let input = b"test_input_for_vdf";

        group.bench_with_input(
            BenchmarkId::new("vdf_compute", iterations),
            iterations,
            |b, _| {
                b.iter(|| {
                    let result =
                        chie_crypto::vdf_delay::vdf_compute(black_box(&params), black_box(input));
                    black_box(result)
                })
            },
        );

        let (output, proof) = chie_crypto::vdf_delay::vdf_compute(&params, input);

        group.bench_with_input(
            BenchmarkId::new("vdf_verify", iterations),
            iterations,
            |b, _| {
                b.iter(|| {
                    let result = chie_crypto::vdf_delay::vdf_verify(
                        black_box(&params),
                        black_box(input),
                        black_box(&output),
                        black_box(&proof),
                    );
                    black_box(result)
                })
            },
        );
    }

    // Randomness beacon
    group.bench_function("randomness_beacon", |b| {
        let seed = b"beacon_seed";
        let iterations = 1000u64;
        b.iter(|| {
            let result = chie_crypto::vdf_delay::vdf_randomness_beacon(
                black_box(seed),
                black_box(iterations),
            );
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 11: BLS Signatures
// ============================================================================

fn bench_bls(c: &mut Criterion) {
    let mut group = c.benchmark_group("bls");

    // Keypair generation
    group.bench_function("keypair_generation", |b| {
        b.iter(|| {
            let keypair = BlsKeypair::generate();
            black_box(keypair)
        })
    });

    // Signing
    let keypair = BlsKeypair::generate();
    let message = b"BLS signature test message";
    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = keypair.sign(black_box(message));
            black_box(signature)
        })
    });

    // Verification
    let signature = keypair.sign(message);
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = keypair.verify(black_box(message), black_box(&signature));
            black_box(result)
        })
    });

    // Signature aggregation
    for num_sigs in [10, 50, 100].iter() {
        let mut signatures = Vec::new();
        for _ in 0..*num_sigs {
            let kp = BlsKeypair::generate();
            signatures.push(kp.sign(message));
        }

        group.bench_with_input(
            BenchmarkId::new("aggregate", num_sigs),
            &signatures,
            |b, sigs| {
                b.iter(|| {
                    let result = chie_crypto::bls::aggregate_signatures(black_box(sigs));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Phase 11: Schnorr Signatures
// ============================================================================

fn bench_schnorr(c: &mut Criterion) {
    let mut group = c.benchmark_group("schnorr");

    // Keypair generation
    group.bench_function("keypair_generation", |b| {
        b.iter(|| {
            let keypair = SchnorrKeypair::generate();
            black_box(keypair)
        })
    });

    // Signing
    let keypair = SchnorrKeypair::generate();
    let message = b"Schnorr signature test message";
    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = keypair.sign(black_box(message));
            black_box(signature)
        })
    });

    // Verification
    let signature = keypair.sign(message);
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = keypair.verify(black_box(message), black_box(&signature));
            black_box(result)
        })
    });

    // Batch verification
    for batch_size in [10, 50, 100].iter() {
        let mut messages = Vec::new();
        let mut public_keys = Vec::new();
        let mut signatures = Vec::new();

        for i in 0..*batch_size {
            let kp = SchnorrKeypair::generate();
            let msg = format!("Message {}", i);
            let sig = kp.sign(msg.as_bytes());
            messages.push(msg.into_bytes());
            public_keys.push(kp.public_key());
            signatures.push(sig);
        }

        group.bench_with_input(
            BenchmarkId::new("batch_verify", batch_size),
            batch_size,
            |b, _| {
                let items: Vec<(SchnorrPublicKey, &[u8], SchnorrSignature)> = messages
                    .iter()
                    .zip(public_keys.iter())
                    .zip(signatures.iter())
                    .map(|((msg, pk), sig)| (*pk, msg.as_slice(), *sig))
                    .collect();
                b.iter(|| {
                    let result = chie_crypto::schnorr::batch_verify(black_box(&items));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Phase 11: ElGamal Encryption
// ============================================================================

fn bench_elgamal(c: &mut Criterion) {
    let mut group = c.benchmark_group("elgamal");

    // Keypair generation
    group.bench_function("keypair_generation", |b| {
        b.iter(|| {
            let keypair = ElGamalKeypair::generate();
            black_box(keypair)
        })
    });

    // Encryption
    let keypair = ElGamalKeypair::generate();
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let ciphertext =
                chie_crypto::elgamal::encrypt(black_box(&keypair.public_key()), black_box(42u64));
            black_box(ciphertext)
        })
    });

    // Decryption
    let ciphertext = chie_crypto::elgamal::encrypt(&keypair.public_key(), 42u64);
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let result = chie_crypto::elgamal::decrypt(
                black_box(keypair.secret_key()),
                black_box(&ciphertext),
            );
            black_box(result)
        })
    });

    // Homomorphic addition
    let ct1 = chie_crypto::elgamal::encrypt(&keypair.public_key(), 10u64);
    let ct2 = chie_crypto::elgamal::encrypt(&keypair.public_key(), 20u64);
    group.bench_function("homomorphic_add", |b| {
        b.iter(|| {
            let result = black_box(&ct1).add(black_box(&ct2));
            black_box(result)
        })
    });

    // Re-randomization
    group.bench_function("rerandomize", |b| {
        b.iter(|| {
            let result = ciphertext.rerandomize(black_box(&keypair.public_key()));
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 11: Proxy Re-Encryption
// ============================================================================

fn bench_proxy_re(c: &mut Criterion) {
    let mut group = c.benchmark_group("proxy_re");

    // Keypair generation
    group.bench_function("keypair_generation", |b| {
        b.iter(|| {
            let keypair = ProxyReKeypair::generate();
            black_box(keypair)
        })
    });

    // Encryption
    let alice = ProxyReKeypair::generate();
    let message = b"Proxy re-encryption test message";
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let ciphertext =
                chie_crypto::proxy_re::encrypt(black_box(&alice.public_key()), black_box(message));
            black_box(ciphertext)
        })
    });

    // Decryption
    let ciphertext = chie_crypto::proxy_re::encrypt(&alice.public_key(), message).unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let result = chie_crypto::proxy_re::decrypt(
                black_box(alice.secret_key()),
                black_box(&ciphertext),
            );
            black_box(result)
        })
    });

    // Re-encryption key generation
    let bob = ProxyReKeypair::generate();
    group.bench_function("generate_re_key", |b| {
        b.iter(|| {
            let re_key = chie_crypto::proxy_re::generate_re_key(
                black_box(alice.secret_key()),
                black_box(&bob.public_key()),
            );
            black_box(re_key)
        })
    });

    // Re-encryption
    let re_key = chie_crypto::proxy_re::generate_re_key(alice.secret_key(), &bob.public_key());
    group.bench_function("re_encrypt", |b| {
        b.iter(|| {
            let result =
                chie_crypto::proxy_re::re_encrypt(black_box(&ciphertext), black_box(&re_key));
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 11: Oblivious Transfer
// ============================================================================

fn bench_ot(c: &mut Criterion) {
    let mut group = c.benchmark_group("oblivious_transfer");

    let messages = vec![b"Message 0".to_vec(), b"Message 1".to_vec()];

    // Sender setup
    group.bench_function("sender_init", |b| {
        b.iter(|| {
            let sender = OTSender::new();
            black_box(sender)
        })
    });

    // Receiver request
    let sender = OTSender::new();
    group.bench_function("receiver_request", |b| {
        b.iter(|| {
            let receiver = OTReceiver::new(black_box(2), black_box(0)).unwrap();
            let request = receiver.create_request();
            black_box((receiver, request))
        })
    });

    // Sender respond
    let receiver = OTReceiver::new(2, 0).unwrap();
    let request = receiver.create_request();
    group.bench_function("sender_respond", |b| {
        b.iter(|| {
            let response = sender.respond(black_box(&request), black_box(&messages));
            black_box(response)
        })
    });

    // Receiver extract
    let response = sender.respond(&request, &messages).unwrap();
    group.bench_function("receiver_extract", |b| {
        b.iter(|| {
            let result = receiver.retrieve(black_box(&response));
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 12: Post-Quantum Kyber KEM
// ============================================================================

fn bench_kyber(c: &mut Criterion) {
    let mut group = c.benchmark_group("kyber");

    // Kyber512
    group.bench_function("kyber512_keygen", |b| {
        b.iter(|| {
            let keypair = Kyber512::keypair();
            black_box(keypair)
        })
    });

    let (pk512, sk512) = Kyber512::keypair();
    group.bench_function("kyber512_encapsulate", |b| {
        b.iter(|| {
            let result = Kyber512::encapsulate(black_box(&pk512));
            black_box(result)
        })
    });

    let (ciphertext512, _) = Kyber512::encapsulate(&pk512).unwrap();
    group.bench_function("kyber512_decapsulate", |b| {
        b.iter(|| {
            let result = Kyber512::decapsulate(black_box(&ciphertext512), black_box(&sk512));
            black_box(result)
        })
    });

    // Kyber768
    group.bench_function("kyber768_keygen", |b| {
        b.iter(|| {
            let keypair = Kyber768::keypair();
            black_box(keypair)
        })
    });

    let (pk768, _sk768) = Kyber768::keypair();
    group.bench_function("kyber768_encapsulate", |b| {
        b.iter(|| {
            let result = Kyber768::encapsulate(black_box(&pk768));
            black_box(result)
        })
    });

    // Kyber1024
    group.bench_function("kyber1024_keygen", |b| {
        b.iter(|| {
            let keypair = Kyber1024::keypair();
            black_box(keypair)
        })
    });

    let (pk1024, _sk1024) = Kyber1024::keypair();
    group.bench_function("kyber1024_encapsulate", |b| {
        b.iter(|| {
            let result = Kyber1024::encapsulate(black_box(&pk1024));
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 12: Post-Quantum Dilithium Signatures
// ============================================================================

fn bench_dilithium(c: &mut Criterion) {
    let mut group = c.benchmark_group("dilithium");

    let message = b"Post-quantum signature test message";

    // Dilithium2
    group.bench_function("dilithium2_keygen", |b| {
        b.iter(|| {
            let keypair = Dilithium2::keypair();
            black_box(keypair)
        })
    });

    let (pk2, sk2) = Dilithium2::keypair();
    group.bench_function("dilithium2_sign", |b| {
        b.iter(|| {
            let signature = Dilithium2::sign(black_box(message), black_box(&sk2));
            black_box(signature)
        })
    });

    let signature2 = Dilithium2::sign(message, &sk2);
    group.bench_function("dilithium2_verify", |b| {
        b.iter(|| {
            let result =
                Dilithium2::verify(black_box(message), black_box(&signature2), black_box(&pk2));
            black_box(result)
        })
    });

    // Dilithium3
    group.bench_function("dilithium3_keygen", |b| {
        b.iter(|| {
            let keypair = Dilithium3::keypair();
            black_box(keypair)
        })
    });

    let (_pk3, sk3) = Dilithium3::keypair();
    group.bench_function("dilithium3_sign", |b| {
        b.iter(|| {
            let signature = Dilithium3::sign(black_box(message), black_box(&sk3));
            black_box(signature)
        })
    });

    // Dilithium5
    group.bench_function("dilithium5_keygen", |b| {
        b.iter(|| {
            let keypair = Dilithium5::keypair();
            black_box(keypair)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 12: SPHINCS+ Hash-Based Signatures
// ============================================================================

fn bench_sphincs(c: &mut Criterion) {
    let mut group = c.benchmark_group("sphincs");

    let message = b"Hash-based signature test message";

    // SPHINCS-SHAKE-128f
    group.bench_function("sphincs128_keygen", |b| {
        b.iter(|| {
            let keypair = SphincsSHAKE128f::keypair();
            black_box(keypair)
        })
    });

    let (pk128, sk128) = SphincsSHAKE128f::keypair();
    group.bench_function("sphincs128_sign", |b| {
        b.iter(|| {
            let signature = SphincsSHAKE128f::sign(black_box(message), black_box(&sk128));
            black_box(signature)
        })
    });

    let signature128 = SphincsSHAKE128f::sign(message, &sk128);
    group.bench_function("sphincs128_verify", |b| {
        b.iter(|| {
            let result = SphincsSHAKE128f::verify(
                black_box(message),
                black_box(&signature128),
                black_box(&pk128),
            );
            black_box(result)
        })
    });

    // SPHINCS-SHAKE-256f
    group.bench_function("sphincs256_keygen", |b| {
        b.iter(|| {
            let keypair = SphincsSHAKE256f::keypair();
            black_box(keypair)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 13: Private Set Intersection
// ============================================================================

fn bench_psi(c: &mut Criterion) {
    let mut group = c.benchmark_group("psi");

    // Hash-based PSI
    for set_size in [100, 500, 1000].iter() {
        let _client_set: Vec<Vec<u8>> = (0..*set_size)
            .map(|i| format!("client_item_{}", i).into_bytes())
            .collect();
        let server_set: Vec<Vec<u8>> = ((*set_size / 2)..*set_size + (*set_size / 2))
            .map(|i| format!("client_item_{}", i).into_bytes())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("hash_psi_client", set_size),
            set_size,
            |b, _| {
                b.iter(|| {
                    let client = PsiClient::new();
                    black_box(client)
                })
            },
        );

        let _client = PsiClient::new();
        group.bench_with_input(
            BenchmarkId::new("hash_psi_server", set_size),
            &server_set,
            |b, server_set| {
                b.iter(|| {
                    let server = PsiServer::new();
                    let message = server.encode_set(black_box(server_set));
                    black_box(message)
                })
            },
        );
    }

    // Bloom filter PSI
    group.bench_function("bloom_psi_setup", |b| {
        let set: Vec<Vec<u8>> = (0..1000)
            .map(|i| format!("item_{}", i).into_bytes())
            .collect();
        b.iter(|| {
            let server = BloomPsiServer::new(black_box(1000), black_box(0.01));
            let _message = server.encode_set(black_box(&set));
            black_box(server)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 13: Forward-Secure Signatures
// ============================================================================

fn bench_forward_secure(c: &mut Criterion) {
    let mut group = c.benchmark_group("forward_secure");

    let message = b"Forward-secure signature test message";

    // Keypair generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let keypair = ForwardSecureBuilder::new()
                .max_periods(black_box(10))
                .build();
            black_box(keypair)
        })
    });

    // Signing
    let keypair = ForwardSecureBuilder::new().max_periods(10).build();
    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = keypair.sign(black_box(message));
            black_box(signature)
        })
    });

    // Verification
    let signature = keypair.sign(message).unwrap();
    let public_key = keypair.public_key().clone();
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = signature.verify(black_box(message), black_box(&public_key));
            black_box(result)
        })
    });

    // Key evolution
    group.bench_function("evolve", |b| {
        let mut kp = ForwardSecureBuilder::new().max_periods(100).build();
        b.iter(|| {
            let result = kp.evolve();
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 13: Searchable Encryption
// ============================================================================

fn bench_searchable(c: &mut Criterion) {
    let mut group = c.benchmark_group("searchable");

    let key = SearchableEncryption::new();

    // Index building
    for num_docs in [100, 500, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("index_build", num_docs),
            num_docs,
            |b, &n| {
                b.iter(|| {
                    let mut builder = EncryptedIndexBuilder::new(black_box(&key));
                    for i in 0..n {
                        let keywords = vec![b"keyword1".to_vec(), b"keyword2".to_vec()];
                        builder = builder.add_document(black_box(i as u64), black_box(&keywords));
                    }
                    let index = builder.build();
                    black_box(index)
                })
            },
        );
    }

    // Trapdoor generation
    group.bench_function("trapdoor_generate", |b| {
        b.iter(|| {
            let trapdoor = key.generate_trapdoor(black_box(b"keyword1"));
            black_box(trapdoor)
        })
    });

    // Search
    let mut builder = EncryptedIndexBuilder::new(&key);
    for i in 0..1000 {
        let keywords = vec![b"keyword1".to_vec(), b"keyword2".to_vec()];
        builder = builder.add_document(i as u64, &keywords);
    }
    let index = builder.build();
    let trapdoor = key.generate_trapdoor(b"keyword1");

    group.bench_function("search", |b| {
        b.iter(|| {
            let results = index.search(black_box(&trapdoor));
            black_box(results)
        })
    });

    group.finish();
}

// ============================================================================
// Phase 13: Certified Deletion
// ============================================================================

fn bench_certified_deletion(c: &mut Criterion) {
    let mut group = c.benchmark_group("certified_deletion");

    let data = b"Sensitive data for certified deletion";

    // Encryption with witness
    group.bench_function("encrypt", |b| {
        let mut cd = CertifiedDeletion::new();
        b.iter(|| {
            let result = cd.encrypt(black_box(data));
            black_box(result)
        })
    });

    // Decryption
    let mut cd = CertifiedDeletion::new();
    let encrypted = cd.encrypt(data);
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let result = cd.decrypt(black_box(&encrypted));
            black_box(result)
        })
    });

    // Deletion certificate generation
    group.bench_function("delete", |b| {
        let mut cd = CertifiedDeletion::new();
        let enc = cd.encrypt(data);
        b.iter(|| {
            let result = cd.certify_deletion(black_box(&enc));
            black_box(result)
        })
    });

    // Deletion verification
    let mut cd2 = CertifiedDeletion::new();
    let encrypted2 = cd2.encrypt(data);
    let cert = cd2.certify_deletion(&encrypted2).unwrap();
    group.bench_function("verify_deletion", |b| {
        b.iter(|| {
            let result = cert.verify(black_box(encrypted2.commitment()));
            black_box(result)
        })
    });

    // Batch deletion
    for batch_size in [10, 50, 100].iter() {
        let mut cd3 = CertifiedDeletion::new();
        let mut items = Vec::new();
        for _ in 0..*batch_size {
            items.push(cd3.encrypt(data));
        }

        group.bench_with_input(
            BenchmarkId::new("batch_delete", batch_size),
            &items,
            |b, items| {
                b.iter(|| {
                    let mut batch = BatchDeletion::new();
                    let result = batch.certify_batch_deletion(black_box(items));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Additional Core Modules: VRF
// ============================================================================

fn bench_vrf(c: &mut Criterion) {
    let mut group = c.benchmark_group("vrf");

    // Keypair generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let keypair = VrfSecretKey::generate();
            black_box(keypair)
        })
    });

    // VRF proof generation
    let secret_key = VrfSecretKey::generate();
    let input = b"VRF input data";
    group.bench_function("prove", |b| {
        b.iter(|| {
            let proof = secret_key.prove(black_box(input));
            black_box(proof)
        })
    });

    // VRF proof verification
    let public_key = secret_key.public_key();
    let proof = secret_key.prove(input);
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = public_key.verify(black_box(input), black_box(&proof));
            black_box(result)
        })
    });

    // Bandwidth challenge
    group.bench_function("bandwidth_challenge", |b| {
        b.iter(|| {
            let proof = chie_crypto::vrf::generate_bandwidth_challenge(
                black_box(&secret_key),
                black_box(b"node_id_123"),
                black_box(b"chunk_id_456"),
                black_box(1234567890u64),
            );
            black_box(proof)
        })
    });

    group.finish();
}

// ============================================================================
// Additional Core Modules: Merkle Trees
// ============================================================================

fn bench_merkle(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");

    // Tree construction
    for num_leaves in [100, 500, 1000, 5000].iter() {
        let leaves: Vec<Vec<u8>> = (0..*num_leaves)
            .map(|i| format!("leaf_{}", i).into_bytes())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("tree_build", num_leaves),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let tree = MerkleTree::from_leaves(black_box(leaves));
                    black_box(tree)
                })
            },
        );
    }

    // Proof generation
    let leaves: Vec<Vec<u8>> = (0..1000)
        .map(|i| format!("leaf_{}", i).into_bytes())
        .collect();
    let tree = MerkleTree::from_leaves(&leaves);

    group.bench_function("proof_generate", |b| {
        b.iter(|| {
            let proof = tree.generate_proof(black_box(100));
            black_box(proof)
        })
    });

    // Proof verification
    let proof = tree.generate_proof(100).unwrap();
    let root = tree.root();
    group.bench_function("proof_verify", |b| {
        b.iter(|| {
            let result = proof.verify(black_box(root), black_box(&leaves[100]), black_box(100));
            black_box(result)
        })
    });

    // Incremental builder
    group.bench_function("incremental_build", |b| {
        b.iter(|| {
            let mut builder = IncrementalMerkleBuilder::new();
            for i in 0..1000 {
                let leaf = format!("leaf_{}", i).into_bytes();
                builder.add_leaf(black_box(&leaf));
            }
            let tree = builder.finalize();
            black_box(tree)
        })
    });

    group.finish();
}

// ============================================================================
// Additional Core Modules: Ring Signatures
// ============================================================================

fn bench_ring(c: &mut Criterion) {
    let mut group = c.benchmark_group("ring");

    let message = b"Ring signature test message";

    // Ring signature (various ring sizes)
    for ring_size in [3, 5, 10, 20].iter() {
        let mut ring = Vec::new();
        let mut signer_keypair = None;
        let signer_index = ring_size / 2;

        for i in 0..*ring_size {
            let kp = KeyPair::generate();
            if i == signer_index {
                signer_keypair = Some(kp.clone());
            }
            ring.push(kp.public_key());
        }

        let signer = signer_keypair.unwrap();

        group.bench_with_input(BenchmarkId::new("sign", ring_size), ring_size, |b, _| {
            b.iter(|| {
                let signature = chie_crypto::ring::sign_ring(
                    black_box(&signer),
                    black_box(&ring),
                    black_box(message),
                );
                black_box(signature)
            })
        });

        let signature = chie_crypto::ring::sign_ring(&signer, &ring, message).unwrap();

        group.bench_with_input(BenchmarkId::new("verify", ring_size), ring_size, |b, _| {
            b.iter(|| {
                let result = chie_crypto::ring::verify_ring(
                    black_box(&ring),
                    black_box(message),
                    black_box(&signature),
                );
                black_box(result)
            })
        });
    }

    group.finish();
}

// ============================================================================
// Additional Core Modules: Linkable Ring Signatures
// ============================================================================

fn bench_linkable_ring(c: &mut Criterion) {
    let mut group = c.benchmark_group("linkable_ring");

    let message = b"Linkable ring signature test message";
    let ring_size = 5;
    let mut ring = Vec::new();
    let signer_index = 2;

    for _ in 0..ring_size {
        ring.push(KeyPair::generate().public_key());
    }
    let signer = KeyPair::generate();
    ring[signer_index] = signer.public_key();

    // Sign
    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature = chie_crypto::linkable_ring::sign_linkable(
                black_box(&signer),
                black_box(&ring),
                black_box(message),
            );
            black_box(signature)
        })
    });

    // Verify
    let signature = chie_crypto::linkable_ring::sign_linkable(&signer, &ring, message).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = chie_crypto::linkable_ring::verify_linkable(
                black_box(&ring),
                black_box(message),
                black_box(&signature),
            );
            black_box(result)
        })
    });

    // Double-sign check
    let signature2 =
        chie_crypto::linkable_ring::sign_linkable(&signer, &ring, b"Another message").unwrap();
    group.bench_function("check_double_sign", |b| {
        b.iter(|| {
            let result = chie_crypto::linkable_ring::check_double_sign(
                black_box(&signature),
                black_box(&signature2),
            );
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Additional Core Modules: Shamir Secret Sharing
// ============================================================================

fn bench_shamir(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir");

    let secret = b"This is a secret message to be shared";

    // Split secret
    for threshold in [3, 5, 7].iter() {
        let total_shares = threshold + 2;
        group.bench_with_input(
            BenchmarkId::new("split", format!("{}_of_{}", threshold, total_shares)),
            threshold,
            |b, &t| {
                b.iter(|| {
                    let shares = chie_crypto::shamir::split(
                        black_box(secret),
                        black_box(t),
                        black_box(total_shares),
                    );
                    black_box(shares)
                })
            },
        );
    }

    // Reconstruct secret
    let shares = chie_crypto::shamir::split(secret, 3, 5).unwrap();
    group.bench_function("reconstruct", |b| {
        b.iter(|| {
            let recovered = chie_crypto::shamir::reconstruct(black_box(&shares[0..3]));
            black_box(recovered)
        })
    });

    group.finish();
}

// ============================================================================
// Additional Core Modules: Time-Lock Encryption
// ============================================================================

fn bench_timelock(c: &mut Criterion) {
    let mut group = c.benchmark_group("timelock");

    let message = b"Time-locked secret message";

    // Encrypt with different iteration counts
    for iterations in [1000, 5000, 10000].iter() {
        let params = TimeParams::new(*iterations);
        group.bench_with_input(
            BenchmarkId::new("encrypt", iterations),
            &params,
            |b, params| {
                b.iter(|| {
                    let ciphertext = chie_crypto::timelock::timelock_encrypt(
                        black_box(message),
                        black_box(params),
                    );
                    black_box(ciphertext)
                })
            },
        );
    }

    // Decrypt
    let params1000 = TimeParams::new(1000);
    let ciphertext = chie_crypto::timelock::timelock_encrypt(message, &params1000).unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let result = chie_crypto::timelock::timelock_decrypt(black_box(&ciphertext));
            black_box(result)
        })
    });

    // Puzzle-based encryption
    let params5000 = TimeParams::new(5000);
    let puzzle = TimeLockPuzzle::new(&params5000).unwrap();
    group.bench_function("encrypt_with_puzzle", |b| {
        b.iter(|| {
            let ciphertext = chie_crypto::timelock::timelock_encrypt_with_puzzle(
                black_box(message),
                black_box(&puzzle),
            );
            black_box(ciphertext)
        })
    });

    group.finish();
}

// ============================================================================
// Additional Core Modules: Onion Encryption
// ============================================================================

fn bench_onion(c: &mut Criterion) {
    let mut group = c.benchmark_group("onion");

    let message = b"Secret onion-routed message";

    // Create onion with different hop counts
    for num_hops in [3, 5, 7].iter() {
        let mut hop_keys = Vec::new();
        for _ in 0..*num_hops {
            hop_keys.push(KeyPair::generate());
        }
        let hop_public_keys: Vec<_> = hop_keys.iter().map(|k| k.public_key()).collect();

        group.bench_with_input(BenchmarkId::new("create", num_hops), num_hops, |b, _| {
            b.iter(|| {
                let onion = chie_crypto::onion::create_onion(
                    black_box(message),
                    black_box(&hop_public_keys),
                );
                black_box(onion)
            })
        });

        // Peel onion
        let onion = chie_crypto::onion::create_onion(message, &hop_public_keys).unwrap();
        group.bench_with_input(
            BenchmarkId::new("peel_first_layer", num_hops),
            num_hops,
            |b, _| {
                b.iter(|| {
                    let packet = onion.clone();
                    let result = packet.peel_layer(black_box(&hop_keys[0]));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Additional Core Modules: Proof of Storage
// ============================================================================

fn bench_pos(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_of_storage");

    // Setup prover with different file sizes
    for file_size in [1024 * 1024, 10 * 1024 * 1024].iter() {
        // 1MB, 10MB
        let data = vec![0x42u8; *file_size];

        group.bench_with_input(
            BenchmarkId::new("prover_init", file_size / (1024 * 1024)),
            file_size,
            |b, _| {
                b.iter(|| {
                    let prover = StorageProver::new(black_box(&data));
                    black_box(prover)
                })
            },
        );
    }

    // Challenge-response
    let data = vec![0x42u8; 1024 * 1024];
    let prover = StorageProver::new(&data);
    let verifier = StorageVerifier::new(*prover.merkle_root(), DEFAULT_CHUNK_SIZE);

    let challenge = verifier.create_challenge_for_chunks(prover.num_chunks());
    group.bench_function("generate_proof", |b| {
        b.iter(|| {
            let proof = prover.generate_proof(black_box(&challenge));
            black_box(proof)
        })
    });

    let proof = prover.generate_proof(&challenge).unwrap();
    group.bench_function("verify_proof", |b| {
        b.iter(|| {
            let result = verifier.verify_proof(black_box(&challenge), black_box(&proof));
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// Additional Core Modules: Key Exchange
// ============================================================================

fn bench_keyexchange(c: &mut Criterion) {
    let mut group = c.benchmark_group("keyexchange");

    // Keypair generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let keypair = KeyExchangeKeypair::generate();
            black_box(keypair)
        })
    });

    // Key exchange
    let alice = KeyExchangeKeypair::generate();
    let bob = KeyExchangeKeypair::generate();

    group.bench_function("exchange", |b| {
        b.iter(|| {
            let shared_secret = alice.exchange(black_box(bob.public_key()));
            black_box(shared_secret)
        })
    });

    // Ephemeral key exchange
    group.bench_function("ephemeral_exchange", |b| {
        b.iter(|| {
            let alice_ephemeral = chie_crypto::keyexchange::ephemeral_keypair();
            let bob_ephemeral = chie_crypto::keyexchange::ephemeral_keypair();
            let shared1 = alice_ephemeral.exchange(bob_ephemeral.public_key());
            let shared2 = bob_ephemeral.exchange(alice_ephemeral.public_key());
            black_box((shared1, shared2))
        })
    });

    // Exchange and derive
    group.bench_function("exchange_and_derive", |b| {
        b.iter(|| {
            let key = chie_crypto::keyexchange::exchange_and_derive(
                black_box(&alice),
                black_box(bob.public_key()),
                black_box(b"CHIE Protocol"),
            );
            black_box(key)
        })
    });

    group.finish();
}

// ============================================================================
// Additional Core Modules: Pedersen Commitments
// ============================================================================

fn bench_pedersen(c: &mut Criterion) {
    let mut group = c.benchmark_group("pedersen");

    // Commitment creation
    group.bench_function("commit", |b| {
        b.iter(|| {
            let (commitment, opening) = chie_crypto::pedersen::commit(black_box(42u64));
            black_box((commitment, opening))
        })
    });

    // Commitment verification
    let (commitment, opening) = chie_crypto::pedersen::commit(42u64);
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = chie_crypto::pedersen::verify(
                black_box(&commitment),
                black_box(42u64),
                black_box(&opening),
            );
            black_box(result)
        })
    });

    // Homomorphic addition
    let (c1, o1) = chie_crypto::pedersen::commit(10u64);
    let (c2, o2) = chie_crypto::pedersen::commit(20u64);
    group.bench_function("homomorphic_add", |b| {
        b.iter(|| {
            let c_sum = black_box(&c1).add(black_box(&c2));
            let o_sum = black_box(&o1).add(black_box(&o2));
            black_box((c_sum, o_sum))
        })
    });

    // Batch operations
    for batch_size in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch_commit", batch_size),
            batch_size,
            |b, &n| {
                b.iter(|| {
                    let mut commitments = Vec::new();
                    for i in 0..n {
                        commitments.push(chie_crypto::pedersen::commit(black_box(i as u64)));
                    }
                    black_box(commitments)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Additional Core Modules: Blind Signatures
// ============================================================================

fn bench_blind(c: &mut Criterion) {
    let mut group = c.benchmark_group("blind");

    // Signer setup
    group.bench_function("signer_init", |b| {
        b.iter(|| {
            let signer = BlindSigner::generate();
            black_box(signer)
        })
    });

    // Token creation (user side)
    group.bench_function("create_token", |b| {
        b.iter(|| {
            let result = BlindSignatureProtocol::create_token(black_box(100), black_box(1000000));
            black_box(result)
        })
    });

    // Token issuance (issuer signs commitment)
    let signer = BlindSigner::generate();
    let (commitment, token, blinding) = BlindSignatureProtocol::create_token(100, 1000000);
    group.bench_function("issue_token", |b| {
        b.iter(|| {
            let signed =
                BlindSignatureProtocol::issue_token(black_box(&signer), black_box(&commitment));
            black_box(signed)
        })
    });

    // Token redemption preparation
    let signed = BlindSignatureProtocol::issue_token(&signer, &commitment);
    group.bench_function("prepare_redemption", |b| {
        b.iter(|| {
            let redeemable = BlindSignatureProtocol::prepare_redemption(
                black_box(token.clone()),
                black_box(blinding.clone()),
                black_box(signed.clone()),
            );
            black_box(redeemable)
        })
    });

    // Token verification
    let redeemable = BlindSignatureProtocol::prepare_redemption(token, blinding, signed);
    let public_key = signer.public_key();
    group.bench_function("verify_token", |b| {
        b.iter(|| {
            let result = BlindSignatureProtocol::verify_and_redeem(
                black_box(&public_key),
                black_box(&redeemable),
                black_box(500000),
            );
            black_box(result)
        })
    });

    // Batch token issuance
    for batch_size in [10, 50, 100].iter() {
        group.bench_with_input(
            BenchmarkId::new("batch_issue", batch_size),
            batch_size,
            |b, &n| {
                b.iter(|| {
                    let mut tokens = Vec::new();
                    for _ in 0..n {
                        let (comm, _tok, _blind) = BlindSignatureProtocol::create_token(
                            black_box(100),
                            black_box(1000000),
                        );
                        let signed = BlindSignatureProtocol::issue_token(&signer, &comm);
                        tokens.push(signed);
                    }
                    black_box(tokens)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Additional Core Modules: Range Proofs
// ============================================================================

fn bench_rangeproof(c: &mut Criterion) {
    let mut group = c.benchmark_group("rangeproof");
    let keypair = KeyPair::generate();
    let secret_key = keypair.secret_key();
    let public_key = keypair.public_key();

    // Proof generation
    for value in [100u64, 1000u64, 10000u64].iter() {
        group.bench_with_input(BenchmarkId::new("prove", value), value, |b, &v| {
            b.iter(|| {
                let proof =
                    RangeProof::prove(black_box(&secret_key), black_box(v), black_box(65535));
                black_box(proof)
            })
        });
    }

    // Proof verification
    let proof = RangeProof::prove(&secret_key, 1000, 65535).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = proof.verify(black_box(&public_key), black_box(65535));
            black_box(result)
        })
    });

    // Batch proofs
    for batch_size in [5, 10, 20].iter() {
        let values: Vec<(u64, u64)> = (0..*batch_size)
            .map(|i| ((i as u64 + 1) * 100, 65535u64))
            .collect();

        group.bench_with_input(
            BenchmarkId::new("batch_prove", batch_size),
            &values,
            |b, vals| {
                b.iter(|| {
                    let proof = BatchRangeProof::prove(black_box(&secret_key), black_box(vals));
                    black_box(proof)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Phase 16: OPRF Benchmarks
// ============================================================================

fn bench_oprf(c: &mut Criterion) {
    let mut group = c.benchmark_group("oprf");

    // Server setup
    group.bench_function("server_setup", |b| {
        b.iter(|| {
            let server = OprfServer::new();
            black_box(server)
        })
    });

    // Client blinding
    let server = OprfServer::new();
    let input = b"user@example.com";
    group.bench_function("client_blind", |b| {
        b.iter(|| {
            let (client, blinded) = OprfClient::blind(black_box(input));
            black_box((client, blinded))
        })
    });

    // Server evaluation
    let (client, blinded) = OprfClient::blind(input);
    group.bench_function("server_evaluate", |b| {
        b.iter(|| {
            let output = server.evaluate(black_box(&blinded));
            black_box(output)
        })
    });

    // Client unblind
    let blinded_output = server.evaluate(&blinded);
    group.bench_function("client_unblind", |b| {
        b.iter(|| {
            let output = client.unblind(black_box(&blinded_output));
            black_box(output)
        })
    });

    // Full OPRF protocol
    group.bench_function("full_protocol", |b| {
        b.iter(|| {
            let server = OprfServer::new();
            let (client, blinded) = OprfClient::blind(input);
            let blinded_output = server.evaluate(&blinded);
            let output = client.unblind(&blinded_output);
            black_box(output)
        })
    });

    // Batch OPRF
    for size in [10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::new("batch_oprf", size), size, |b, &size| {
            b.iter(|| {
                let server = OprfServer::new();

                let inputs: Vec<Vec<u8>> = (0..size)
                    .map(|i| format!("user{}@example.com", i).into_bytes())
                    .collect();
                let input_refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();

                let (batch_client, blinded_inputs) = BatchOprfClient::blind_batch(&input_refs);

                let blinded_outputs: Vec<_> = blinded_inputs
                    .iter()
                    .map(|blinded| server.evaluate(blinded))
                    .collect();

                let outputs = batch_client.unblind_batch(&blinded_outputs);

                black_box(outputs)
            })
        });
    }

    group.finish();
}

// ============================================================================
// Phase 16: Identity-Based Encryption Benchmarks
// ============================================================================

fn bench_ibe(c: &mut Criterion) {
    let mut group = c.benchmark_group("ibe");

    // Master key generation
    group.bench_function("master_setup", |b| {
        b.iter(|| {
            let master = IbeMaster::generate();
            black_box(master)
        })
    });

    // Secret key extraction
    let master = IbeMaster::generate();
    group.bench_function("extract_secret_key", |b| {
        b.iter(|| {
            let sk = master.extract_secret_key(black_box("alice@example.com"));
            black_box(sk)
        })
    });

    // Encryption
    let params = master.public_params();
    let plaintext = b"Secret message";
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            let ct = params
                .encrypt(black_box("alice@example.com"), black_box(plaintext))
                .unwrap();
            black_box(ct)
        })
    });

    // Decryption
    let alice_sk = master.extract_secret_key("alice@example.com");
    let ct = params.encrypt("alice@example.com", plaintext).unwrap();
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            let pt = alice_sk.decrypt(black_box(&ct)).unwrap();
            black_box(pt)
        })
    });

    // Full encryption + decryption
    group.bench_function("full_protocol", |b| {
        b.iter(|| {
            let master = IbeMaster::generate();
            let params = master.public_params();
            let sk = master.extract_secret_key("alice@example.com");
            let ct = params.encrypt("alice@example.com", plaintext).unwrap();
            let pt = sk.decrypt(&ct).unwrap();
            black_box(pt)
        })
    });

    // Throughput for various message sizes
    for size in [64, 256, 1024, 4096].iter() {
        let message = vec![0x42u8; *size];
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt_throughput", size),
            size,
            |b, _| {
                b.iter(|| {
                    let ct = params
                        .encrypt("alice@example.com", black_box(&message))
                        .unwrap();
                    black_box(ct)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Phase 16: Aggregate MAC Benchmarks
// ============================================================================

fn bench_aggregate_mac(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate_mac");

    // Key generation
    group.bench_function("key_generation", |b| {
        b.iter(|| {
            let key = AggregateMacKey::generate();
            black_box(key)
        })
    });

    // Single message authentication
    let key = AggregateMacKey::generate();
    let message = b"test message";
    group.bench_function("authenticate_single", |b| {
        b.iter(|| {
            let tag = key.authenticate(black_box(message));
            black_box(tag)
        })
    });

    // Single message verification
    let tag = key.authenticate(message);
    group.bench_function("verify_single", |b| {
        b.iter(|| {
            let result = key.verify(black_box(message), black_box(&tag));
            black_box(result)
        })
    });

    // Batch authentication
    for batch_size in [10, 50, 100, 500].iter() {
        let messages: Vec<Vec<u8>> = (0..*batch_size)
            .map(|i| format!("message{}", i).into_bytes())
            .collect();
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

        group.bench_with_input(
            BenchmarkId::new("authenticate_batch", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    let tag = key.authenticate_batch(black_box(&message_refs)).unwrap();
                    black_box(tag)
                })
            },
        );
    }

    // Batch verification
    for batch_size in [10, 50, 100, 500].iter() {
        let messages: Vec<Vec<u8>> = (0..*batch_size)
            .map(|i| format!("message{}", i).into_bytes())
            .collect();
        let message_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        let tag = key.authenticate_batch(&message_refs).unwrap();

        group.bench_with_input(
            BenchmarkId::new("verify_batch", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    let result = key.verify_batch(black_box(&message_refs), black_box(&tag));
                    black_box(result)
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// Phase 16: Advanced Commitment Benchmarks
// ============================================================================

fn bench_advanced_commitments(c: &mut Criterion) {
    let mut group = c.benchmark_group("advanced_commitments");

    // Trapdoor commitment setup
    group.bench_function("trapdoor_setup", |b| {
        b.iter(|| {
            let (commitment, trapdoor) = TrapdoorCommitment::setup();
            black_box((commitment, trapdoor))
        })
    });

    // Trapdoor commitment
    let (commitment, trapdoor) = TrapdoorCommitment::setup();
    let value = b"secret value";
    group.bench_function("trapdoor_commit", |b| {
        b.iter(|| {
            let (com, opening) = commitment.commit(black_box(value));
            black_box((com, opening))
        })
    });

    // Trapdoor verification
    let (com, opening) = commitment.commit(value);
    group.bench_function("trapdoor_verify", |b| {
        b.iter(|| {
            let result = commitment.verify(black_box(&com), black_box(value), black_box(&opening));
            black_box(result)
        })
    });

    // Trapdoor equivocation
    let fake_value = b"different value";
    group.bench_function("trapdoor_equivocate", |b| {
        b.iter(|| {
            let fake_opening = commitment.equivocate(
                black_box(&com),
                black_box(value),
                black_box(&opening),
                black_box(fake_value),
                black_box(&trapdoor),
            );
            black_box(fake_opening)
        })
    });

    // Vector commitment
    for vec_size in [10, 50, 100].iter() {
        let values: Vec<Vec<u8>> = (0..*vec_size)
            .map(|i| format!("value{}", i).into_bytes())
            .collect();
        let vc = VectorCommitment::new(*vec_size);

        group.bench_with_input(
            BenchmarkId::new("vector_commit", vec_size),
            vec_size,
            |b, _| {
                b.iter(|| {
                    let com = vc.commit(black_box(&values));
                    black_box(com)
                })
            },
        );
    }

    // Vector opening
    for vec_size in [10, 50, 100].iter() {
        let values: Vec<Vec<u8>> = (0..*vec_size)
            .map(|i| format!("value{}", i).into_bytes())
            .collect();
        let vc = VectorCommitment::new(*vec_size);
        let _com = vc.commit(&values);

        group.bench_with_input(
            BenchmarkId::new("vector_open", vec_size),
            vec_size,
            |b, _| {
                b.iter(|| {
                    let opening = vc.open(black_box(&values), black_box(0)).unwrap();
                    black_box(opening)
                })
            },
        );
    }

    // Vector verification
    for vec_size in [10, 50, 100].iter() {
        let values: Vec<Vec<u8>> = (0..*vec_size)
            .map(|i| format!("value{}", i).into_bytes())
            .collect();
        let vc = VectorCommitment::new(*vec_size);
        let com = vc.commit(&values);
        let opening = vc.open(&values, 0).unwrap();

        group.bench_with_input(
            BenchmarkId::new("vector_verify", vec_size),
            vec_size,
            |b, _| {
                b.iter(|| {
                    let result = vc.verify(black_box(&com), black_box(&opening));
                    black_box(result)
                })
            },
        );
    }

    // Extractable commitment setup
    group.bench_function("extractable_setup", |b| {
        b.iter(|| {
            let ec = ExtractableCommitment::setup();
            black_box(ec)
        })
    });

    // Extractable commit
    let ec = ExtractableCommitment::setup();
    group.bench_function("extractable_commit", |b| {
        b.iter(|| {
            let (com, opening) = ec.commit(black_box(value));
            black_box((com, opening))
        })
    });

    // Extractable verify
    let (ec_com, ec_opening) = ec.commit(value);
    group.bench_function("extractable_verify", |b| {
        b.iter(|| {
            let result = ec.verify(black_box(&ec_com), black_box(value), black_box(&ec_opening));
            black_box(result)
        })
    });

    group.finish();
}

// ============================================================================
// FROST Benchmarks (Phase 18)
// ============================================================================

fn bench_frost(c: &mut Criterion) {
    use chie_crypto::frost::{
        FrostKeygen, FrostSigner, aggregate_frost_signatures, verify_frost_signature,
    };

    let mut group = c.benchmark_group("frost");

    // Key generation benchmarks for different thresholds
    for (threshold, num_signers) in [(2, 3), (3, 5), (5, 7)] {
        group.bench_function(
            BenchmarkId::new("keygen", format!("{}-of-{}", threshold, num_signers)),
            |b| {
                b.iter(|| {
                    let mut keygen = FrostKeygen::new(threshold, num_signers);
                    let shares = keygen.generate_shares();
                    black_box((shares, keygen.group_public_key()))
                })
            },
        );
    }

    // Preprocessing (nonce generation)
    let threshold = 2;
    let num_signers = 3;
    let mut keygen = FrostKeygen::new(threshold, num_signers);
    let shares = keygen.generate_shares();
    let group_pk = keygen.group_public_key();

    group.bench_function("preprocess", |b| {
        let mut signer = FrostSigner::new(1, shares[0].clone(), group_pk);
        b.iter(|| {
            signer.preprocess();
            black_box(signer.get_nonce_commitment())
        })
    });

    // Partial signature generation
    let mut signers: Vec<_> = shares
        .iter()
        .enumerate()
        .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), group_pk))
        .collect();

    for signer in &mut signers {
        signer.preprocess();
    }

    let message = b"FROST benchmark message";
    let signing_set = vec![1, 2];
    let commitments: Vec<_> = signing_set
        .iter()
        .map(|&id| signers[id - 1].get_nonce_commitment())
        .collect();

    group.bench_function("partial_sign", |b| {
        b.iter(|| {
            let sig = signers[0].sign(
                black_box(message),
                black_box(&signing_set),
                black_box(&commitments),
            );
            black_box(sig)
        })
    });

    // Signature aggregation
    let partial_sigs: Vec<_> = signing_set
        .iter()
        .map(|&id| {
            signers[id - 1]
                .sign(message, &signing_set, &commitments)
                .unwrap()
        })
        .collect();

    group.bench_function("aggregate", |b| {
        b.iter(|| {
            let sig = aggregate_frost_signatures(
                black_box(message),
                black_box(&signing_set),
                black_box(&commitments),
                black_box(&partial_sigs),
            );
            black_box(sig)
        })
    });

    // Signature verification
    let signature =
        aggregate_frost_signatures(message, &signing_set, &commitments, &partial_sigs).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = verify_frost_signature(
                black_box(&group_pk),
                black_box(message),
                black_box(&signature),
            );
            black_box(result)
        })
    });

    // End-to-end signing (preprocessing + signing + aggregation)
    group.bench_function("e2e_signing_2_of_3", |b| {
        b.iter(|| {
            let mut keygen = FrostKeygen::new(2, 3);
            let shares = keygen.generate_shares();
            let group_pk = keygen.group_public_key();

            let mut signers: Vec<_> = shares
                .iter()
                .enumerate()
                .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), group_pk))
                .collect();

            for signer in &mut signers {
                signer.preprocess();
            }

            let signing_set = vec![1, 2];
            let commitments: Vec<_> = signing_set
                .iter()
                .map(|&id| signers[id - 1].get_nonce_commitment())
                .collect();

            let partial_sigs: Vec<_> = signing_set
                .iter()
                .map(|&id| {
                    signers[id - 1]
                        .sign(message, &signing_set, &commitments)
                        .unwrap()
                })
                .collect();

            let signature =
                aggregate_frost_signatures(message, &signing_set, &commitments, &partial_sigs)
                    .unwrap();
            black_box(signature)
        })
    });

    // Throughput benchmark for different message sizes
    for msg_size in [64, 256, 1024, 4096] {
        let msg = vec![0u8; msg_size];
        group.throughput(Throughput::Bytes(msg_size as u64));
        group.bench_function(BenchmarkId::new("verify_throughput", msg_size), |b| {
            // Setup fresh signing for each message size
            let mut keygen = FrostKeygen::new(2, 3);
            let shares = keygen.generate_shares();
            let group_pk = keygen.group_public_key();

            let mut signers: Vec<_> = shares
                .iter()
                .enumerate()
                .map(|(i, share)| FrostSigner::new(i + 1, share.clone(), group_pk))
                .collect();

            for signer in &mut signers {
                signer.preprocess();
            }

            let signing_set = vec![1, 2];
            let commitments: Vec<_> = signing_set
                .iter()
                .map(|&id| signers[id - 1].get_nonce_commitment())
                .collect();

            let partial_sigs: Vec<_> = signing_set
                .iter()
                .map(|&id| {
                    signers[id - 1]
                        .sign(&msg, &signing_set, &commitments)
                        .unwrap()
                })
                .collect();

            let signature =
                aggregate_frost_signatures(&msg, &signing_set, &commitments, &partial_sigs)
                    .unwrap();

            b.iter(|| {
                let result = verify_frost_signature(
                    black_box(&group_pk),
                    black_box(&msg),
                    black_box(&signature),
                );
                black_box(result)
            })
        });
    }

    group.finish();
}

// ============================================================================
// Phase 19: BBS+ Signatures Benchmarks
// ============================================================================

fn bench_bbs_plus(c: &mut Criterion) {
    use chie_crypto::bbs_plus::{
        BbsPlusKeypair, create_proof as bbs_create_proof, sign_messages as bbs_sign_messages,
        verify_proof as bbs_verify_proof, verify_signature as bbs_verify_signature,
    };

    let mut group = c.benchmark_group("bbs_plus");

    // Keypair generation for different message counts
    for message_count in [3, 5, 10, 20] {
        group.bench_function(BenchmarkId::new("keypair_gen", message_count), |b| {
            b.iter(|| {
                let keypair = BbsPlusKeypair::generate(black_box(message_count));
                black_box(keypair)
            })
        });
    }

    // Sign messages (5 attributes)
    let keypair = BbsPlusKeypair::generate(5);
    let messages = vec![
        b"user_id".to_vec(),
        b"role".to_vec(),
        b"credit".to_vec(),
        b"expiry".to_vec(),
        b"tier".to_vec(),
    ];

    group.bench_function("sign_5_messages", |b| {
        b.iter(|| {
            let sig = bbs_sign_messages(keypair.secret_key(), black_box(&messages));
            black_box(sig)
        })
    });

    // Verify signature
    let signature = bbs_sign_messages(keypair.secret_key(), &messages).unwrap();
    group.bench_function("verify_signature", |b| {
        b.iter(|| {
            let result = bbs_verify_signature(
                keypair.public_key(),
                black_box(&signature),
                black_box(&messages),
            );
            black_box(result)
        })
    });

    // Create selective disclosure proof (reveal 2 of 5)
    let revealed_indices = vec![1, 2];
    group.bench_function("create_proof_reveal_2_of_5", |b| {
        b.iter(|| {
            let proof = bbs_create_proof(
                keypair.public_key(),
                black_box(&signature),
                black_box(&messages),
                black_box(&revealed_indices),
                b"context",
            );
            black_box(proof)
        })
    });

    // Verify selective disclosure proof
    let revealed_messages: Vec<Vec<u8>> = revealed_indices
        .iter()
        .map(|&i| messages[i].clone())
        .collect();
    let proof = bbs_create_proof(
        keypair.public_key(),
        &signature,
        &messages,
        &revealed_indices,
        b"context",
    )
    .unwrap();

    group.bench_function("verify_proof", |b| {
        b.iter(|| {
            let result = bbs_verify_proof(
                keypair.public_key(),
                black_box(&proof),
                black_box(&revealed_indices),
                black_box(&revealed_messages),
                b"context",
            );
            black_box(result)
        })
    });

    // End-to-end: Sign + Create proof
    group.bench_function("e2e_sign_and_prove", |b| {
        b.iter(|| {
            let sig = bbs_sign_messages(keypair.secret_key(), &messages).unwrap();
            let proof = bbs_create_proof(
                keypair.public_key(),
                &sig,
                &messages,
                &revealed_indices,
                b"context",
            )
            .unwrap();
            black_box(proof)
        })
    });

    // Benchmark different disclosure patterns
    for reveal_count in [0, 1, 3, 5] {
        let reveal_indices: Vec<usize> = (0..reveal_count).collect();
        group.bench_function(BenchmarkId::new("create_proof_reveal", reveal_count), |b| {
            b.iter(|| {
                let proof = bbs_create_proof(
                    keypair.public_key(),
                    black_box(&signature),
                    black_box(&messages),
                    black_box(&reveal_indices),
                    b"context",
                );
                black_box(proof)
            })
        });
    }

    // Signature serialization
    group.bench_function("signature_serialization", |b| {
        b.iter(|| {
            let bytes = signature.to_bytes();
            black_box(bytes)
        })
    });

    // Proof serialization
    group.bench_function("proof_serialization", |b| {
        b.iter(|| {
            let bytes = proof.to_bytes();
            black_box(bytes)
        })
    });

    // Throughput for different message counts
    for msg_count in [3, 10, 20] {
        let keypair_mc = BbsPlusKeypair::generate(msg_count);
        let messages_mc: Vec<Vec<u8>> = (0..msg_count)
            .map(|i| format!("attribute_{}", i).into_bytes())
            .collect();

        group.throughput(Throughput::Elements(msg_count as u64));
        group.bench_function(BenchmarkId::new("sign_throughput", msg_count), |b| {
            b.iter(|| {
                let sig = bbs_sign_messages(keypair_mc.secret_key(), black_box(&messages_mc));
                black_box(sig)
            })
        });
    }

    group.finish();
}

// ============================================================================
// Criterion Configuration
// ============================================================================

criterion_group!(
    benches,
    // Original benchmarks
    bench_signing,
    bench_batch_signing,
    bench_encryption,
    bench_streaming,
    bench_hashing,
    bench_chunk_hashing,
    bench_kdf,
    bench_rotation,
    bench_keyserde,
    bench_hsm,
    bench_ct,
    bench_commitments,
    bench_threshold,
    bench_hmac,
    bench_accumulator,
    bench_bulletproofs,
    bench_dkg,
    bench_polycommit,
    bench_vdf,
    // Phase 11 benchmarks
    bench_bls,
    bench_schnorr,
    bench_elgamal,
    bench_proxy_re,
    bench_ot,
    // Phase 12 benchmarks
    bench_kyber,
    bench_dilithium,
    bench_sphincs,
    // Phase 13 benchmarks
    bench_psi,
    bench_forward_secure,
    bench_searchable,
    bench_certified_deletion,
    // Additional core module benchmarks
    bench_vrf,
    bench_merkle,
    bench_ring,
    bench_linkable_ring,
    bench_shamir,
    bench_timelock,
    bench_onion,
    bench_pos,
    bench_keyexchange,
    bench_pedersen,
    bench_blind,
    bench_rangeproof,
    // Phase 16 benchmarks
    bench_oprf,
    bench_ibe,
    bench_aggregate_mac,
    bench_advanced_commitments,
    // Phase 18 benchmarks
    bench_frost,
    // Phase 19 benchmarks
    bench_bbs_plus,
);
criterion_main!(benches);

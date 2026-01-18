//! Cryptographic primitives for CHIE Protocol.
//!
//! This crate provides:
//! - Content encryption using ChaCha20-Poly1305
//! - Digital signatures using Ed25519
//! - Aggregate signatures for multi-peer coordination
//! - Fast hashing using BLAKE3
//! - Key derivation using HKDF
//! - Constant-time comparison utilities
//! - Streaming encryption for large content
//! - Key serialization (PEM, hex, base64)
//! - Key rotation and management utilities
//! - HSM/TPM integration for enterprise deployments
//! - PKCS#11 provider interface for hardware security modules
//! - Multi-party key generation ceremony orchestration
//! - Certificate management and key revocation (CRL/OCSP-like)
//! - Secure key storage with encryption at rest
//! - Cryptographic commitments and proof-of-possession
//! - Verifiable Random Functions (VRF) for unpredictable challenges
//! - Blind signatures for privacy-preserving tokens
//! - Shamir's secret sharing for key backup and recovery
//! - Merkle trees for efficient content verification
//! - Zero-knowledge range proofs for privacy-preserving verification
//! - X25519 key exchange for secure P2P channels
//! - Pedersen commitments for homomorphic bandwidth aggregation
//! - HMAC-based authentication for message integrity
//! - Cryptographic accumulators for efficient set membership
//! - Ring signatures for anonymous signing within a group
//! - Ring CT (Confidential Transactions) for privacy-preserving value transfers
//! - Linkable ring signatures for double-spend prevention
//! - Time-lock encryption for scheduled content release
//! - Onion encryption for privacy-preserving P2P routing
//! - Proof of Storage for verifiable content retention
//! - Bulletproofs for efficient range proofs
//! - Distributed Key Generation (DKG) for decentralized setup
//! - Polynomial commitments for batch verification
//! - Verifiable Delay Functions (VDF) for time-based proofs
//! - BLS signatures for superior signature aggregation
//! - BBS+ signatures for selective disclosure and privacy-preserving credentials
//! - Schnorr signatures for simplicity and provable security
//! - ElGamal encryption for homomorphic operations
//! - Paillier homomorphic encryption for privacy-preserving aggregation
//! - Proxy re-encryption for delegated decryption
//! - Oblivious transfer for private information retrieval
//! - Post-quantum key encapsulation with CRYSTALS-Kyber
//! - Post-quantum signatures with CRYSTALS-Dilithium
//! - Stateless hash-based signatures with SPHINCS+
//! - Private Set Intersection (PSI) for privacy-preserving P2P discovery
//! - Forward-Secure Signatures for key evolution and retroactive security
//! - FROST (Flexible Round-Optimized Schnorr Threshold) signatures for efficient threshold signing
//! - Functional Encryption (FE) with Inner Product support for privacy-preserving computation
//! - Differential Privacy mechanisms for privacy-preserving data analysis
//! - Anonymous Credentials (Idemix-style) for privacy-preserving authentication
//! - Searchable Encryption for encrypted content indexing
//! - Certified Deletion for provable data removal
//! - Garbled Circuits for secure two-party computation
//! - SPAKE2 password-authenticated key exchange
//! - SRP (Secure Remote Password) protocol for password-based authentication
//! - OPRF (Oblivious Pseudorandom Function) for private protocols
//! - Identity-Based Encryption (IBE) for simplified key management
//! - Aggregate MAC for efficient multi-message authentication
//! - Advanced commitment schemes with opening proofs
//! - MuSig2 multi-signature aggregation for efficient multi-party signing
//! - Adaptor signatures for atomic swaps and scriptless scripts
//! - Threshold ECDSA for distributed signature generation
//! - Zero-knowledge proof composition framework for complex protocols
//! - OpenPGP key format compatibility for Ed25519 keys
//! - OpenSSH key format support for SSH key import/export
//! - TLS 1.3 key schedule support (RFC 8446)
//! - WebCrypto API compatibility layer for browser interoperability
//! - Attribute-Based Encryption (ABE) for fine-grained access control
//! - Cryptographic operation audit logging for compliance and forensics
//! - FIPS 140-3 compliance reporting and self-tests
//! - Key usage policy enforcement for access control and compliance
//! - Entropy quality monitoring for RNG health and security
//! - Side-channel resistance verification for timing attack detection
//! - Formal verification helpers for property-based testing
//! - Utility functions for file encryption and message handling
//! - Zeroizing wrappers for sensitive data

pub mod abe;
pub mod accumulator;
pub mod adaptor;
pub mod advanced_commitment;
pub mod aggregate;
pub mod aggregate_mac;
pub mod anonymous_credentials;
pub mod audit_log;
pub mod bbs_plus;
pub mod blind;
pub mod bls;
pub mod bulletproof;
pub mod cache_timing;
pub mod cert_manager;
pub mod certified_deletion;
mod codec;
pub mod commitment;
pub mod compliance;
pub mod ct;
pub mod ct_audit;
pub mod differential_privacy;
pub mod dilithium;
pub mod dkg;
pub mod elgamal;
pub mod encryption;
pub mod entropy;
pub mod formal_verify;
pub mod forward_secure;
pub mod frost;
pub mod functional_encryption;
pub mod garbled_circuit;
pub mod hash;
pub mod hmac;
pub mod hsm;
pub mod ibe;
pub mod kdf;
pub mod key_backup;
pub mod key_formats;
pub mod key_policy;
pub mod key_rotation_scheduler;
pub mod keyexchange;
pub mod keygen_ceremony;
pub mod keyserde;
pub mod keystore;
pub mod kyber;
pub mod linkable_ring;
pub mod merkle;
pub mod musig2;
pub mod onion;
pub mod openpgp;
pub mod openssh;
pub mod oprf;
pub mod ot;
pub mod paillier;
pub mod pbkdf;
pub mod pedersen;
pub mod pkcs11;
pub mod polycommit;
pub mod pos;
pub mod proxy_re;
pub mod psi;
pub mod rangeproof;
pub mod ring;
pub mod ringct;
pub mod rotation;
pub mod schnorr;
pub mod searchable;
pub mod shamir;
pub mod sidechannel;
pub mod signing;
pub mod simd;
pub mod spake2;
pub mod sphincs;
pub mod srp;
pub mod streaming;
pub mod threshold;
pub mod threshold_ecdsa;
pub mod timelock;
pub mod tls13;
pub mod utils;
pub mod vdf_delay;
pub mod vrf;
pub mod webcrypto;
pub mod zeroizing;
pub mod zkproof;

pub use abe::{
    AbeAuthority, AbeCiphertext, AbeError, AbeResult, AccessPolicy, MasterSecretKey, PolicyNode,
    UserSecretKey,
};
pub use accumulator::{
    AccumulatorDigest, AccumulatorError, AccumulatorResult, BloomAccumulator, CompactAccumulator,
    HashAccumulator, MembershipProof, hash_element,
};
pub use adaptor::{
    AdaptorError, AdaptorPoint, AdaptorPublicKey, AdaptorResult, AdaptorSecret, AdaptorSecretKey,
    AdaptorSignature, AdaptorSigner, PreSignature, complete_signature, extract_secret,
    verify_adaptor_signature, verify_pre_signature,
};
pub use advanced_commitment::{
    AdvancedCommitmentError, AdvancedCommitmentResult, ExtractableCom, ExtractableCommitment,
    ExtractableOpening, Trapdoor, TrapdoorCom, TrapdoorCommitment, TrapdoorOpening, VectorCom,
    VectorCommitment, VectorOpening,
};
pub use aggregate::{
    AggregateError, AggregateResult, AggregateSignature, SignatureAggregator, verify_batch,
};
pub use aggregate_mac::{
    AggregateMacBuilder, AggregateMacError, AggregateMacKey, AggregateMacResult, AggregateTag,
    MacTag,
};
pub use anonymous_credentials::{
    AnonCredError, AnonCredResult, AnonymousCredential, CredentialPresentation, CredentialRequest,
    Issuer, IssuerPublicKey, User,
};
pub use audit_log::{AuditEntry, AuditLog, AuditStatistics, OperationType, SeverityLevel};
pub use bbs_plus::{
    BbsPlusError, BbsPlusKeypair, BbsPlusProof, BbsPlusPublicKey, BbsPlusResult, BbsPlusSecretKey,
    BbsPlusSignature, create_proof as bbs_create_proof, sign_messages as bbs_sign_messages,
    verify_proof as bbs_verify_proof, verify_signature as bbs_verify_signature,
};
pub use blind::{
    BlindError, BlindPublicKey, BlindResult, BlindSignatureProtocol, BlindSigner, BlindingFactor,
    RedeemableToken, SignedCommitment, TokenCommitment, UnlinkableToken,
};
pub use bls::{
    BlsError, BlsKeypair, BlsPublicKey, BlsResult, BlsSecretKey, BlsSignature,
    aggregate_signatures, verify_aggregated as verify_bls_aggregated,
};
pub use bulletproof::{
    AggregatedBulletproof, BulletproofCommitment, BulletproofError, BulletproofParams,
    BulletproofRangeProof, BulletproofResult, prove_range, prove_range_aggregated,
    verify_aggregated, verify_range,
};
pub use cache_timing::{
    ByteLookup, CacheAligned, CacheTimingError, CacheTimingResult, ConstantTimeLookup,
    conditional_swap, constant_time_clamp_index, constant_time_memcmp, prefetch_array,
    prefetch_read,
};
pub use certified_deletion::{
    BatchDeletion, CertifiedDeletion, CertifiedDeletionError, CertifiedDeletionResult,
    DeletionCertificate, EncryptedWithWitness,
};
pub use commitment::{
    BandwidthProofCommitment, ChunkChallenge, ChunkPossessionProof, Commitment, CommitmentError,
    CommitmentOpening, KeyPossessionProof, commit, generate_challenge, verify_commitment,
};
pub use compliance::{
    ComplianceAlgorithm, ComplianceChecker, ComplianceIssue, ComplianceReport, ComplianceStatus,
    IssueSeverity, SecurityLevel, SelfTestResult, SelfTestResults,
};
pub use ct::*;
pub use ct_audit::{
    CtAuditError, CtAuditResult, CtAuditor, OperationBenchmark, TimingStatistics, measure_average,
    measure_once,
};
pub use differential_privacy::{
    DPError, DPResult, ExponentialMechanism, GaussianMechanism, LaplaceMechanism, PrivacyBudget,
};
pub use dilithium::{
    Dilithium2, Dilithium2PublicKey, Dilithium2SecretKey, Dilithium2Signature, Dilithium3,
    Dilithium3PublicKey, Dilithium3SecretKey, Dilithium3Signature, Dilithium5, Dilithium5PublicKey,
    Dilithium5SecretKey, Dilithium5Signature, DilithiumError, DilithiumResult,
};
pub use dkg::{
    DkgCommitments, DkgError, DkgParams, DkgParticipant, DkgResult, DkgShare, aggregate_public_key,
};
pub use elgamal::{
    ElGamalCiphertext, ElGamalError, ElGamalKeypair, ElGamalPublicKey, ElGamalResult,
    ElGamalSecretKey, decrypt as elgamal_decrypt, encrypt as elgamal_encrypt,
};
pub use encryption::*;
pub use entropy::{EntropyError, EntropyMonitor, EntropyQuality, EntropyResult, EntropySource};
pub use formal_verify::{
    Invariant, PostCondition, PreCondition, PropertyCheckResult, PropertyChecker, PropertyResult,
    StateMachine, VerificationCondition, check_invariant, check_postcondition, check_precondition,
};
pub use forward_secure::{
    ForwardSecureBuilder, ForwardSecureError, ForwardSecureKeypair, ForwardSecurePublicKey,
    ForwardSecureResult, ForwardSecureSignature,
};
pub use frost::{
    FrostError, FrostKeygen, FrostNonceCommitment, FrostResult, FrostSecretShare, FrostSigner,
    PartialSignature as FrostPartialSignature, aggregate_frost_signatures, verify_frost_signature,
};
pub use functional_encryption::{
    FunctionalEncryptionError, FunctionalEncryptionResult, IpfeCiphertext, IpfeFunctionalKey,
    IpfeMasterPublicKey, IpfeMasterSecretKey, MultiClientIpfe, ipfe_decrypt, ipfe_encrypt,
    ipfe_keygen, ipfe_setup,
};
pub use garbled_circuit::{
    Circuit, GarbledCircuit, GarbledCircuitError, GarbledCircuitResult, Gate, GateType, WireLabel,
};
pub use hash::*;
pub use hmac::{
    AuthenticatedMessage, HmacError, HmacKey, HmacResult, HmacTag, compute_hmac,
    compute_hmac_blake3, compute_hmac_sha256, compute_tagged_hmac, verify_hmac, verify_hmac_blake3,
    verify_hmac_sha256, verify_tagged_hmac,
};
pub use hsm::{
    HsmError, HsmManager, HsmManagerBuilder, HsmResult, KeyId, KeyMetadata, Pkcs11Config,
    Pkcs11Provider, SigningProvider, SoftwareProvider, TpmConfig, TpmHierarchy, TpmProvider,
};
pub use ibe::{IbeCiphertext, IbeError, IbeMaster, IbeParams, IbeResult, IbeSecretKey};
pub use kdf::*;
pub use key_backup::{
    BackupConfig, BackupError, BackupResult, BackupShare, EncryptedBackup,
    KeyType as BackupKeyType, backup_key_encrypted, backup_key_shamir, backup_secret_encrypted,
    backup_secret_shamir, recover_key_encrypted, recover_key_shamir, recover_secret_encrypted,
    recover_secret_shamir,
};
pub use key_formats::{DerKey, JwkKey, KeyFormatError, KeyFormatResult};
pub use key_policy::{KeyPolicy, KeyUsagePolicy, Operation, PolicyEngine, PolicyViolation};
pub use key_rotation_scheduler::{
    KeyMetadata as RotationKeyMetadata, KeyRotationPolicy, KeyRotationScheduler,
};
pub use keyexchange::{
    KeyExchange, KeyExchangeError, KeyExchangeKeypair, KeyExchangeResult, SharedSecret,
    ephemeral_keypair, exchange_and_derive,
};
pub use keyserde::*;
pub use keystore::{
    KeyMetadata as KeyStoreMetadata, KeyStoreError, KeyStoreResult, KeyType, SecureKeyStore,
};
pub use kyber::{
    Kyber512, Kyber512Ciphertext, Kyber512PublicKey, Kyber512SecretKey, Kyber512SharedSecret,
    Kyber768, Kyber768Ciphertext, Kyber768PublicKey, Kyber768SecretKey, Kyber768SharedSecret,
    Kyber1024, Kyber1024Ciphertext, Kyber1024PublicKey, Kyber1024SecretKey, Kyber1024SharedSecret,
    KyberError, KyberResult,
};
pub use linkable_ring::{
    KeyImageDb, LinkableRingError, LinkableRingResult, LinkableRingSignature, check_double_sign,
    sign_linkable, verify_linkable,
};
pub use merkle::{
    IncrementalMerkleBuilder, MerkleError, MerkleProof, MerkleResult, MerkleTree, MultiProof,
};
pub use musig2::{
    MuSig2Error, MuSig2Nonce, MuSig2PublicKey, MuSig2Result, MuSig2SecretKey, MuSig2Signature,
    MuSig2Signer, NonceCommitment, PartialSignature, SigningNonce, aggregate_nonces,
    aggregate_partial_signatures, aggregate_partial_signatures_with_nonce, aggregate_public_keys,
    verify_musig2,
};
pub use onion::{
    OnionBuilder, OnionError, OnionLayer, OnionPacket, OnionResult, OnionRoute, create_onion,
};
pub use openpgp::{OpenPgpError, OpenPgpPublicKey, OpenPgpResult, OpenPgpSecretKey};
pub use openssh::{SshKeyError, SshKeyResult, SshPrivateKey, SshPublicKey};
pub use oprf::{
    BatchOprfClient, BlindedInput, BlindedOutput, OprfClient, OprfError, OprfOutput, OprfResult,
    OprfServer,
};
pub use ot::{OTError, OTReceiver, OTRequest, OTResponse, OTResult, OTSender};
pub use paillier::{
    PaillierCiphertext, PaillierKeypair, PaillierPrivateKey, PaillierPublicKey,
    decrypt as paillier_decrypt, encrypt as paillier_encrypt,
};
pub use pbkdf::*;
pub use pedersen::{PedersenCommitment, PedersenError, PedersenOpening, PedersenResult};
pub use pkcs11::{Pkcs11MockProvider, Pkcs11Session, SessionState};
pub use polycommit::{
    BatchEvaluationProof, EvaluationProof, PolyBlinding, PolyCommitError, PolyCommitParams,
    PolyCommitResult, PolyCommitment, commit_polynomial, prove_batch_evaluations, prove_evaluation,
    verify_batch_evaluations, verify_evaluation,
};
pub use pos::{
    AuditSession, Challenge, DEFAULT_CHUNK_SIZE, PosResult, ProofOfStorageError, StorageProof,
    StorageProver, StorageVerifier,
};
pub use proxy_re::{
    ProxyReCiphertext, ProxyReError, ProxyReKeypair, ProxyRePublicKey, ProxyReReKey, ProxyReResult,
    ProxyReSecretKey, decrypt as proxy_re_decrypt, encrypt as proxy_re_encrypt, generate_re_key,
    re_encrypt,
};
pub use psi::{
    BloomPsiClient, BloomPsiMessage, BloomPsiServer, PsiClient, PsiError, PsiResult, PsiServer,
    PsiServerMessage,
};
pub use rangeproof::{BatchRangeProof, RangeProof, RangeProofError, RangeProofResult};
pub use ring::{
    RingError, RingResult, RingSignature, RingSignatureBuilder, sign_ring, verify_ring,
};
pub use ringct::{
    RingCtBuilder, RingCtError, RingCtInput, RingCtOutput, RingCtResult, RingCtTransaction,
};
pub use rotation::{
    EncryptedKey, EncryptionKeyRing, KeyVersion, ReEncryptor, RotationError, RotationPolicy,
    SigningKeyRing,
};
pub use schnorr::{
    SchnorrError, SchnorrKeypair, SchnorrPublicKey, SchnorrResult, SchnorrSecretKey,
    SchnorrSignature, batch_verify as schnorr_batch_verify,
};
pub use searchable::{
    DocumentId, EncryptedIndex, EncryptedIndexBuilder, MultiKeywordSearch, SearchableEncryption,
    SearchableError, SearchableResult,
};
pub use shamir::{
    ShamirError, ShamirResult, Share, reconstruct, reconstruct_key_32, split, split_key_32,
};
pub use sidechannel::{
    SideChannelAnalysis, SideChannelAnalyzer, TimingTest, Vulnerability, VulnerabilitySeverity,
};
pub use signing::*;
pub use simd::{
    SimdError, SimdResult, batch_constant_time_eq, constant_time_eq, parallel_hash,
    parallel_hash_with_threads, secure_copy, secure_zero as simd_secure_zero, xor_buffers,
    xor_keystream,
};
pub use spake2::{
    Spake2, Spake2Error, Spake2Message, Spake2Result, Spake2SharedSecret, Spake2Side,
};
pub use sphincs::{
    SphincsError, SphincsResult, SphincsSHAKE128f, SphincsSHAKE128fPublicKey,
    SphincsSHAKE128fSecretKey, SphincsSHAKE128fSignature, SphincsSHAKE192f,
    SphincsSHAKE192fPublicKey, SphincsSHAKE192fSecretKey, SphincsSHAKE192fSignature,
    SphincsSHAKE256f, SphincsSHAKE256fPublicKey, SphincsSHAKE256fSecretKey,
    SphincsSHAKE256fSignature,
};
pub use srp::{
    SrpClient, SrpError, SrpPublicKey, SrpResult, SrpServer, SrpSessionKey, SrpVerifier,
};
pub use streaming::*;
pub use threshold::{
    MultiSig, MultiSigBuilder, ThresholdCoordinator, ThresholdError, ThresholdSig,
};
pub use threshold_ecdsa::{
    NonceShare, PublicNonceShare, PublicShare, SecretShare, ThresholdEcdsaError,
    ThresholdEcdsaResult, ThresholdEcdsaSignature, ThresholdEcdsaSigner, ThresholdPartialSignature,
    aggregate_threshold_public_key, aggregate_threshold_signatures, generate_threshold_keys,
    verify_threshold_ecdsa,
};
pub use timelock::{
    TimeLockCiphertext, TimeLockError, TimeLockPuzzle, TimeLockResult, TimeParams,
    timelock_decrypt, timelock_encrypt, timelock_encrypt_with_puzzle,
};
pub use tls13::{Tls13Error, Tls13KeySchedule, Tls13Result, derive_traffic_keys};
pub use utils::{
    EncryptedAndSigned, EncryptedMessage, SignedMessage, UtilError, UtilResult, decrypt_file,
    encrypt_file, generate_and_save_key, load_key,
};
pub use vdf_delay::{
    VdfError, VdfOutput, VdfParams, VdfProof, VdfResult, vdf_compute, vdf_randomness_beacon,
    vdf_verify,
};
pub use vrf::{
    VrfError, VrfProof, VrfPublicKey, VrfResult, VrfSecretKey, generate_bandwidth_challenge,
    verify_bandwidth_challenge,
};
pub use webcrypto::{
    Algorithm, KeyType as WebCryptoKeyType, KeyUsage, WebCryptoError, WebCryptoKey,
    WebCryptoKeyPair, WebCryptoResult,
};
pub use zeroizing::{
    SecureBuffer, ZeroizingKey, secure_move, secure_zero, zeroizing_key_32, zeroizing_nonce,
};
pub use zkproof::{
    AndProof, OrProof, ZkProof, ZkProofBuilder, ZkProofError, ZkProofResult, ZkProvable,
    create_binding,
};

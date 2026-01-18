# Deep Dive Analysis

## 1. Positioning Victory: "Steam Workshop meets BitTorrent"

Placing **Indie Game Assets** in Tier S (highest priority) is a strategic insight. This market's users (developers and gamers) possess the following characteristics, making them optimal as "initial nodes" for this model:

- **High-spec PC ownership rate**: Always-running high-performance CPU/GPU/SSD available
- **Extended online time**: Habit of keeping PCs running for development or gaming
- **Technical literacy**: Low resistance to P2P, port forwarding, and cache configuration
- **Dissatisfaction with Unity/Unreal**: Easily sympathize with the "rebellion" narrative against 30% fees

For this demographic, distributing a **desktop app (built with Tauri) as an "Asset Launcher + Downloader"** minimizes UX friction by aligning with the Steam and Epic Games Launcher context.

## 2. Technical and Legal Defense Strengthening (Deep Dive)

### A. Legal Foundation: BandwidthProof Tamper Prevention

To prove "labor through bandwidth provision," we need to prevent false claims (attacks where nodes claim to have sent data without actually sending it).

**Rust Implementation Direction (Conceptual Code):**

Beyond simple signatures, by including random "challenges," we prove that data was actually held and transmitted.

```rust
// Enhanced bandwidth proof proposal
struct SecureBandwidthProof {
    session_id: Uuid,           // Unique transfer session ID
    chunk_index: u64,           // Location of sent data
    recipient_nonce: [u8; 32],  // Random value issued by receiver (replay attack prevention)
    sender_signature: Vec<u8>,  // Sender's signature
    recipient_signature: Vec<u8>, // Receiver's receipt signature ("I confirm receipt")
    latency_ms: u32,            // For communication quality scoring
}

// Central server aggregates these and BANs anomalies (physically impossible transfer volumes in short time)
```

### B. Copyright Infringement Risk Isolation: "Obfuscated Storage"

Learning from Winny/Share lessons, we design a system where node operators cannot perceive "what file content they're storing."

1. **Encryption**: Content is encrypted client-side at upload
2. **Chunking**: Files are split into IPFS-format pieces
3. **Filename removal**: Stored locally as `QmHash...` IDs without extensions or metadata

**Legal defense**: "What exists on the user's PC is merely encrypted byte sequences, not constituting a copyrighted work (cannot be played). Only purchasers hold decryption keys."

## 3. Gamified Infrastructure: "Investment Caching"

The `SelectivePinning` idea of "choosing which content to host" can become this platform's greatest engagement driver. We present this as a **"prediction market"** in the UI.

- **UI Concept**: A heat map screen like a stock market
    - "This asset is starting to sell! Pin (save) now for XX% bandwidth reward yield!"
    - "New RPG texture pack, pre-orders open. Secure the right to support launch traffic."
- **Psychological Effect**: Users transform from mere downloaders to **"investors who identify hit content"**

## 4. Monetization and Token Economics Fine-Tuning

The proposed "points (non-crypto assets)" strategy is correct under Japanese regulations.
However, **"withdrawal (cashing out)"** requests will inevitably arise. Here, we prepare schemes for "effective cashing out" without legal violations:

- **Amazon Gift Card Exchange**: Partner with point exchange services, convert to digital gifts (processed within secondhand business and payment services laws)
- **Steam Wallet Code Exchange**: Equivalent to cash for the target demographic (gamers)
- **Pro License Application**: Services that handle Unity/Adobe subscription payments

## 5. Next Actions: Rust PoC Construction (Phase 0)

The business model is now sufficiently sharp. Next is the technical PoC phase to prove "Can P2P bandwidth measurement and reward calculation actually work in Rust?"

The following **Rust project skeleton code** can be created:

1. **Core P2P Node (`libp2p`-based)**:
   - Custom protocol (`Request-Response`) for file transfer and proof generation logic
2. **Central Coordinator (Actix-web/Axum)**:
   - Server receiving `Proof` from nodes, performing fraud verification, recording rewards in DB
3. **Simulation Engine**:
   - Simulator launching 100 virtual nodes, flowing traffic, verifying reward distribution doesn't break

---

## Current Implementation Status (2026-01-18)

### Achieved Milestones

| Component | Status | Details |
|-----------|--------|---------|
| P2P Node (libp2p) | ✅ Complete | 41 modules, 494+ tests |
| Central Coordinator (Axum) | ✅ Complete | 50+ modules, 251 tests |
| Simulation Engine | ✅ Complete | MeshSimulation with 2/5/N node support |
| Cryptography | ✅ Complete | 82 modules, 1034 tests |
| Desktop Client (Tauri) | ✅ Complete | React + Rust IPC |

### Technical Metrics

- **Rust SLOC**: 196,538 (code), 243,995 (total)
- **Total Tests**: 2,000+
- **Build**: Zero warnings policy enforced

### Advanced Features Implemented

- Post-quantum cryptography (Kyber, Dilithium, SPHINCS+)
- FROST threshold signatures
- BBS+ selective disclosure
- Bandwidth proof protocol with dual signatures
- Dynamic pricing engine with demand/supply multipliers
- Fraud detection with z-score anomaly analysis

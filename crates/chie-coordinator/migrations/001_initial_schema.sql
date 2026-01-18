-- CHIE Protocol Database Schema
-- Version: 001 - Initial Schema

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- Users and Authentication
-- ============================================================================

CREATE TYPE user_role AS ENUM ('USER', 'CREATOR', 'ADMIN');
CREATE TYPE kyc_status AS ENUM ('NONE', 'PENDING', 'VERIFIED', 'REJECTED');

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role user_role NOT NULL DEFAULT 'USER',

    -- Node information
    peer_id VARCHAR(100) UNIQUE,
    public_key BYTEA,

    -- Points and referral
    points_balance BIGINT NOT NULL DEFAULT 0,
    referrer_id UUID REFERENCES users(id),
    referral_code VARCHAR(20) UNIQUE,

    -- KYC (for creators)
    kyc_status kyc_status NOT NULL DEFAULT 'NONE',
    stripe_account_id VARCHAR(100),

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ
);

CREATE INDEX idx_users_peer_id ON users(peer_id);
CREATE INDEX idx_users_referrer ON users(referrer_id);
CREATE INDEX idx_users_role ON users(role);

-- ============================================================================
-- Content Management
-- ============================================================================

CREATE TYPE content_category AS ENUM (
    'THREE_D_MODELS', 'TEXTURES', 'AUDIO', 'SCRIPTS',
    'ANIMATIONS', 'ASSET_PACKS', 'AI_MODELS', 'OTHER'
);

CREATE TYPE content_status AS ENUM (
    'PROCESSING', 'ACTIVE', 'PENDING_REVIEW', 'REJECTED', 'REMOVED'
);

CREATE TABLE content (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    creator_id UUID NOT NULL REFERENCES users(id),

    -- Content info
    title VARCHAR(200) NOT NULL,
    description TEXT,
    category content_category NOT NULL,
    tags VARCHAR(50)[] DEFAULT '{}',

    -- IPFS info
    cid VARCHAR(100) NOT NULL UNIQUE,
    size_bytes BIGINT NOT NULL,
    chunk_count INTEGER NOT NULL,
    encryption_key BYTEA, -- Stored encrypted

    -- Pricing
    price BIGINT NOT NULL,

    -- Status
    status content_status NOT NULL DEFAULT 'PROCESSING',

    -- Preview
    preview_images TEXT[] DEFAULT '{}',

    -- Stats
    download_count BIGINT NOT NULL DEFAULT 0,
    total_revenue BIGINT NOT NULL DEFAULT 0,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_content_creator ON content(creator_id);
CREATE INDEX idx_content_cid ON content(cid);
CREATE INDEX idx_content_status ON content(status);
CREATE INDEX idx_content_category ON content(category);

-- ============================================================================
-- Node Management
-- ============================================================================

CREATE TYPE node_status AS ENUM ('ONLINE', 'OFFLINE', 'SYNCING', 'BANNED');

CREATE TABLE nodes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id),
    peer_id VARCHAR(100) NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,

    -- Status
    status node_status NOT NULL DEFAULT 'OFFLINE',

    -- Capacity
    max_storage_bytes BIGINT NOT NULL DEFAULT 0,
    used_storage_bytes BIGINT NOT NULL DEFAULT 0,
    max_bandwidth_bps BIGINT NOT NULL DEFAULT 0,

    -- Stats
    total_bandwidth_bytes BIGINT NOT NULL DEFAULT 0,
    total_earnings BIGINT NOT NULL DEFAULT 0,
    uptime_seconds BIGINT NOT NULL DEFAULT 0,

    -- Reputation
    reputation_score REAL NOT NULL DEFAULT 1.0,
    successful_transfers BIGINT NOT NULL DEFAULT 0,
    failed_transfers BIGINT NOT NULL DEFAULT 0,

    -- Connection info
    last_seen_at TIMESTAMPTZ,
    ip_address INET,
    region VARCHAR(50),

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_nodes_user ON nodes(user_id);
CREATE INDEX idx_nodes_peer_id ON nodes(peer_id);
CREATE INDEX idx_nodes_status ON nodes(status);
CREATE INDEX idx_nodes_region ON nodes(region);

-- ============================================================================
-- Content Pinning (which nodes have which content)
-- ============================================================================

CREATE TABLE content_pins (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    content_id UUID NOT NULL REFERENCES content(id) ON DELETE CASCADE,

    -- Pin info
    pinned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    bytes_provided BIGINT NOT NULL DEFAULT 0,
    earnings_from_content BIGINT NOT NULL DEFAULT 0,

    -- Last activity
    last_served_at TIMESTAMPTZ,

    UNIQUE(node_id, content_id)
);

CREATE INDEX idx_pins_node ON content_pins(node_id);
CREATE INDEX idx_pins_content ON content_pins(content_id);

-- ============================================================================
-- Bandwidth Proofs
-- ============================================================================

CREATE TYPE proof_status AS ENUM ('PENDING', 'VERIFIED', 'REJECTED', 'REWARDED');

CREATE TABLE bandwidth_proofs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL UNIQUE,

    -- Transfer info
    content_id UUID NOT NULL REFERENCES content(id),
    chunk_index INTEGER NOT NULL,
    bytes_transferred BIGINT NOT NULL,

    -- Participants
    provider_node_id UUID NOT NULL REFERENCES nodes(id),
    requester_node_id UUID NOT NULL REFERENCES nodes(id),

    -- Cryptographic proof
    provider_public_key BYTEA NOT NULL,
    requester_public_key BYTEA NOT NULL,
    provider_signature BYTEA NOT NULL,
    requester_signature BYTEA NOT NULL,
    challenge_nonce BYTEA NOT NULL,
    chunk_hash BYTEA NOT NULL,

    -- Timing
    start_timestamp_ms BIGINT NOT NULL,
    end_timestamp_ms BIGINT NOT NULL,
    latency_ms INTEGER NOT NULL,

    -- Verification
    status proof_status NOT NULL DEFAULT 'PENDING',
    verified_at TIMESTAMPTZ,
    rejection_reason TEXT,

    -- Reward
    reward_amount BIGINT,
    rewarded_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_proofs_content ON bandwidth_proofs(content_id);
CREATE INDEX idx_proofs_provider ON bandwidth_proofs(provider_node_id);
CREATE INDEX idx_proofs_requester ON bandwidth_proofs(requester_node_id);
CREATE INDEX idx_proofs_status ON bandwidth_proofs(status);
CREATE INDEX idx_proofs_session ON bandwidth_proofs(session_id);
CREATE INDEX idx_proofs_created ON bandwidth_proofs(created_at);

-- Nonce tracking for replay attack prevention
CREATE TABLE used_nonces (
    nonce BYTEA PRIMARY KEY,
    used_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Auto-cleanup old nonces (keep for 24 hours)
CREATE INDEX idx_nonces_used_at ON used_nonces(used_at);

-- ============================================================================
-- Rewards and Transactions
-- ============================================================================

CREATE TYPE transaction_type AS ENUM (
    'BANDWIDTH_REWARD', 'CREATOR_PAYOUT', 'REFERRAL_REWARD',
    'PURCHASE', 'WITHDRAWAL', 'BONUS', 'PLATFORM_FEE'
);

CREATE TABLE point_transactions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id),

    -- Transaction info
    amount BIGINT NOT NULL, -- Positive for credit, negative for debit
    type transaction_type NOT NULL,

    -- Related entities
    proof_id UUID REFERENCES bandwidth_proofs(id),
    content_id UUID REFERENCES content(id),
    related_user_id UUID REFERENCES users(id), -- For referral rewards

    -- Balance tracking
    balance_before BIGINT NOT NULL,
    balance_after BIGINT NOT NULL,

    -- Metadata
    description TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_transactions_user ON point_transactions(user_id);
CREATE INDEX idx_transactions_type ON point_transactions(type);
CREATE INDEX idx_transactions_created ON point_transactions(created_at);

-- ============================================================================
-- Purchases
-- ============================================================================

CREATE TYPE purchase_status AS ENUM ('PENDING', 'COMPLETED', 'REFUNDED');

CREATE TABLE purchases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    buyer_id UUID NOT NULL REFERENCES users(id),
    content_id UUID NOT NULL REFERENCES content(id),

    -- Amounts
    price BIGINT NOT NULL,
    creator_payout BIGINT NOT NULL,
    platform_fee BIGINT NOT NULL,
    referral_rewards BIGINT NOT NULL DEFAULT 0,

    -- Status
    status purchase_status NOT NULL DEFAULT 'PENDING',

    -- Delivery
    encryption_key BYTEA, -- Key to decrypt content, encrypted with buyer's key

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,

    UNIQUE(buyer_id, content_id)
);

CREATE INDEX idx_purchases_buyer ON purchases(buyer_id);
CREATE INDEX idx_purchases_content ON purchases(content_id);
CREATE INDEX idx_purchases_status ON purchases(status);

-- ============================================================================
-- Referral Tracking
-- ============================================================================

CREATE TABLE referral_rewards (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),

    -- The referrer who gets the reward
    referrer_id UUID NOT NULL REFERENCES users(id),

    -- The user whose activity generated the reward
    source_user_id UUID NOT NULL REFERENCES users(id),

    -- The purchase or proof that triggered the reward
    purchase_id UUID REFERENCES purchases(id),
    proof_id UUID REFERENCES bandwidth_proofs(id),

    -- Tier level (1 = direct, 2 = second level, 3 = third level)
    tier_level INTEGER NOT NULL CHECK (tier_level BETWEEN 1 AND 3),

    -- Amounts
    base_amount BIGINT NOT NULL,
    reward_percentage REAL NOT NULL,
    reward_amount BIGINT NOT NULL,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_referrals_referrer ON referral_rewards(referrer_id);
CREATE INDEX idx_referrals_source ON referral_rewards(source_user_id);

-- ============================================================================
-- Analytics and Metrics
-- ============================================================================

-- Hourly content demand metrics
CREATE TABLE content_demand_hourly (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    content_id UUID NOT NULL REFERENCES content(id),
    hour TIMESTAMPTZ NOT NULL,

    download_requests BIGINT NOT NULL DEFAULT 0,
    bytes_transferred BIGINT NOT NULL DEFAULT 0,
    active_seeders INTEGER NOT NULL DEFAULT 0,
    average_latency_ms INTEGER,

    UNIQUE(content_id, hour)
);

CREATE INDEX idx_demand_content ON content_demand_hourly(content_id);
CREATE INDEX idx_demand_hour ON content_demand_hourly(hour);

-- Node performance metrics
CREATE TABLE node_metrics_hourly (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID NOT NULL REFERENCES nodes(id),
    hour TIMESTAMPTZ NOT NULL,

    bytes_served BIGINT NOT NULL DEFAULT 0,
    requests_handled BIGINT NOT NULL DEFAULT 0,
    average_latency_ms INTEGER,
    uptime_percentage REAL,

    UNIQUE(node_id, hour)
);

CREATE INDEX idx_node_metrics_node ON node_metrics_hourly(node_id);
CREATE INDEX idx_node_metrics_hour ON node_metrics_hourly(hour);

-- ============================================================================
-- Leaderboards (materialized for performance)
-- ============================================================================

CREATE TABLE leaderboard_monthly (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id),
    month DATE NOT NULL,

    rank INTEGER NOT NULL,
    total_bandwidth_bytes BIGINT NOT NULL DEFAULT 0,
    total_earnings BIGINT NOT NULL DEFAULT 0,
    badge VARCHAR(50),

    UNIQUE(user_id, month)
);

CREATE INDEX idx_leaderboard_month ON leaderboard_monthly(month);
CREATE INDEX idx_leaderboard_rank ON leaderboard_monthly(month, rank);

-- ============================================================================
-- Fraud Detection
-- ============================================================================

CREATE TYPE fraud_status AS ENUM ('SUSPECTED', 'CONFIRMED', 'CLEARED');

CREATE TABLE fraud_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_id UUID NOT NULL REFERENCES nodes(id),

    -- Detection info
    detection_method VARCHAR(50) NOT NULL,
    confidence_score REAL NOT NULL,
    status fraud_status NOT NULL DEFAULT 'SUSPECTED',

    -- Evidence
    evidence JSONB NOT NULL DEFAULT '{}',
    related_proofs UUID[] DEFAULT '{}',

    -- Resolution
    resolved_by UUID REFERENCES users(id),
    resolved_at TIMESTAMPTZ,
    resolution_notes TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_fraud_node ON fraud_reports(node_id);
CREATE INDEX idx_fraud_status ON fraud_reports(status);

-- ============================================================================
-- Functions and Triggers
-- ============================================================================

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply to relevant tables
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_content_updated_at
    BEFORE UPDATE ON content
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_nodes_updated_at
    BEFORE UPDATE ON nodes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Function to check nonce and prevent replay attacks
CREATE OR REPLACE FUNCTION check_and_use_nonce(p_nonce BYTEA)
RETURNS BOOLEAN AS $$
DECLARE
    v_exists BOOLEAN;
BEGIN
    SELECT EXISTS(SELECT 1 FROM used_nonces WHERE nonce = p_nonce) INTO v_exists;

    IF v_exists THEN
        RETURN FALSE; -- Nonce already used
    END IF;

    INSERT INTO used_nonces (nonce) VALUES (p_nonce);
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Function to calculate referral chain rewards
CREATE OR REPLACE FUNCTION get_referral_chain(p_user_id UUID, p_max_depth INTEGER DEFAULT 3)
RETURNS TABLE(referrer_id UUID, depth INTEGER) AS $$
WITH RECURSIVE chain AS (
    SELECT referrer_id, 1 AS depth
    FROM users
    WHERE id = p_user_id AND referrer_id IS NOT NULL

    UNION ALL

    SELECT u.referrer_id, c.depth + 1
    FROM chain c
    JOIN users u ON u.id = c.referrer_id
    WHERE c.depth < p_max_depth AND u.referrer_id IS NOT NULL
)
SELECT * FROM chain;
$$ LANGUAGE sql;

-- Cleanup old nonces (run periodically)
CREATE OR REPLACE FUNCTION cleanup_old_nonces()
RETURNS INTEGER AS $$
DECLARE
    v_deleted INTEGER;
BEGIN
    DELETE FROM used_nonces WHERE used_at < NOW() - INTERVAL '24 hours';
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$ LANGUAGE plpgsql;

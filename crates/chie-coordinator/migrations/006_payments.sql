-- Payment and Settlement System Migration
-- Creates tables for payment ledger, settlement batches, and escrow

-- Payment status enum
CREATE TYPE payment_status AS ENUM (
    'pending',
    'processing',
    'completed',
    'failed',
    'cancelled',
    'refunded'
);

-- Settlement status enum
CREATE TYPE settlement_status AS ENUM (
    'pending',
    'batched',
    'processing',
    'completed',
    'failed'
);

-- Escrow status enum
CREATE TYPE escrow_status AS ENUM (
    'held',
    'released',
    'refunded',
    'expired'
);

-- Payment ledger table
CREATE TABLE payment_ledger (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    points BIGINT NOT NULL CHECK (points > 0),
    amount_cents BIGINT NOT NULL CHECK (amount_cents > 0),
    currency VARCHAR(3) NOT NULL DEFAULT 'USD',
    exchange_rate DOUBLE PRECISION NOT NULL CHECK (exchange_rate > 0),
    provider VARCHAR(50) NOT NULL,
    provider_transaction_id VARCHAR(255),
    status payment_status NOT NULL DEFAULT 'pending',
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Settlement batches table
CREATE TABLE settlement_batches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payment_count BIGINT NOT NULL DEFAULT 0,
    total_amount_cents BIGINT NOT NULL DEFAULT 0,
    status settlement_status NOT NULL DEFAULT 'pending',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

-- Escrow entries table
CREATE TABLE escrow_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_id UUID NOT NULL REFERENCES bandwidth_proofs(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    requester_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount_points BIGINT NOT NULL CHECK (amount_points > 0),
    status escrow_status NOT NULL DEFAULT 'held',
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

-- Indexes for payment_ledger
CREATE INDEX idx_payment_ledger_user_id ON payment_ledger(user_id);
CREATE INDEX idx_payment_ledger_status ON payment_ledger(status);
CREATE INDEX idx_payment_ledger_created_at ON payment_ledger(created_at DESC);
CREATE INDEX idx_payment_ledger_provider ON payment_ledger(provider);

-- Indexes for settlement_batches
CREATE INDEX idx_settlement_batches_status ON settlement_batches(status);
CREATE INDEX idx_settlement_batches_created_at ON settlement_batches(created_at DESC);

-- Indexes for escrow_entries
CREATE INDEX idx_escrow_entries_proof_id ON escrow_entries(proof_id);
CREATE INDEX idx_escrow_entries_provider_id ON escrow_entries(provider_id);
CREATE INDEX idx_escrow_entries_status ON escrow_entries(status);
CREATE INDEX idx_escrow_entries_created_at ON escrow_entries(created_at DESC);

-- Trigger to update updated_at for payment_ledger
CREATE OR REPLACE FUNCTION update_payment_ledger_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER payment_ledger_updated_at
    BEFORE UPDATE ON payment_ledger
    FOR EACH ROW
    EXECUTE FUNCTION update_payment_ledger_updated_at();

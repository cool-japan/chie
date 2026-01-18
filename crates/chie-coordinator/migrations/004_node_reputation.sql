-- Migration 004: Node Reputation & Trust System
-- Creates tables and indexes for node reputation tracking

-- Node reputation scores table
CREATE TABLE IF NOT EXISTS node_reputation (
    peer_id TEXT PRIMARY KEY,
    score INTEGER NOT NULL DEFAULT 500 CHECK (score >= 0 AND score <= 1000),
    trust_level TEXT NOT NULL DEFAULT 'medium' CHECK (trust_level IN (
        'untrusted',
        'low',
        'medium',
        'high',
        'excellent'
    )),
    last_updated TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Reputation events table for tracking historical events
CREATE TABLE IF NOT EXISTS reputation_events (
    id UUID PRIMARY KEY,
    peer_id TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN (
        'proof_verified',
        'proof_failed',
        'fast_transfer',
        'slow_transfer',
        'high_quality_bandwidth',
        'low_quality_bandwidth',
        'fraud_detected',
        'node_offline',
        'node_online',
        'uptime_milestone'
    )),
    impact INTEGER NOT NULL CHECK (impact >= -100 AND impact <= 100),
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    -- Foreign key constraint (soft reference, node might not exist yet)
    CONSTRAINT fk_peer_id FOREIGN KEY (peer_id) REFERENCES node_reputation(peer_id) ON DELETE CASCADE
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_node_reputation_score ON node_reputation(score DESC);
CREATE INDEX IF NOT EXISTS idx_node_reputation_trust_level ON node_reputation(trust_level);
CREATE INDEX IF NOT EXISTS idx_node_reputation_last_updated ON node_reputation(last_updated DESC);

CREATE INDEX IF NOT EXISTS idx_reputation_events_peer_id ON reputation_events(peer_id);
CREATE INDEX IF NOT EXISTS idx_reputation_events_created_at ON reputation_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reputation_events_event_type ON reputation_events(event_type);
CREATE INDEX IF NOT EXISTS idx_reputation_events_peer_created ON reputation_events(peer_id, created_at DESC);

-- Composite index for common queries
CREATE INDEX IF NOT EXISTS idx_node_reputation_trust_score ON node_reputation(trust_level, score DESC);

-- Function to automatically update last_updated timestamp
CREATE OR REPLACE FUNCTION update_node_reputation_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.last_updated = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update timestamp on reputation changes
CREATE TRIGGER trigger_update_node_reputation_timestamp
    BEFORE UPDATE ON node_reputation
    FOR EACH ROW
    EXECUTE FUNCTION update_node_reputation_timestamp();

-- Comments for documentation
COMMENT ON TABLE node_reputation IS 'Tracks reputation scores and trust levels for network nodes';
COMMENT ON COLUMN node_reputation.score IS 'Reputation score from 0-1000, higher is better';
COMMENT ON COLUMN node_reputation.trust_level IS 'Trust level derived from score: untrusted/low/medium/high/excellent';
COMMENT ON TABLE reputation_events IS 'Historical log of reputation-affecting events';
COMMENT ON COLUMN reputation_events.impact IS 'Score impact of this event (-100 to +100)';
COMMENT ON COLUMN reputation_events.metadata IS 'Additional event context (transfer speed, fraud details, etc.)';

-- Migration 003: Content Moderation System
-- Creates tables and indexes for content safety and moderation

-- Content flags table for tracking moderation issues
CREATE TABLE IF NOT EXISTS content_flags (
    id UUID PRIMARY KEY,
    content_id TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason IN (
        'policy_violation',
        'suspicious_hash',
        'excessive_size',
        'user_reported',
        'malware_detected',
        'dmca_takedown',
        'spam',
        'manual_flag',
        'automated_rule',
        'other'
    )),
    description TEXT,
    reporter_id UUID,  -- References users table (nullable for system flags)
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending',
        'under_review',
        'resolved'
    )),
    action TEXT CHECK (action IN (
        'approved',
        'rejected',
        'quarantined',
        'banned',
        'dismissed'
    )),
    moderator_id UUID,  -- References users table (nullable until reviewed)
    severity INTEGER NOT NULL DEFAULT 50 CHECK (severity >= 0 AND severity <= 100),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB,  -- Additional flag metadata (notes, evidence, etc.)

    -- Constraints
    CONSTRAINT fk_reporter FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_moderator FOREIGN KEY (moderator_id) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT resolved_action_check CHECK (
        (status = 'resolved' AND action IS NOT NULL AND resolved_at IS NOT NULL) OR
        (status != 'resolved' AND action IS NULL AND resolved_at IS NULL)
    )
);

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_content_flags_content_id ON content_flags(content_id);
CREATE INDEX IF NOT EXISTS idx_content_flags_status ON content_flags(status);
CREATE INDEX IF NOT EXISTS idx_content_flags_severity ON content_flags(severity DESC);
CREATE INDEX IF NOT EXISTS idx_content_flags_created_at ON content_flags(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_content_flags_reporter ON content_flags(reporter_id) WHERE reporter_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_content_flags_moderator ON content_flags(moderator_id) WHERE moderator_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_content_flags_pending ON content_flags(severity DESC, created_at ASC) WHERE status IN ('pending', 'under_review');

-- Composite index for common queries
CREATE INDEX IF NOT EXISTS idx_content_flags_status_severity ON content_flags(status, severity DESC);

-- Add content table if it doesn't exist (for upload rate limiting)
CREATE TABLE IF NOT EXISTS content (
    id TEXT PRIMARY KEY,
    uploader_id UUID,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    size_bytes BIGINT,
    content_type TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_uploader FOREIGN KEY (uploader_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Index for upload rate limiting queries
CREATE INDEX IF NOT EXISTS idx_content_uploader_created ON content(uploader_id, created_at DESC) WHERE uploader_id IS NOT NULL;

-- Comments for documentation
COMMENT ON TABLE content_flags IS 'Tracks content moderation flags and actions';
COMMENT ON COLUMN content_flags.severity IS 'Severity score from 0-100, higher is more severe';
COMMENT ON COLUMN content_flags.metadata IS 'Additional context: notes, evidence, related flags, etc.';
COMMENT ON COLUMN content_flags.reason IS 'Why the content was flagged';
COMMENT ON COLUMN content_flags.action IS 'Moderation action taken (only set when resolved)';
COMMENT ON TABLE content IS 'Content metadata for the CHIE protocol';

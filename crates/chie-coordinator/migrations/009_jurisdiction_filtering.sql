-- Jurisdiction-Aware Content Filtering System
-- Implements geographic and legal jurisdiction-based content filtering

-- Restriction reason enum
CREATE TYPE restriction_reason AS ENUM (
    'dmca_takedown',
    'eu_copyright_directive',
    'gdpr_right_to_erasure',
    'court_order',
    'government_request',
    'tos_violation',
    'regional_licensing',
    'age_restriction',
    'other'
);

-- Content restrictions table
CREATE TABLE IF NOT EXISTS content_restrictions (
    id UUID PRIMARY KEY,
    content_id UUID NOT NULL,  -- Foreign key to content table
    jurisdiction_codes TEXT[] NOT NULL,  -- ISO 3166-1 alpha-2 country codes (e.g., ['US', 'GB', 'FR'])
    reason restriction_reason NOT NULL,
    legal_reference TEXT,  -- Case number, DMCA reference number, court order number, etc.
    description TEXT NOT NULL,
    is_global BOOLEAN NOT NULL DEFAULT false,  -- If true, blocked worldwide
    placed_by TEXT NOT NULL,  -- Admin user who placed the restriction
    placed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,  -- Optional expiration date for temporary restrictions
    appeal_url TEXT,  -- URL where users can appeal the restriction

    CONSTRAINT valid_description CHECK (length(description) > 0),
    CONSTRAINT valid_jurisdiction_codes CHECK (array_length(jurisdiction_codes, 1) > 0 OR is_global = true)
);

-- Indexes for efficient jurisdiction filtering
CREATE INDEX idx_content_restrictions_content_id ON content_restrictions(content_id);
CREATE INDEX idx_content_restrictions_jurisdiction_codes ON content_restrictions USING GIN (jurisdiction_codes);
CREATE INDEX idx_content_restrictions_is_global ON content_restrictions(is_global) WHERE is_global = true;
CREATE INDEX idx_content_restrictions_expires_at ON content_restrictions(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX idx_content_restrictions_reason ON content_restrictions(reason);
CREATE INDEX idx_content_restrictions_placed_at ON content_restrictions(placed_at DESC);

-- Index for active restrictions (most common query)
-- Note: Cannot use NOW() in partial index (not IMMUTABLE). Application must filter expired restrictions.
CREATE INDEX idx_content_restrictions_active ON content_restrictions(content_id, expires_at);

-- Comments for documentation
COMMENT ON TABLE content_restrictions IS 'Geographic and legal jurisdiction-based content restrictions';

COMMENT ON COLUMN content_restrictions.jurisdiction_codes IS 'Array of ISO 3166-1 alpha-2 country codes where content is restricted';
COMMENT ON COLUMN content_restrictions.is_global IS 'If true, content is blocked worldwide regardless of jurisdiction_codes';
COMMENT ON COLUMN content_restrictions.legal_reference IS 'Legal case number, DMCA reference, court order number, etc.';
COMMENT ON COLUMN content_restrictions.placed_by IS 'Admin user ID or system that placed the restriction';
COMMENT ON COLUMN content_restrictions.expires_at IS 'Optional expiration timestamp for temporary restrictions';
COMMENT ON COLUMN content_restrictions.appeal_url IS 'URL where users can appeal the content restriction';

-- Example restrictions:
-- DMCA takedown (US only):
--   jurisdiction_codes = ['US'], reason = 'dmca_takedown', legal_reference = 'DMCA-2024-001'
-- EU Copyright Directive (all EU countries):
--   jurisdiction_codes = ['AT', 'BE', 'BG', ...], reason = 'eu_copyright_directive'
-- Global court order:
--   is_global = true, reason = 'court_order', legal_reference = 'Case #2024-CV-12345'

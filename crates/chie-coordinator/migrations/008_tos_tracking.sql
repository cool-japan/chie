-- Terms of Service Version Tracking System
-- Implements legal compliance for ToS management

-- Terms of Service versions
CREATE TABLE IF NOT EXISTS tos_versions (
    id UUID PRIMARY KEY,
    version TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    content TEXT NOT NULL,  -- Full ToS text
    summary_of_changes TEXT,  -- What changed from previous version
    effective_date TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT false,
    requires_acceptance BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by TEXT NOT NULL,  -- Admin user who created this version

    CONSTRAINT valid_version CHECK (length(version) > 0 AND length(version) <= 50),
    CONSTRAINT valid_title CHECK (length(title) > 0 AND length(title) <= 200),
    CONSTRAINT valid_content CHECK (length(content) > 0)
);

-- User acceptances of ToS versions
CREATE TABLE IF NOT EXISTS tos_acceptances (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tos_version_id UUID NOT NULL REFERENCES tos_versions(id) ON DELETE CASCADE,
    tos_version TEXT NOT NULL,  -- Denormalized for faster queries
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ip_address TEXT,  -- IP address from which acceptance was made
    user_agent TEXT,  -- Browser/client user agent

    CONSTRAINT unique_user_version UNIQUE (user_id, tos_version_id)
);

-- Indexes for ToS versions
CREATE INDEX idx_tos_versions_is_active ON tos_versions(is_active) WHERE is_active = true;
CREATE INDEX idx_tos_versions_effective_date ON tos_versions(effective_date DESC);
CREATE INDEX idx_tos_versions_version ON tos_versions(version);

-- Indexes for ToS acceptances
CREATE INDEX idx_tos_acceptances_user_id ON tos_acceptances(user_id);
CREATE INDEX idx_tos_acceptances_tos_version_id ON tos_acceptances(tos_version_id);
CREATE INDEX idx_tos_acceptances_accepted_at ON tos_acceptances(accepted_at DESC);
CREATE INDEX idx_tos_acceptances_tos_version ON tos_acceptances(tos_version);

-- Ensure only one active version at a time (optional, can be enforced in application)
CREATE UNIQUE INDEX idx_tos_versions_only_one_active
    ON tos_versions(is_active)
    WHERE is_active = true;

-- Comments for documentation
COMMENT ON TABLE tos_versions IS 'Terms of Service version history for legal compliance';
COMMENT ON TABLE tos_acceptances IS 'User acceptances of ToS versions with audit trail';

COMMENT ON COLUMN tos_versions.version IS 'Version number (e.g., "1.0", "2.0", "2.1")';
COMMENT ON COLUMN tos_versions.effective_date IS 'Date when this version becomes active';
COMMENT ON COLUMN tos_versions.is_active IS 'Whether this is the currently active version';
COMMENT ON COLUMN tos_versions.requires_acceptance IS 'Whether users must explicitly accept this version';
COMMENT ON COLUMN tos_versions.summary_of_changes IS 'Summary of changes from previous version';

COMMENT ON COLUMN tos_acceptances.ip_address IS 'IP address for legal audit trail';
COMMENT ON COLUMN tos_acceptances.user_agent IS 'User agent string for device tracking';
COMMENT ON COLUMN tos_acceptances.accepted_at IS 'Timestamp of acceptance (for legal compliance)';

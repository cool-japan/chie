-- GDPR Compliance Tables
-- Implements GDPR requirements including data export and right to be forgotten

-- Export status enum
CREATE TYPE gdpr_export_status AS ENUM ('pending', 'processing', 'completed', 'failed', 'expired');

-- Export format enum
CREATE TYPE export_format AS ENUM ('json', 'csv', 'zip');

-- RTBF status enum
CREATE TYPE rtbf_status AS ENUM ('pending', 'processing', 'completed', 'cancelled', 'failed');

-- GDPR data export requests (Article 20 - Right to Data Portability)
CREATE TABLE IF NOT EXISTS gdpr_exports (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status gdpr_export_status NOT NULL DEFAULT 'pending',
    format export_format NOT NULL DEFAULT 'json',
    file_path TEXT,
    file_size_bytes BIGINT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,

    CONSTRAINT valid_file_size CHECK (file_size_bytes IS NULL OR file_size_bytes >= 0)
);

-- Indexes for GDPR exports
CREATE INDEX idx_gdpr_exports_user_id ON gdpr_exports(user_id);
CREATE INDEX idx_gdpr_exports_status ON gdpr_exports(status);
CREATE INDEX idx_gdpr_exports_expires_at ON gdpr_exports(expires_at);
CREATE INDEX idx_gdpr_exports_created_at ON gdpr_exports(created_at DESC);

-- Right to be forgotten requests (Article 17 - Right to Erasure)
CREATE TABLE IF NOT EXISTS rtbf_requests (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status rtbf_status NOT NULL DEFAULT 'pending',
    reason TEXT,
    anonymize_only BOOLEAN NOT NULL DEFAULT false,
    legal_hold BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    deleted_records JSONB,

    CONSTRAINT valid_deletion_mode CHECK (NOT (legal_hold = true AND anonymize_only = false))
);

-- Indexes for RTBF requests
CREATE INDEX idx_rtbf_requests_user_id ON rtbf_requests(user_id);
CREATE INDEX idx_rtbf_requests_status ON rtbf_requests(status);
CREATE INDEX idx_rtbf_requests_created_at ON rtbf_requests(created_at DESC);
CREATE INDEX idx_rtbf_requests_legal_hold ON rtbf_requests(legal_hold) WHERE legal_hold = true;

-- Legal holds (prevents data deletion for legal/compliance reasons)
CREATE TABLE IF NOT EXISTS legal_holds (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    content_id UUID,  -- Can hold specific content instead of entire user
    case_number TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'released', 'expired')),
    placed_by TEXT NOT NULL,  -- Admin user who placed the hold
    placed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    notes TEXT,

    CONSTRAINT user_or_content_required CHECK (user_id IS NOT NULL OR content_id IS NOT NULL)
);

-- Indexes for legal holds
CREATE INDEX idx_legal_holds_user_id ON legal_holds(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_legal_holds_content_id ON legal_holds(content_id) WHERE content_id IS NOT NULL;
CREATE INDEX idx_legal_holds_status ON legal_holds(status);
CREATE INDEX idx_legal_holds_case_number ON legal_holds(case_number);
CREATE INDEX idx_legal_holds_expires_at ON legal_holds(expires_at);

-- Comments for documentation
COMMENT ON TABLE gdpr_exports IS 'GDPR Article 20 - Right to Data Portability - User data export requests';
COMMENT ON TABLE rtbf_requests IS 'GDPR Article 17 - Right to Erasure (Right to be Forgotten) - Data deletion requests';
COMMENT ON TABLE legal_holds IS 'Legal holds preventing data deletion for compliance or litigation';

COMMENT ON COLUMN rtbf_requests.anonymize_only IS 'If true, anonymize data instead of deletion (for legal retention)';
COMMENT ON COLUMN rtbf_requests.legal_hold IS 'If true, user has active legal hold (can only anonymize, not delete)';
COMMENT ON COLUMN rtbf_requests.deleted_records IS 'JSON summary of deleted/anonymized records by table';

COMMENT ON COLUMN legal_holds.case_number IS 'Legal case or compliance reference number';
COMMENT ON COLUMN legal_holds.placed_by IS 'Admin user ID or system that placed the hold';

-- Multi-Tenancy Support Migration
--
-- This migration adds support for multi-tenant isolation, enabling per-creator
-- namespaces and data isolation.

-- Tenant status enum
CREATE TYPE tenant_status AS ENUM ('active', 'suspended', 'archived');

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY,
    namespace VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    status tenant_status NOT NULL DEFAULT 'active',
    owner_user_id UUID NOT NULL,

    -- Quotas
    storage_quota_bytes BIGINT,  -- NULL = unlimited
    bandwidth_quota_bytes BIGINT,  -- per month, NULL = unlimited
    max_users INTEGER,  -- NULL = unlimited
    max_nodes INTEGER,  -- NULL = unlimited

    -- Custom settings (JSON)
    settings JSONB NOT NULL DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CHECK (namespace ~ '^[a-zA-Z0-9_-]+$'),
    CHECK (length(namespace) >= 3 AND length(namespace) <= 64),
    CHECK (storage_quota_bytes IS NULL OR storage_quota_bytes > 0),
    CHECK (bandwidth_quota_bytes IS NULL OR bandwidth_quota_bytes > 0),
    CHECK (max_users IS NULL OR max_users > 0),
    CHECK (max_nodes IS NULL OR max_nodes > 0)
);

-- Indexes for efficient lookups
CREATE INDEX idx_tenants_namespace ON tenants(namespace);
CREATE INDEX idx_tenants_owner_user_id ON tenants(owner_user_id);
CREATE INDEX idx_tenants_status ON tenants(status);
CREATE INDEX idx_tenants_created_at ON tenants(created_at DESC);

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_tenants_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_tenants_updated_at();

-- Add tenant_id to existing tables for multi-tenant isolation
-- Note: In a real migration, you would add these columns to all relevant tables
-- For now, we'll document the pattern:

-- Example for users table (if it exists):
-- ALTER TABLE users ADD COLUMN tenant_id UUID REFERENCES tenants(id);
-- CREATE INDEX idx_users_tenant_id ON users(tenant_id);

-- Example for content table (if it exists):
-- ALTER TABLE content ADD COLUMN tenant_id UUID REFERENCES tenants(id);
-- CREATE INDEX idx_content_tenant_id ON content(tenant_id);

-- Example for nodes table (if it exists):
-- ALTER TABLE nodes ADD COLUMN tenant_id UUID REFERENCES tenants(id);
-- CREATE INDEX idx_nodes_tenant_id ON nodes(tenant_id);

-- Tenant API keys table (for API authentication)
CREATE TABLE IF NOT EXISTS tenant_api_keys (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash VARCHAR(128) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT '{}',
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CHECK (length(key_hash) > 0)
);

CREATE INDEX idx_tenant_api_keys_tenant_id ON tenant_api_keys(tenant_id);
CREATE INDEX idx_tenant_api_keys_key_hash ON tenant_api_keys(key_hash);
CREATE INDEX idx_tenant_api_keys_expires_at ON tenant_api_keys(expires_at);

-- Tenant usage tracking (for quota enforcement)
CREATE TABLE IF NOT EXISTS tenant_usage (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    month DATE NOT NULL,  -- First day of the month
    storage_used_bytes BIGINT NOT NULL DEFAULT 0,
    bandwidth_used_bytes BIGINT NOT NULL DEFAULT 0,
    api_requests_count BIGINT NOT NULL DEFAULT 0,

    PRIMARY KEY (tenant_id, month),
    CHECK (storage_used_bytes >= 0),
    CHECK (bandwidth_used_bytes >= 0),
    CHECK (api_requests_count >= 0)
);

CREATE INDEX idx_tenant_usage_tenant_id ON tenant_usage(tenant_id);
CREATE INDEX idx_tenant_usage_month ON tenant_usage(month DESC);

-- Comments for documentation
COMMENT ON TABLE tenants IS 'Multi-tenant isolation - each tenant represents a creator/organization';
COMMENT ON COLUMN tenants.namespace IS 'Unique namespace identifier (e.g., "creator-123")';
COMMENT ON COLUMN tenants.status IS 'Tenant status: active, suspended, or archived';
COMMENT ON COLUMN tenants.storage_quota_bytes IS 'Total storage quota in bytes (NULL = unlimited)';
COMMENT ON COLUMN tenants.bandwidth_quota_bytes IS 'Monthly bandwidth quota in bytes (NULL = unlimited)';
COMMENT ON COLUMN tenants.settings IS 'Custom tenant settings as JSON';

COMMENT ON TABLE tenant_api_keys IS 'API keys for tenant authentication';
COMMENT ON TABLE tenant_usage IS 'Monthly usage tracking for quota enforcement';

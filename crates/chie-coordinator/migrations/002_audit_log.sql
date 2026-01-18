-- Create audit_log table for comprehensive operation tracking

CREATE TABLE IF NOT EXISTS audit_log (
    id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'warning', 'critical')),
    category VARCHAR(50) NOT NULL CHECK (category IN ('user', 'node', 'content', 'proof', 'admin', 'security', 'config', 'data_management')),
    action VARCHAR(100) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    ip_address INET,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    correlation_id VARCHAR(100),
    details JSONB,
    result VARCHAR(20) NOT NULL DEFAULT 'success',
    error_message TEXT
);

-- Index for timestamp-based queries (most common)
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);

-- Index for category and severity filtering
CREATE INDEX idx_audit_log_category ON audit_log(category);
CREATE INDEX idx_audit_log_severity ON audit_log(severity);

-- Index for actor tracking
CREATE INDEX idx_audit_log_actor ON audit_log(actor);

-- Index for correlation ID tracing
CREATE INDEX idx_audit_log_correlation_id ON audit_log(correlation_id) WHERE correlation_id IS NOT NULL;

-- Index for resource tracking
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id) WHERE resource_type IS NOT NULL;

-- Composite index for common query patterns (time + category + severity)
CREATE INDEX idx_audit_log_query ON audit_log(timestamp DESC, category, severity);

-- Add comment for table documentation
COMMENT ON TABLE audit_log IS 'Comprehensive audit trail for all critical operations in the coordinator';
COMMENT ON COLUMN audit_log.severity IS 'Event severity: info (normal), warning (unusual), critical (security-relevant)';
COMMENT ON COLUMN audit_log.category IS 'Event category for filtering and organization';
COMMENT ON COLUMN audit_log.action IS 'Specific action performed (e.g., user_created, proof_verified)';
COMMENT ON COLUMN audit_log.actor IS 'Who performed the action (user ID, system, or anonymous)';
COMMENT ON COLUMN audit_log.result IS 'Operation result: success, failure, partial';
COMMENT ON COLUMN audit_log.correlation_id IS 'Request correlation ID for distributed tracing';

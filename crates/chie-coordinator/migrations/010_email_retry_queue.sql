-- Email Retry Queue Persistence
-- Stores failed email deliveries for retry processing across restarts

-- Table: email_retry_queue
-- Stores failed email notifications with retry metadata
CREATE TABLE IF NOT EXISTS email_retry_queue (
    id UUID PRIMARY KEY,
    alert_id UUID NOT NULL,
    alert_severity TEXT NOT NULL CHECK (alert_severity IN ('Info', 'Warning', 'Critical')),
    alert_message TEXT NOT NULL,
    recipients TEXT[] NOT NULL,
    failed_recipients TEXT[] NOT NULL,
    last_error TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 5,
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,

    -- Constraints
    CONSTRAINT retry_count_positive CHECK (retry_count >= 0),
    CONSTRAINT max_retries_positive CHECK (max_retries > 0),
    CONSTRAINT max_retries_reasonable CHECK (max_retries <= 100),
    CONSTRAINT failed_recipients_not_empty CHECK (array_length(failed_recipients, 1) > 0)
);

-- Indexes for email retry queue
CREATE INDEX idx_email_retry_next_retry ON email_retry_queue(next_retry_at)
    WHERE next_retry_at IS NOT NULL;
CREATE INDEX idx_email_retry_expires ON email_retry_queue(expires_at);
CREATE INDEX idx_email_retry_alert ON email_retry_queue(alert_id);
CREATE INDEX idx_email_retry_created ON email_retry_queue(created_at);
CREATE INDEX idx_email_retry_count ON email_retry_queue(retry_count);

-- Trigger: Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_email_retry_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_email_retry_updated_at
    BEFORE UPDATE ON email_retry_queue
    FOR EACH ROW
    EXECUTE FUNCTION update_email_retry_updated_at();

-- Comments for documentation
COMMENT ON TABLE email_retry_queue IS 'Persistent storage for failed email deliveries requiring retry';
COMMENT ON COLUMN email_retry_queue.id IS 'Unique identifier for failed email (matches in-memory FailedEmail.id)';
COMMENT ON COLUMN email_retry_queue.alert_id IS 'ID of the alert that triggered this email';
COMMENT ON COLUMN email_retry_queue.alert_severity IS 'Severity level of the alert (Info, Warning, Critical)';
COMMENT ON COLUMN email_retry_queue.alert_message IS 'Alert message content';
COMMENT ON COLUMN email_retry_queue.recipients IS 'All intended recipients (for reference)';
COMMENT ON COLUMN email_retry_queue.failed_recipients IS 'Recipients that failed to receive the email';
COMMENT ON COLUMN email_retry_queue.last_error IS 'Last error message encountered during send attempt';
COMMENT ON COLUMN email_retry_queue.retry_count IS 'Number of retry attempts made';
COMMENT ON COLUMN email_retry_queue.max_retries IS 'Maximum retry attempts allowed';
COMMENT ON COLUMN email_retry_queue.next_retry_at IS 'Next scheduled retry time (NULL if not eligible)';
COMMENT ON COLUMN email_retry_queue.expires_at IS 'Time when this retry entry should be abandoned';

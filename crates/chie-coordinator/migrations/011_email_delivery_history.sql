-- Email Delivery History
-- Comprehensive tracking of all email delivery attempts (success and failure)

-- Table: email_delivery_history
-- Stores complete history of email deliveries for analytics and auditing
CREATE TABLE IF NOT EXISTS email_delivery_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID NOT NULL,
    alert_severity TEXT NOT NULL CHECK (alert_severity IN ('Info', 'Warning', 'Critical')),
    alert_title TEXT NOT NULL,
    alert_message TEXT NOT NULL,
    recipient TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('sent', 'failed', 'queued', 'abandoned')),
    priority TEXT NOT NULL CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    retry_attempt INTEGER NOT NULL DEFAULT 0,
    error_message TEXT,
    delivered_at TIMESTAMPTZ,
    failed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT retry_attempt_non_negative CHECK (retry_attempt >= 0),
    CONSTRAINT retry_attempt_reasonable CHECK (retry_attempt <= 100),
    CONSTRAINT status_timestamp_consistency CHECK (
        (status = 'sent' AND delivered_at IS NOT NULL) OR
        (status = 'failed' AND failed_at IS NOT NULL) OR
        (status IN ('queued', 'abandoned'))
    )
);

-- Indexes for email delivery history
CREATE INDEX idx_email_delivery_alert ON email_delivery_history(alert_id);
CREATE INDEX idx_email_delivery_recipient ON email_delivery_history(recipient);
CREATE INDEX idx_email_delivery_status ON email_delivery_history(status);
CREATE INDEX idx_email_delivery_priority ON email_delivery_history(priority);
CREATE INDEX idx_email_delivery_created ON email_delivery_history(created_at DESC);
CREATE INDEX idx_email_delivery_delivered ON email_delivery_history(delivered_at DESC)
    WHERE delivered_at IS NOT NULL;
CREATE INDEX idx_email_delivery_failed ON email_delivery_history(failed_at DESC)
    WHERE failed_at IS NOT NULL;
CREATE INDEX idx_email_delivery_severity ON email_delivery_history(alert_severity);

-- Composite index for common queries
CREATE INDEX idx_email_delivery_recipient_status ON email_delivery_history(recipient, status, created_at DESC);
CREATE INDEX idx_email_delivery_alert_recipient ON email_delivery_history(alert_id, recipient);

-- Comments for documentation
COMMENT ON TABLE email_delivery_history IS 'Complete history of all email delivery attempts for analytics and auditing';
COMMENT ON COLUMN email_delivery_history.id IS 'Unique identifier for this delivery record';
COMMENT ON COLUMN email_delivery_history.alert_id IS 'ID of the alert that triggered this email';
COMMENT ON COLUMN email_delivery_history.alert_severity IS 'Severity level of the alert (Info, Warning, Critical)';
COMMENT ON COLUMN email_delivery_history.alert_title IS 'Alert title/subject';
COMMENT ON COLUMN email_delivery_history.alert_message IS 'Alert message content';
COMMENT ON COLUMN email_delivery_history.recipient IS 'Email recipient address';
COMMENT ON COLUMN email_delivery_history.status IS 'Delivery status (sent, failed, queued, abandoned)';
COMMENT ON COLUMN email_delivery_history.priority IS 'Email priority level (low, normal, high, urgent)';
COMMENT ON COLUMN email_delivery_history.retry_attempt IS 'Which retry attempt this was (0 = first attempt)';
COMMENT ON COLUMN email_delivery_history.error_message IS 'Error message if delivery failed';
COMMENT ON COLUMN email_delivery_history.delivered_at IS 'When the email was successfully delivered';
COMMENT ON COLUMN email_delivery_history.failed_at IS 'When the delivery failed';
COMMENT ON COLUMN email_delivery_history.created_at IS 'When this record was created';

-- Table: email_templates
-- Customizable email templates for different alert severities
CREATE TABLE IF NOT EXISTS email_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    severity TEXT CHECK (severity IN ('Info', 'Warning', 'Critical', 'All')),
    subject_template TEXT NOT NULL,
    html_template TEXT NOT NULL,
    text_template TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT template_name_not_empty CHECK (length(name) > 0),
    CONSTRAINT subject_template_not_empty CHECK (length(subject_template) > 0)
);

-- Index for email templates
CREATE INDEX idx_email_templates_severity ON email_templates(severity)
    WHERE is_active = true;
CREATE INDEX idx_email_templates_active ON email_templates(is_active);

-- Trigger: Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_email_template_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_email_template_updated_at
    BEFORE UPDATE ON email_templates
    FOR EACH ROW
    EXECUTE FUNCTION update_email_template_updated_at();

-- Comments for email templates
COMMENT ON TABLE email_templates IS 'Customizable email templates for alert notifications';
COMMENT ON COLUMN email_templates.id IS 'Unique identifier for this template';
COMMENT ON COLUMN email_templates.name IS 'Template name (unique identifier for lookup)';
COMMENT ON COLUMN email_templates.description IS 'Human-readable description of the template';
COMMENT ON COLUMN email_templates.severity IS 'Alert severity this template applies to (or All for default)';
COMMENT ON COLUMN email_templates.subject_template IS 'Subject line template (supports placeholders)';
COMMENT ON COLUMN email_templates.html_template IS 'HTML email body template (supports placeholders)';
COMMENT ON COLUMN email_templates.text_template IS 'Plain text email body template (supports placeholders)';
COMMENT ON COLUMN email_templates.is_active IS 'Whether this template is currently active';

-- Table: email_rate_limits
-- Per-recipient rate limiting configuration
CREATE TABLE IF NOT EXISTS email_rate_limits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    recipient_pattern TEXT NOT NULL UNIQUE,
    max_emails_per_hour INTEGER NOT NULL,
    max_emails_per_day INTEGER NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT max_emails_per_hour_positive CHECK (max_emails_per_hour > 0),
    CONSTRAINT max_emails_per_day_positive CHECK (max_emails_per_day > 0),
    CONSTRAINT max_emails_per_day_reasonable CHECK (max_emails_per_day <= 10000),
    CONSTRAINT hourly_daily_consistency CHECK (max_emails_per_hour <= max_emails_per_day)
);

-- Index for email rate limits
CREATE INDEX idx_email_rate_limits_pattern ON email_rate_limits(recipient_pattern)
    WHERE is_active = true;

-- Trigger: Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_email_rate_limit_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_update_email_rate_limit_updated_at
    BEFORE UPDATE ON email_rate_limits
    FOR EACH ROW
    EXECUTE FUNCTION update_email_rate_limit_updated_at();

-- Comments for email rate limits
COMMENT ON TABLE email_rate_limits IS 'Per-recipient rate limiting rules to prevent email flooding';
COMMENT ON COLUMN email_rate_limits.id IS 'Unique identifier for this rate limit rule';
COMMENT ON COLUMN email_rate_limits.recipient_pattern IS 'Email pattern to match (supports wildcards like *@example.com)';
COMMENT ON COLUMN email_rate_limits.max_emails_per_hour IS 'Maximum emails per hour for matching recipients';
COMMENT ON COLUMN email_rate_limits.max_emails_per_day IS 'Maximum emails per day for matching recipients';
COMMENT ON COLUMN email_rate_limits.is_active IS 'Whether this rate limit rule is active';

-- Insert default email template
INSERT INTO email_templates (name, description, severity, subject_template, html_template, text_template, is_active)
VALUES (
    'default_alert',
    'Default alert email template',
    'All',
    '[CHIE Alert - {{severity}}] {{title}}',
    '<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: {{severity_color}}; color: white; padding: 20px; border-radius: 5px 5px 0 0; }
        .content { background-color: #f4f4f4; padding: 20px; border-radius: 0 0 5px 5px; }
        .field { margin: 10px 0; }
        .field-label { font-weight: bold; }
        .footer { margin-top: 20px; font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{title}}</h1>
        </div>
        <div class="content">
            <div class="field">
                <span class="field-label">Severity:</span> {{severity}}
            </div>
            <div class="field">
                <span class="field-label">Message:</span> {{message}}
            </div>
            <div class="field">
                <span class="field-label">Metric Value:</span> {{metric_value}}
            </div>
            <div class="field">
                <span class="field-label">Alert ID:</span> {{alert_id}}
            </div>
            <div class="field">
                <span class="field-label">Created At:</span> {{created_at}}
            </div>
        </div>
        <div class="footer">
            This is an automated alert from CHIE Coordinator.
        </div>
    </div>
</body>
</html>',
    '{{title}}

Severity: {{severity}}
Message: {{message}}
Metric Value: {{metric_value}}
Alert ID: {{alert_id}}
Created At: {{created_at}}

---
This is an automated alert from CHIE Coordinator.',
    true
)
ON CONFLICT (name) DO NOTHING;

-- Insert default rate limit (100 emails per hour, 500 per day for all recipients)
INSERT INTO email_rate_limits (recipient_pattern, max_emails_per_hour, max_emails_per_day, is_active)
VALUES ('*', 100, 500, true)
ON CONFLICT (recipient_pattern) DO NOTHING;

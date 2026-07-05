CREATE TABLE IF NOT EXISTS audit_events (
    id BIGSERIAL PRIMARY KEY,

    service TEXT NOT NULL,
    entity TEXT NOT NULL,

    old_data JSONB,
    new_data JSONB,
    operation TEXT NOT NULL,

    changed_by TEXT,
    occurred_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id BIGSERIAL PRIMARY KEY,

    service TEXT NOT NULL,
    severity TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    message TEXT NOT NULL,
    details JSONB,

    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS events (
    id          SERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ  NOT NULL,
    source_ip   INET         NOT NULL,
    source_port INTEGER,
    service     VARCHAR(10)  NOT NULL,
    event_type  VARCHAR(50)  NOT NULL,
    username    VARCHAR(255),
    password    VARCHAR(255),
    command     TEXT,
    payload     JSONB
);

CREATE INDEX IF NOT EXISTS events_timestamp_idx  ON events (timestamp);
CREATE INDEX IF NOT EXISTS events_source_ip_idx  ON events (source_ip);
CREATE INDEX IF NOT EXISTS events_service_idx    ON events (service);

# Honeypot System — Phase 1 Design: Core Honeypots + Logging

**Date:** 2026-06-04  
**Scope:** Phase 1 of 3 (Phase 2: Alerting, Phase 3: Reporting Dashboard)

---

## 1. Objective

Deploy a Docker-based honeypot system that detects unauthorized internal activity (lateral movement, reconnaissance, brute force) across three high-value protocols — SSH, HTTP, MySQL — and stores all interaction data in a structured PostgreSQL database for Phase 3 reporting.

---

## 2. Architecture

Four containers on a dedicated Docker bridge network (`honeypot-net`):

```
[Attacker]
    │
    ├─ :22   → [cowrie]       SSH medium-interaction honeypot
    ├─ :80   → [opencanary]   HTTP honeypot
    └─ :3306 → [opencanary]   MySQL honeypot
                │                 │
                └─────────────────┘
                      shared volumes
                          │
                    [log-collector]   ← tails + normalizes JSON logs
                          │
                     [postgres]       ← events table, internal only
```

- `honeypot-net` is a Docker bridge; no routing to production subnets
- PostgreSQL is not port-mapped to the host — only `log-collector` can reach it
- Cowrie and OpenCanary write JSON logs to named Docker volumes shared with `log-collector`
- All four services start with `docker-compose up -d`

---

## 3. Components

### `cowrie`
- Image: `cowrie/cowrie` (official)
- Protocol: SSH on port 2222 (mapped to configurable host port, default 22)
- Interaction level: Medium — fake filesystem, fake credentials that always succeed, command capture
- Fake filesystem pre-populated with: `.bash_history`, SSH keys, `/etc/passwd`, `/etc/shadow`
- Logs to: `cowrie.json` on shared volume `cowrie-logs`

### `opencanary`
- Image: Built from `python:3.11-slim` + OpenCanary
- Protocols: HTTP (port 80), MySQL (port 3306)
- HTTP: Fake admin login page returning 200 with plausible content
- MySQL: Accepts connections, logs auth attempts and client metadata
- Logs to: `opencanary.log` on shared volume `opencanary-logs`

### `log-collector`
- Image: Built from `python:3.11-slim`
- ~150 lines of Python using `pygtail` (offset-tracking file tail) and `psycopg2`
- Two parser functions: one for Cowrie's schema, one for OpenCanary's schema
- Normalizes both into a unified `Event` dataclass before DB insert
- Resumes from last offset on restart — no duplicate inserts
- Runs a daily retention job: deletes events older than 30 days
- Retries DB connection at startup with backoff

### `postgres`
- Image: `postgres:16-alpine`
- Database: `honeypot`
- Initialized via `init.sql` on first run
- Data persisted to named volume `postgres-data`
- Not port-mapped to host

---

## 4. Data Flow

```
1. Attacker connects to a honeypot port
2. Cowrie/OpenCanary handles the session → appends JSON event to log file
3. log-collector detects new lines via pygtail
4. Collector normalizes to unified Event:
     Cowrie fields    → timestamp, source_ip, source_port, service='ssh',
                        event_type, username, password, command, payload
     OpenCanary fields → same schema, service='http' or 'mysql'
5. Collector inserts row into postgres events table
6. On restart, pygtail resumes from saved offset (no duplicates)
```

---

## 5. Database Schema

```sql
CREATE TABLE events (
    id          SERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ  NOT NULL,
    source_ip   INET         NOT NULL,
    source_port INTEGER,
    service     VARCHAR(10)  NOT NULL,  -- 'ssh', 'http', 'mysql'
    event_type  VARCHAR(50)  NOT NULL,  -- 'login_attempt', 'command', 'connect', 'disconnect'
    username    VARCHAR(255),
    password    VARCHAR(255),
    command     TEXT,
    payload     JSONB                   -- full normalized event; service-specific fields
);

CREATE INDEX ON events (timestamp);
CREATE INDEX ON events (source_ip);
CREATE INDEX ON events (service);
```

- `payload` stores service-specific fields not covered by fixed columns (HTTP path, user-agent, MySQL client version)
- Phase 3 can query payload via `payload->>'key'`
- Retention: daily DELETE for rows older than 30 days, run inside `log-collector`

---

## 6. Project Structure

```
honeypot/
├── .env.example                # template: SSH_PORT, HTTP_PORT, MYSQL_PORT, POSTGRES_PASSWORD
├── .env                        # local copy (git-ignored)
├── docker-compose.yml
├── cowrie/
│   └── cowrie.cfg              # hostname, fake credentials, log path
├── opencanary/
│   ├── Dockerfile
│   └── opencanary.conf         # http=1, mysql=1, log path
├── log-collector/
│   ├── Dockerfile
│   ├── collector.py
│   └── requirements.txt        # psycopg2-binary, pygtail
└── postgres/
    └── init.sql                # CREATE TABLE + indexes
```

---

## 7. Deployment

```bash
cp .env.example .env       # set ports and DB password
docker-compose up -d       # starts all four containers
```

Port defaults (configurable in `.env`):

| Host Port | Container | Protocol |
|-----------|-----------|----------|
| 22        | cowrie    | SSH      |
| 80        | opencanary| HTTP     |
| 3306      | opencanary| MySQL    |

---

## 8. Out of Scope (Phase 1)

- Alerting (Slack, email, SIEM) — Phase 2
- Reporting dashboard, report generation — Phase 3
- SMB, RDP, Redis, FTP honeypots — future expansion
- macvlan networking — future option for more convincing host spoofing
- Deception tokens (fake credentials in files, fake DB records) — Phase 2

---

## 9. Success Criteria

- `docker-compose up -d` starts all containers cleanly
- SSH connection attempt to port 22 appears as a row in `events` table within 5 seconds
- HTTP GET to port 80 appears as a row in `events` table within 5 seconds
- MySQL auth attempt to port 3306 appears as a row in `events` table within 5 seconds
- `log-collector` restart does not produce duplicate rows
- Events older than 30 days are deleted by the retention job

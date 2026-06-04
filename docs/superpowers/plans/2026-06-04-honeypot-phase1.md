# Honeypot Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy a Docker-based honeypot system (Cowrie SSH + OpenCanary HTTP/MySQL) that captures all interaction events into a PostgreSQL database, started with a single `docker-compose up -d`.

**Architecture:** Four containers on a dedicated Docker bridge network (`honeypot-net`): `cowrie` (SSH), `opencanary` (HTTP + MySQL), `log-collector` (normalizes JSON logs → PostgreSQL), and `postgres`. The log-collector tails both log files via pygtail, normalizes each format into a unified `Event` schema, and inserts rows into a single `events` table.

**Tech Stack:** Python 3.11, psycopg2-binary, pygtail, PostgreSQL 16, Cowrie (official Docker image), OpenCanary, Docker Compose v2, pytest

---

## File Map

| File | Responsibility |
|------|---------------|
| `postgres/init.sql` | Schema: CREATE TABLE events + indexes |
| `log-collector/collector.py` | Event dataclass, parsers, DB functions, main loop |
| `log-collector/requirements.txt` | psycopg2-binary, pygtail, pytest |
| `log-collector/tests/conftest.py` | Postgres test fixture (session-scoped) |
| `log-collector/tests/test_parsers.py` | Unit tests for parse_cowrie, parse_opencanary |
| `log-collector/tests/test_db.py` | Integration tests for insert_event, run_retention |
| `log-collector/Dockerfile` | python:3.11-slim + collector.py |
| `opencanary/Dockerfile` | python:3.11-slim + opencanary install |
| `opencanary/opencanary.conf` | Enable http=1, mysql=1; configure log path |
| `cowrie/cowrie.cfg` | Hostname, log path, JSON output enabled |
| `docker-compose.yml` | All four services, volumes, network |
| `.env.example` | SSH_PORT, HTTP_PORT, MYSQL_PORT, POSTGRES_PASSWORD |

---

## Task 1: Project Scaffold

**Files:**
- Create: `postgres/init.sql`
- Create: `log-collector/requirements.txt`
- Create: `log-collector/tests/__init__.py` (empty)

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p honeypot/postgres
mkdir -p honeypot/cowrie
mkdir -p honeypot/opencanary
mkdir -p honeypot/log-collector/tests
touch honeypot/log-collector/tests/__init__.py
```

- [ ] **Step 2: Write `postgres/init.sql`**

```sql
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
```

- [ ] **Step 3: Write `log-collector/requirements.txt`**

```
psycopg2-binary==2.9.9
pygtail==0.14.0
pytest==8.2.0
```

- [ ] **Step 4: Commit**

```bash
cd honeypot
git add postgres/init.sql log-collector/requirements.txt log-collector/tests/__init__.py
git commit -m "feat: project scaffold — schema and requirements"
```

---

## Task 2: Event Dataclass + Cowrie Parser

**Files:**
- Create: `log-collector/collector.py`
- Create: `log-collector/tests/test_parsers.py`

- [ ] **Step 1: Write failing tests for `parse_cowrie`**

Create `log-collector/tests/test_parsers.py`:

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime, timezone
from collector import parse_cowrie

LOGIN_FAILED  = '{"eventid":"cowrie.login.failed","src_ip":"10.0.0.1","src_port":54321,"timestamp":"2024-01-01T00:00:00.000000Z","session":"abc","username":"root","password":"pass123"}'
COMMAND       = '{"eventid":"cowrie.command.input","src_ip":"10.0.0.1","src_port":54321,"timestamp":"2024-01-01T00:00:00.000000Z","session":"abc","input":"ls -la"}'
CONNECT       = '{"eventid":"cowrie.session.connect","src_ip":"10.0.0.1","src_port":54321,"timestamp":"2024-01-01T00:00:00.000000Z","session":"abc"}'
UNKNOWN_EVENT = '{"eventid":"cowrie.unknown","src_ip":"10.0.0.1","timestamp":"2024-01-01T00:00:00.000000Z"}'


def test_parse_cowrie_login_failed():
    e = parse_cowrie(LOGIN_FAILED)
    assert e is not None
    assert e.source_ip == '10.0.0.1'
    assert e.source_port == 54321
    assert e.service == 'ssh'
    assert e.event_type == 'login_attempt'
    assert e.username == 'root'
    assert e.password == 'pass123'
    assert e.command is None


def test_parse_cowrie_command():
    e = parse_cowrie(COMMAND)
    assert e is not None
    assert e.event_type == 'command'
    assert e.command == 'ls -la'
    assert e.username is None


def test_parse_cowrie_connect():
    e = parse_cowrie(CONNECT)
    assert e is not None
    assert e.event_type == 'connect'


def test_parse_cowrie_timestamp():
    e = parse_cowrie(LOGIN_FAILED)
    assert e.timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)


def test_parse_cowrie_unknown_returns_none():
    assert parse_cowrie(UNKNOWN_EVENT) is None


def test_parse_cowrie_invalid_json_returns_none():
    assert parse_cowrie('not json') is None
```

- [ ] **Step 2: Run tests — verify they fail with `ModuleNotFoundError`**

```bash
cd honeypot/log-collector
pip install -r requirements.txt
pytest tests/test_parsers.py -v
```

Expected: `ModuleNotFoundError: No module named 'collector'`

- [ ] **Step 3: Create `log-collector/collector.py` with Event dataclass and stub**

```python
import json
import os
import time
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import psycopg2
from pygtail import Pygtail

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger(__name__)

COWRIE_LOG    = os.environ.get('COWRIE_LOG',    '/var/log/cowrie/cowrie.json')
OPENCANARY_LOG = os.environ.get('OPENCANARY_LOG', '/var/log/opencanary/opencanary.log')
OFFSETS_DIR   = os.environ.get('OFFSETS_DIR',   '/var/offsets')
POLL_INTERVAL = int(os.environ.get('POLL_INTERVAL', '2'))
RETENTION_DAYS = int(os.environ.get('RETENTION_DAYS', '30'))

COWRIE_EVENT_MAP = {
    'cowrie.login.failed':   'login_attempt',
    'cowrie.login.success':  'login_attempt',
    'cowrie.command.input':  'command',
    'cowrie.session.connect':'connect',
    'cowrie.session.closed': 'disconnect',
}

OPENCANARY_TYPE_MAP = {
    3000: ('http',  'login_attempt'),
    8001: ('mysql', 'login_attempt'),
}


@dataclass
class Event:
    timestamp:   datetime
    source_ip:   str
    source_port: Optional[int]
    service:     str
    event_type:  str
    username:    Optional[str] = None
    password:    Optional[str] = None
    command:     Optional[str] = None
    payload:     dict = field(default_factory=dict)


def parse_cowrie(line: str) -> Optional[Event]:
    pass  # TODO


def parse_opencanary(line: str) -> Optional[Event]:
    pass  # TODO
```

- [ ] **Step 4: Run tests — verify they fail with `AssertionError` (not import error)**

```bash
pytest tests/test_parsers.py -v
```

Expected: `FAILED tests/test_parsers.py::test_parse_cowrie_login_failed — AssertionError`

- [ ] **Step 5: Implement `parse_cowrie`**

Replace the `parse_cowrie` stub in `collector.py`:

```python
def parse_cowrie(line: str) -> Optional[Event]:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    event_type = COWRIE_EVENT_MAP.get(data.get('eventid'))
    if not event_type:
        return None

    return Event(
        timestamp=datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00')),
        source_ip=data.get('src_ip', ''),
        source_port=data.get('src_port'),
        service='ssh',
        event_type=event_type,
        username=data.get('username'),
        password=data.get('password'),
        command=data.get('input'),
        payload={k: v for k, v in data.items()
                 if k not in ('eventid', 'src_ip', 'src_port', 'timestamp',
                              'username', 'password', 'input')},
    )
```

- [ ] **Step 6: Run tests — verify all Cowrie tests pass**

```bash
pytest tests/test_parsers.py -v -k cowrie
```

Expected: `6 passed`

- [ ] **Step 7: Commit**

```bash
git add log-collector/collector.py log-collector/tests/test_parsers.py
git commit -m "feat: Event dataclass and Cowrie parser with tests"
```

---

## Task 3: OpenCanary Parser

**Files:**
- Modify: `log-collector/tests/test_parsers.py` (add OpenCanary tests)
- Modify: `log-collector/collector.py` (implement parse_opencanary)

- [ ] **Step 1: Add failing OpenCanary tests to `test_parsers.py`**

Append to `log-collector/tests/test_parsers.py`:

```python
from collector import parse_opencanary

HTTP  = '{"dst_host":"192.168.1.100","dst_port":80,"local_time":"2024-01-01 00:00:00.000000","logdata":{"HEADERS":{},"PATH":"/admin","USERNAME":"admin","PASSWORD":"admin"},"logtype":3000,"node_id":"opencanary-1","src_host":"10.0.0.2","src_port":54322,"utc_time":"2024-01-01 00:00:00.000000"}'
MYSQL = '{"dst_host":"192.168.1.100","dst_port":3306,"local_time":"2024-01-01 00:00:00.000000","logdata":{"PASSWORD":"secret","USERNAME":"root"},"logtype":8001,"node_id":"opencanary-1","src_host":"10.0.0.3","src_port":54323,"utc_time":"2024-01-01 00:00:00.000000"}'
OC_UNKNOWN = '{"logtype":9999,"src_host":"10.0.0.1","src_port":100,"utc_time":"2024-01-01 00:00:00.000000"}'


def test_parse_opencanary_http():
    e = parse_opencanary(HTTP)
    assert e is not None
    assert e.source_ip == '10.0.0.2'
    assert e.source_port == 54322
    assert e.service == 'http'
    assert e.event_type == 'login_attempt'
    assert e.username == 'admin'
    assert e.password == 'admin'


def test_parse_opencanary_mysql():
    e = parse_opencanary(MYSQL)
    assert e is not None
    assert e.source_ip == '10.0.0.3'
    assert e.service == 'mysql'
    assert e.event_type == 'login_attempt'
    assert e.username == 'root'
    assert e.password == 'secret'


def test_parse_opencanary_timestamp():
    e = parse_opencanary(HTTP)
    assert e.timestamp == datetime(2024, 1, 1, tzinfo=timezone.utc)


def test_parse_opencanary_unknown_logtype_returns_none():
    assert parse_opencanary(OC_UNKNOWN) is None


def test_parse_opencanary_invalid_json_returns_none():
    assert parse_opencanary('not json') is None
```

- [ ] **Step 2: Run new tests — verify they fail**

```bash
pytest tests/test_parsers.py -v -k opencanary
```

Expected: `5 failed`

- [ ] **Step 3: Implement `parse_opencanary`**

Replace the `parse_opencanary` stub in `collector.py`:

```python
def parse_opencanary(line: str) -> Optional[Event]:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return None

    mapping = OPENCANARY_TYPE_MAP.get(data.get('logtype'))
    if not mapping:
        return None

    service, event_type = mapping
    logdata = data.get('logdata', {})

    try:
        timestamp = datetime.strptime(
            data.get('utc_time', ''), '%Y-%m-%d %H:%M:%S.%f'
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        timestamp = datetime.now(timezone.utc)

    return Event(
        timestamp=timestamp,
        source_ip=data.get('src_host', ''),
        source_port=data.get('src_port'),
        service=service,
        event_type=event_type,
        username=logdata.get('USERNAME'),
        password=logdata.get('PASSWORD'),
        command=None,
        payload={k: v for k, v in data.items()
                 if k not in ('src_host', 'src_port', 'utc_time',
                              'logtype', 'logdata', 'local_time')},
    )
```

- [ ] **Step 4: Run all parser tests — verify all pass**

```bash
pytest tests/test_parsers.py -v
```

Expected: `11 passed`

- [ ] **Step 5: Commit**

```bash
git add log-collector/collector.py log-collector/tests/test_parsers.py
git commit -m "feat: OpenCanary parser with tests"
```

---

## Task 4: DB Functions (insert_event + run_retention)

**Files:**
- Create: `log-collector/tests/conftest.py`
- Create: `log-collector/tests/test_db.py`
- Modify: `log-collector/collector.py` (add insert_event, run_retention)

**Prerequisite:** A PostgreSQL instance must be running for these tests.

```bash
docker run -d --name test-postgres \
  -e POSTGRES_DB=honeypot_test \
  -e POSTGRES_USER=honeypot \
  -e POSTGRES_PASSWORD=honeypot \
  -p 5432:5432 \
  postgres:16-alpine
# wait ~3s for it to start
docker exec test-postgres psql -U honeypot -d honeypot_test \
  -f /dev/stdin < honeypot/postgres/init.sql
```

- [ ] **Step 1: Write `log-collector/tests/conftest.py`**

```python
import os
import pytest
import psycopg2

@pytest.fixture(scope='session')
def db_conn():
    try:
        conn = psycopg2.connect(
            host=os.environ.get('TEST_PG_HOST', 'localhost'),
            port=int(os.environ.get('TEST_PG_PORT', '5432')),
            dbname=os.environ.get('TEST_PG_DB', 'honeypot_test'),
            user=os.environ.get('TEST_PG_USER', 'honeypot'),
            password=os.environ.get('TEST_PG_PASSWORD', 'honeypot'),
        )
    except psycopg2.OperationalError:
        pytest.skip('postgres not available — start test-postgres container first')
    yield conn
    conn.close()


@pytest.fixture(autouse=True)
def clean_events(db_conn):
    yield
    with db_conn.cursor() as cur:
        cur.execute('DELETE FROM events')
    db_conn.commit()
```

- [ ] **Step 2: Write failing tests in `log-collector/tests/test_db.py`**

```python
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
import pytest
from datetime import datetime, timezone
from collector import Event, insert_event, run_retention


def make_event(**overrides):
    defaults = dict(
        timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        source_ip='10.0.0.1',
        source_port=54321,
        service='ssh',
        event_type='login_attempt',
        username='root',
        password='pass123',
        command=None,
        payload={},
    )
    defaults.update(overrides)
    return Event(**defaults)


def test_insert_event_basic(db_conn):
    insert_event(db_conn, make_event())
    with db_conn.cursor() as cur:
        cur.execute('SELECT source_ip, service, event_type, username FROM events')
        row = cur.fetchone()
    assert row == ('10.0.0.1', 'ssh', 'login_attempt', 'root')


def test_insert_event_null_password(db_conn):
    insert_event(db_conn, make_event(password=None, event_type='connect'))
    with db_conn.cursor() as cur:
        cur.execute('SELECT password FROM events')
        row = cur.fetchone()
    assert row[0] is None


def test_insert_event_payload_queryable(db_conn):
    insert_event(db_conn, make_event(payload={'session': 'abc123'}))
    with db_conn.cursor() as cur:
        cur.execute("SELECT payload->>'session' FROM events")
        row = cur.fetchone()
    assert row[0] == 'abc123'


def test_run_retention_deletes_old_events(db_conn):
    insert_event(db_conn, make_event(timestamp=datetime(2020, 1, 1, tzinfo=timezone.utc)))
    insert_event(db_conn, make_event(timestamp=datetime.now(timezone.utc)))
    run_retention(db_conn, days=30)
    with db_conn.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM events')
        count = cur.fetchone()[0]
    assert count == 1


def test_run_retention_keeps_recent_events(db_conn):
    insert_event(db_conn, make_event(timestamp=datetime.now(timezone.utc)))
    run_retention(db_conn, days=30)
    with db_conn.cursor() as cur:
        cur.execute('SELECT COUNT(*) FROM events')
        count = cur.fetchone()[0]
    assert count == 1
```

- [ ] **Step 3: Run tests — verify they fail with `ImportError` for insert_event**

```bash
pytest tests/test_db.py -v
```

Expected: `ImportError: cannot import name 'insert_event' from 'collector'`

- [ ] **Step 4: Add `insert_event` and `run_retention` to `collector.py`**

Add these functions after the parser functions:

```python
def connect_db() -> psycopg2.extensions.connection:
    while True:
        try:
            conn = psycopg2.connect(
                host=os.environ['POSTGRES_HOST'],
                dbname=os.environ['POSTGRES_DB'],
                user=os.environ['POSTGRES_USER'],
                password=os.environ['POSTGRES_PASSWORD'],
            )
            log.info('Connected to postgres')
            return conn
        except psycopg2.OperationalError as e:
            log.warning(f'DB connection failed: {e}, retrying in 5s')
            time.sleep(5)


def insert_event(conn, event: Event) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO events
                (timestamp, source_ip, source_port, service, event_type,
                 username, password, command, payload)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event.timestamp,
                event.source_ip,
                event.source_port,
                event.service,
                event.event_type,
                event.username,
                event.password,
                event.command,
                json.dumps(event.payload),
            ),
        )
    conn.commit()


def run_retention(conn, days: int = RETENTION_DAYS) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "DELETE FROM events WHERE timestamp < NOW() - INTERVAL %s",
            (f'{days} days',),
        )
        deleted = cur.rowcount
    conn.commit()
    if deleted:
        log.info(f'Retention: deleted {deleted} events older than {days} days')
```

- [ ] **Step 5: Run DB tests — verify all pass**

```bash
pytest tests/test_db.py -v
```

Expected: `5 passed`

- [ ] **Step 6: Run full test suite — verify nothing broken**

```bash
pytest tests/ -v
```

Expected: `16 passed`

- [ ] **Step 7: Commit**

```bash
git add log-collector/collector.py log-collector/tests/conftest.py log-collector/tests/test_db.py
git commit -m "feat: insert_event and run_retention with DB tests"
```

---

## Task 5: Main Collector Loop + log-collector Dockerfile

**Files:**
- Modify: `log-collector/collector.py` (add tail_and_insert + main)
- Create: `log-collector/Dockerfile`

- [ ] **Step 1: Add `tail_and_insert` and `main` to `collector.py`**

Append to `collector.py`:

```python
def tail_and_insert(conn, log_path: str, parser) -> None:
    if not os.path.exists(log_path):
        return
    os.makedirs(OFFSETS_DIR, exist_ok=True)
    offset_file = os.path.join(OFFSETS_DIR, os.path.basename(log_path) + '.offset')
    try:
        for line in Pygtail(log_path, offset_file=offset_file):
            line = line.strip()
            if not line:
                continue
            event = parser(line)
            if event:
                insert_event(conn, event)
    except Exception as e:
        log.error(f'Error tailing {log_path}: {e}')


def main() -> None:
    conn = connect_db()
    last_retention = datetime.now(timezone.utc)

    while True:
        tail_and_insert(conn, COWRIE_LOG, parse_cowrie)
        tail_and_insert(conn, OPENCANARY_LOG, parse_opencanary)

        now = datetime.now(timezone.utc)
        if (now - last_retention).total_seconds() > 86400:
            run_retention(conn)
            last_retention = now

        time.sleep(POLL_INTERVAL)


if __name__ == '__main__':
    main()
```

- [ ] **Step 2: Create `log-collector/Dockerfile`**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collector.py .

CMD ["python", "collector.py"]
```

- [ ] **Step 3: Verify the image builds**

```bash
cd honeypot/log-collector
docker build -t honeypot-collector:test .
```

Expected: `Successfully built ...` (no errors)

- [ ] **Step 4: Commit**

```bash
cd honeypot
git add log-collector/collector.py log-collector/Dockerfile
git commit -m "feat: main collector loop and Dockerfile"
```

---

## Task 6: OpenCanary Dockerfile + Config

**Files:**
- Create: `opencanary/Dockerfile`
- Create: `opencanary/opencanary.conf`

- [ ] **Step 1: Write `opencanary/Dockerfile`**

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev gcc \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir opencanary

RUN mkdir -p /etc/opencanary /var/log/opencanary

COPY opencanary.conf /etc/opencanary/opencanary.conf

EXPOSE 80 3306

CMD ["opencanaryd", "--start", "--uid=nobody", "--gid=nogroup"]
```

- [ ] **Step 2: Write `opencanary/opencanary.conf`**

```json
{
    "device.node_id": "opencanary-1",
    "device.listen_addr": "0.0.0.0",
    "ftp.enabled": false,
    "git.enabled": false,
    "http.enabled": true,
    "http.port": 80,
    "http.skin": "basicLogin",
    "http.skin.list": [{"desc": "Basic login", "name": "basicLogin"}],
    "mysql.enabled": true,
    "mysql.port": 3306,
    "mysql.banner": "5.7.21-log",
    "ssh.enabled": false,
    "logger": {
        "class": "PyLogger",
        "kwargs": {
            "formatters": {
                "plain": {"format": "%(message)s"}
            },
            "handlers": {
                "file": {
                    "class": "logging.FileHandler",
                    "filename": "/var/log/opencanary/opencanary.log",
                    "formatter": "plain"
                }
            }
        }
    }
}
```

- [ ] **Step 3: Verify the image builds**

```bash
cd honeypot/opencanary
docker build -t honeypot-opencanary:test .
```

Expected: `Successfully built ...` (no errors; takes ~60s first time)

- [ ] **Step 4: Commit**

```bash
cd honeypot
git add opencanary/Dockerfile opencanary/opencanary.conf
git commit -m "feat: OpenCanary Dockerfile and config for HTTP + MySQL"
```

---

## Task 7: Cowrie Configuration

**Files:**
- Create: `cowrie/cowrie.cfg`

- [ ] **Step 1: Write `cowrie/cowrie.cfg`**

```ini
[honeypot]
hostname = webserver01
log_path = /cowrie/var/log/cowrie
download_path = /cowrie/var/lib/cowrie/downloads
share_path = /cowrie/share/cowrie
state_path = /cowrie/var/lib/cowrie
etc_path = /cowrie/etc
contents_path = /cowrie/honeyfs
txtcmds_path = /cowrie/txtcmds

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0
version = SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json
epoch_timestamp = false
```

- [ ] **Step 2: Commit**

```bash
git add cowrie/cowrie.cfg
git commit -m "feat: Cowrie SSH honeypot configuration"
```

---

## Task 8: docker-compose.yml + .env.example

**Files:**
- Create: `docker-compose.yml`
- Create: `.env.example`
- Create: `.gitignore`

- [ ] **Step 1: Write `.env.example`**

```bash
# Host ports exposed by honeypot services — change if ports conflict
SSH_PORT=22
HTTP_PORT=80
MYSQL_PORT=3306

# PostgreSQL password — change before deploying
POSTGRES_PASSWORD=changeme
```

- [ ] **Step 2: Write `.gitignore`**

```
.env
```

- [ ] **Step 3: Write `docker-compose.yml`**

```yaml
services:
  cowrie:
    image: cowrie/cowrie:latest
    container_name: cowrie
    restart: unless-stopped
    volumes:
      - ./cowrie/cowrie.cfg:/cowrie/etc/cowrie.cfg:ro
      - cowrie-logs:/cowrie/var/log/cowrie
    ports:
      - "${SSH_PORT:-22}:2222"
    networks:
      - honeypot-net

  opencanary:
    build: ./opencanary
    container_name: opencanary
    restart: unless-stopped
    volumes:
      - opencanary-logs:/var/log/opencanary
    ports:
      - "${HTTP_PORT:-80}:80"
      - "${MYSQL_PORT:-3306}:3306"
    networks:
      - honeypot-net

  log-collector:
    build: ./log-collector
    container_name: log-collector
    restart: unless-stopped
    volumes:
      - cowrie-logs:/var/log/cowrie:ro
      - opencanary-logs:/var/log/opencanary:ro
      - collector-offsets:/var/offsets
    environment:
      POSTGRES_HOST: postgres
      POSTGRES_DB: honeypot
      POSTGRES_USER: honeypot
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      COWRIE_LOG: /var/log/cowrie/cowrie.json
      OPENCANARY_LOG: /var/log/opencanary/opencanary.log
      OFFSETS_DIR: /var/offsets
      POLL_INTERVAL: "2"
    depends_on:
      - postgres
    networks:
      - honeypot-net

  postgres:
    image: postgres:16-alpine
    container_name: postgres
    restart: unless-stopped
    environment:
      POSTGRES_DB: honeypot
      POSTGRES_USER: honeypot
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - ./postgres/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
      - postgres-data:/var/lib/postgresql/data
    networks:
      - honeypot-net

volumes:
  cowrie-logs:
  opencanary-logs:
  postgres-data:
  collector-offsets:

networks:
  honeypot-net:
    driver: bridge
```

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml .env.example .gitignore
git commit -m "feat: docker-compose and env template"
```

---

## Task 9: End-to-End Smoke Test

**Prerequisites:** Docker and Docker Compose v2 installed. Ports 22, 80, 3306 free on the host (or edit `.env`).

- [ ] **Step 1: Start all services**

```bash
cd honeypot
cp .env.example .env
# Edit .env if ports 22/80/3306 are in use
docker compose up -d --build
```

Expected: All four containers show `Started` or `Running`.

- [ ] **Step 2: Verify all containers are healthy**

```bash
docker compose ps
```

Expected: `cowrie`, `opencanary`, `log-collector`, `postgres` all have status `running`.

- [ ] **Step 3: Trigger an SSH login attempt**

```bash
ssh -o StrictHostKeyChecking=no -p 22 root@localhost
# Enter any password when prompted, then Ctrl+C
```

Expected: Cowrie presents a fake SSH banner and accepts the connection.

- [ ] **Step 4: Trigger an HTTP request**

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:80/
```

Expected: `200`

- [ ] **Step 5: Trigger a MySQL auth attempt**

```bash
mysql -h 127.0.0.1 -P 3306 -u root -pwrongpass --connect-timeout=3 2>&1 || true
```

Expected: connection attempt is made (OpenCanary logs it even if it rejects)

- [ ] **Step 6: Wait for log-collector to process, then query the DB**

```bash
sleep 5
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT timestamp, source_ip, service, event_type, username FROM events ORDER BY timestamp DESC LIMIT 10;"
```

Expected: Rows visible for `ssh`, `http`, and `mysql` services.

- [ ] **Step 7: Verify no duplicate rows on collector restart**

```bash
docker compose restart log-collector
sleep 5
docker exec postgres psql -U honeypot -d honeypot \
  -c "SELECT COUNT(*) FROM events;"
```

Expected: Row count is unchanged after restart (pygtail offset prevents re-processing).

- [ ] **Step 8: Commit final state**

```bash
git add .
git commit -m "feat: Phase 1 complete — honeypot + logging operational"
```

---

## Success Criteria Checklist

- [ ] `docker-compose up -d` starts all four containers without errors
- [ ] SSH attempt → row in `events` within 5 seconds
- [ ] HTTP request → row in `events` within 5 seconds
- [ ] MySQL attempt → row in `events` within 5 seconds
- [ ] Collector restart produces no duplicate rows
- [ ] All 16 unit + integration tests pass (`pytest tests/ -v`)

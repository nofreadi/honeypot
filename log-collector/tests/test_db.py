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

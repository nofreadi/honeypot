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

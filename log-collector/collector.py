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


def parse_opencanary(line: str) -> Optional[Event]:
    pass  # TODO

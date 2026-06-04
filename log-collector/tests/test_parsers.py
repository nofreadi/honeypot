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

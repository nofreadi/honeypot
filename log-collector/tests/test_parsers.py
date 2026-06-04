import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from datetime import datetime, timezone
from collector import parse_cowrie, parse_opencanary

LOGIN_FAILED  = '{"eventid":"cowrie.login.failed","src_ip":"10.0.0.1","src_port":54321,"timestamp":"2024-01-01T00:00:00.000000Z","session":"abc","username":"root","password":"pass123"}'
COMMAND       = '{"eventid":"cowrie.command.input","src_ip":"10.0.0.1","src_port":54321,"timestamp":"2024-01-01T00:00:00.000000Z","session":"abc","input":"ls -la"}'
CONNECT       = '{"eventid":"cowrie.session.connect","src_ip":"10.0.0.1","src_port":54321,"timestamp":"2024-01-01T00:00:00.000000Z","session":"abc"}'
UNKNOWN_EVENT = '{"eventid":"cowrie.unknown","src_ip":"10.0.0.1","timestamp":"2024-01-01T00:00:00.000000Z"}'

HTTP  = '{"dst_host":"192.168.1.100","dst_port":80,"local_time":"2024-01-01 00:00:00.000000","logdata":{"HEADERS":{},"PATH":"/admin","USERNAME":"admin","PASSWORD":"admin"},"logtype":3000,"node_id":"opencanary-1","src_host":"10.0.0.2","src_port":54322,"utc_time":"2024-01-01 00:00:00.000000"}'
MYSQL = '{"dst_host":"192.168.1.100","dst_port":3306,"local_time":"2024-01-01 00:00:00.000000","logdata":{"PASSWORD":"secret","USERNAME":"root"},"logtype":8001,"node_id":"opencanary-1","src_host":"10.0.0.3","src_port":54323,"utc_time":"2024-01-01 00:00:00.000000"}'
OC_UNKNOWN = '{"logtype":9999,"src_host":"10.0.0.1","src_port":100,"utc_time":"2024-01-01 00:00:00.000000"}'


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

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

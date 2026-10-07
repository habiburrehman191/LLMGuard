"""One disposable synthetic incident for native Incident Detail browser QA."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'reports/ui/security-incident-detail'
PREVIEW = OUTPUT / 'preview'
PREVIEW.mkdir(parents=True, exist_ok=True)
os.environ['LLMGUARD_DB_PATH'] = str(PREVIEW / 'llmguard.db')
os.environ['LLMGUARD_TESTBED_DATABASE_URL'] = 'sqlite:///' + (PREVIEW / 'auth.db').as_posix()

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application
from app.db import init_db
from app.security_events import get_incident, list_incidents, record_security_event


def fixture():
    init_db()
    bootstrap_default_application()
    with sqlite3.connect(PREVIEW / 'llmguard.db') as db:
        for table in ('security_incident_status_audit', 'security_incident_events', 'security_incidents', 'security_events'):
            db.execute(f'DELETE FROM {table}')
    request_id = 'synthetic-detail-request-&-='.ljust(200, 'x')
    for stage, event_type, severity, risk, action in [('input', 'INPUT_FIREWALL', 'high', .97, 'block'),
                                                   ('context', 'CONTEXT_FIREWALL', 'critical', None, 'quarantine'),
                                                   ('output', 'OUTPUT_FIREWALL', 'high', 0, 'block')]:
        record_security_event(application_id=UNIVERSITY_APPLICATION_ID, channel='student', request_id=request_id,
                              stage=stage, event_type=event_type, classification='malicious', severity=severity,
                              risk_score=risk, action=action, source_id='synthetic-source-id' if stage == 'context' else None,
                              chunk_id='synthetic-chunk-id' if stage == 'context' else None)
    snapshot()


def snapshot():
    incident = list_incidents()[0]
    (OUTPUT / 'fixture.json').write_text(json.dumps(asdict(get_incident(incident.incident_id)), indent=2), encoding='utf-8')


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) == 2 else ''
    if mode == 'serve':
        from app.auth import seed_development_users
        from app.database import SessionLocal, init_database
        import uvicorn
        init_database()
        with SessionLocal() as db:
            seed_development_users(db)
        fixture()
        uvicorn.run('app.main:app', host='127.0.0.1', port=8769)
    elif mode == 'incident':
        fixture()
    elif mode == 'snapshot':
        snapshot()
    else:
        raise ValueError('Choose serve/incident/snapshot.')

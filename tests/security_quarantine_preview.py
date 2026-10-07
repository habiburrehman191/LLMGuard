"""Isolated persisted synthetic evidence for Quarantine browser QA only."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'reports/ui/security-quarantine'
mode = sys.argv[1] if len(sys.argv) == 2 else ''
if mode not in ('serve', 'serve-empty', 'fixtures'):
    raise ValueError('Choose serve, serve-empty, or fixtures.')
PREVIEW = OUTPUT / ('preview-empty' if mode == 'serve-empty' else 'preview')
PREVIEW.mkdir(parents=True, exist_ok=True)
os.environ['LLMGUARD_DB_PATH'] = str(PREVIEW / 'llmguard.db')
os.environ['LLMGUARD_TESTBED_DATABASE_URL'] = 'sqlite:///' + (PREVIEW / 'auth.db').as_posix()

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application, register_application
from app.db import init_db
from app.security_events import get_request_trace, list_quarantine_events, record_security_event


def fixture():
    init_db()
    bootstrap_default_application()
    other = register_application(organization_name='Synthetic QA', organization_slug='synthetic-qa',
                                 application_id='synthetic-quarantine-app', name='Synthetic Quarantine App',
                                 slug='synthetic-quarantine-app', environment='test', status='active', channels=('public',))
    empty = register_application(organization_name='Synthetic QA', organization_slug='synthetic-qa',
                                 application_id='synthetic-quarantine-empty', name='Synthetic Empty App',
                                 slug='synthetic-quarantine-empty', environment='test', status='active', channels=('public',))
    if mode != 'serve-empty':
        definitions = [
            (UNIVERSITY_APPLICATION_ID, 'synthetic-quarantine-request-&-=/#'.ljust(200, 'x'), 'context', 'CONTEXT_FIREWALL', 'malicious', 'high', 'synthetic-source-'.ljust(300, 's'), 'synthetic-chunk-'.ljust(300, 'c')),
            (UNIVERSITY_APPLICATION_ID, 'synthetic-quarantine-input', 'input', 'INPUT_FIREWALL', 'suspicious', 'medium', None, None),
            (other.application_id, 'synthetic-quarantine-other', 'context', 'CONTEXT_FIREWALL', 'malicious', 'high', 'synthetic-other-source', 'synthetic-other-chunk'),
        ]
        for application_id, request_id, stage, event_type, classification, severity, source_id, chunk_id in definitions:
            if not get_request_trace(application_id, request_id):
                record_security_event(application_id=application_id, channel='public', stage=stage, event_type=event_type,
                                      classification=classification, severity=severity, action='quarantine', risk_score=.8,
                                      request_id=request_id, source_id=source_id, chunk_id=chunk_id)
        # Optional references are absent on this valid stored record; it has no incident association.
        if not any(r.event.request_id is None for r in list_quarantine_events()):
            record_security_event(application_id=other.application_id, channel='public', stage='context',
                                  event_type='CONTEXT_FIREWALL', classification='safe', severity='low', action='quarantine')
        if not get_request_trace(other.application_id, 'synthetic-not-quarantined'):
            record_security_event(application_id=other.application_id, channel='public', stage='input',
                                  event_type='INPUT_FIREWALL', classification='safe', severity='low', action='allow',
                                  request_id='synthetic-not-quarantined')
    manifest = {'records': [{'event': asdict(r.event), 'incident_id': r.incident_id} for r in list_quarantine_events()],
                'application_id': UNIVERSITY_APPLICATION_ID, 'other_application_id': other.application_id,
                'empty_application_id': empty.application_id}
    (OUTPUT / ('empty-fixtures.json' if mode == 'serve-empty' else 'fixtures.json')).write_text(json.dumps(manifest, indent=2), encoding='utf-8')


if __name__ == '__main__':
    fixture()
    if mode in ('serve', 'serve-empty'):
        from app.auth import seed_development_users
        from app.database import SessionLocal, init_database
        import uvicorn
        init_database()
        with SessionLocal() as db:
            seed_development_users(db)
        uvicorn.run('app.main:app', host='127.0.0.1', port=8772 if mode == 'serve-empty' else 8771)

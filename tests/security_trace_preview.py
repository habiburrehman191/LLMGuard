"""Disposable stored synthetic traces for Request Trace browser QA only."""
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'reports/ui/security-trace'
PREVIEW = OUTPUT / 'preview'
PREVIEW.mkdir(parents=True, exist_ok=True)
os.environ['LLMGUARD_DB_PATH'] = str(PREVIEW / 'llmguard.db')
os.environ['LLMGUARD_TESTBED_DATABASE_URL'] = 'sqlite:///' + (PREVIEW / 'auth.db').as_posix()

from app.application_registry import UNIVERSITY_APPLICATION_ID, bootstrap_default_application, register_application
from app.db import init_db
from app.security_events import get_request_trace, record_security_event


def fixture():
    init_db()
    bootstrap_default_application()
    other = register_application(organization_name='Synthetic QA', organization_slug='synthetic-qa',
                                 application_id='synthetic-trace-app', name='Synthetic Trace App', slug='synthetic-trace-app',
                                 environment='test', status='active', channels=('public',))
    definitions = {
        'blocked': ('synthetic-trace-input-block', [('input', 'INPUT_FIREWALL', 'block', 'malicious', .97)]),
        'allowed': ('synthetic-trace-allowed', [('input', 'INPUT_FIREWALL', 'allow', 'safe', 0), ('context', 'CONTEXT_FIREWALL', 'allow', 'safe', .03), ('output', 'OUTPUT_FIREWALL', 'allow', 'safe', .02)]),
        'sanitized': ('synthetic-trace-sanitized', [('input', 'INPUT_FIREWALL', 'allow', 'safe', .02), ('context', 'CONTEXT_FIREWALL', 'sanitize', 'suspicious', .45), ('output', 'OUTPUT_FIREWALL', 'allow', 'safe', 0)]),
        'output_blocked': ('synthetic-trace-output-block', [('input', 'INPUT_FIREWALL', 'allow', 'safe', .02), ('context', 'CONTEXT_FIREWALL', 'allow', 'safe', .02), ('output', 'OUTPUT_FIREWALL', 'block', 'malicious', .96)]),
        'bypassed': ('synthetic-trace-bypass', [('input', 'PROTECTION_BYPASS', 'bypass', 'bypassed', None)]),
        'session': ('synthetic-trace-session', [('input', 'SESSION_RESTRICTION', 'session_restrict', 'session_risk', .62)]),
        'additional': ('synthetic-trace-boundary', [('input', 'INPUT_FIREWALL', 'allow', 'safe', .01), ('university_authorization', 'UNIVERSITY_AUTHORIZATION', 'allow', 'safe', None), ('retrieval', 'RETRIEVAL_AUDIT', 'log', 'safe', None), ('context', 'CONTEXT_FIREWALL', 'sanitize', 'suspicious', .4), ('output', 'OUTPUT_FIREWALL', 'allow', 'safe', .01)]),
        'long_id': ('synthetic-trace-long-&-='.ljust(200, 'x'), [('input', 'INPUT_FIREWALL', 'block', 'malicious', .99)]),
        'ambiguous': ('synthetic-trace-shared-&-=', [('input', 'INPUT_FIREWALL', 'allow', 'safe', .01)]),
    }
    manifest = {}
    for name, (request_id, rows) in definitions.items():
        if not get_request_trace(UNIVERSITY_APPLICATION_ID, request_id):
            for stage, event_type, action, classification, risk in rows:
                record_security_event(application_id=UNIVERSITY_APPLICATION_ID, channel='student', request_id=request_id,
                                      stage=stage, event_type=event_type, classification=classification,
                                      severity='high' if action in ('block', 'session_restrict') else 'medium' if action == 'sanitize' else 'none' if action == 'bypass' else 'low',
                                      risk_score=risk, action=action, source_id='synthetic-source-id' if stage == 'context' else None,
                                      chunk_id='synthetic-chunk-id' if stage == 'context' else None)
        manifest[name] = {'request_id': request_id, 'application_id': UNIVERSITY_APPLICATION_ID,
                          'events': [asdict(e) for e in get_request_trace(UNIVERSITY_APPLICATION_ID, request_id)]}
    shared = manifest['ambiguous']['request_id']
    if not get_request_trace(other.application_id, shared):
        record_security_event(application_id=other.application_id, channel='public', request_id=shared, stage='integration',
                              event_type='INTEGRATION_AUDIT', classification='safe', severity='low', risk_score=None, action='log')
    manifest['ambiguous']['other_application_id'] = other.application_id
    manifest['ambiguous']['other_events'] = [asdict(e) for e in get_request_trace(other.application_id, shared)]
    (OUTPUT / 'fixtures.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('serve', 'fixtures'):
        raise ValueError('Choose serve/fixtures.')
    fixture()
    if sys.argv[1] == 'serve':
        from app.auth import seed_development_users
        from app.database import SessionLocal, init_database
        import uvicorn
        init_database()
        with SessionLocal() as db:
            seed_development_users(db)
        uvicorn.run('app.main:app', host='127.0.0.1', port=8770)

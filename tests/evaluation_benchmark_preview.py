"""Isolated auth/data stores; reads the real final report without running evaluation."""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
mode = sys.argv[1] if len(sys.argv) == 2 else ''
if mode not in ('serve', 'serve-unavailable'):
    raise ValueError('Choose serve or serve-unavailable.')
PREVIEW = ROOT / 'reports/ui/evaluation-benchmark' / ('preview' if mode == 'serve' else 'preview-unavailable')
PREVIEW.mkdir(parents=True, exist_ok=True)
os.environ['LLMGUARD_DB_PATH'] = str(PREVIEW / 'llmguard.db')
os.environ['LLMGUARD_TESTBED_DATABASE_URL'] = 'sqlite:///' + (PREVIEW / 'auth.db').as_posix()

if __name__ == '__main__':
    from app.db import init_db
    from app.auth import seed_development_users
    from app.database import SessionLocal, init_database
    from app.main import app
    import uvicorn
    init_db()
    init_database()
    with SessionLocal() as db:
        seed_development_users(db)
    if mode == 'serve-unavailable':
        from app import benchmark_presentation
        from app.portals import admin
        admin.load_benchmark_presentation = lambda dataset_path: benchmark_presentation.load_benchmark_presentation(
            dataset_path, report_path=PREVIEW / 'missing-final-report.json')
    uvicorn.run(app, host='127.0.0.1', port=8773 if mode == 'serve' else 8774)

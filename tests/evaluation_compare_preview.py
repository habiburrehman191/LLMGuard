"""Isolated synthetic stores; actual Compare endpoint, no detector/model stubs.

Browser QA submits only input-blocked requests and verifies the real disabled
bypass response. It does not enable bypass or call a model.
"""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
mode = sys.argv[1] if len(sys.argv) == 2 else ''
if mode not in ('serve','serve-unavailable'):
    raise ValueError('Choose serve or serve-unavailable.')
PREVIEW = ROOT/'reports/ui/evaluation-compare'/('preview' if mode=='serve' else 'preview-unavailable')
PREVIEW.mkdir(parents=True,exist_ok=True)
os.environ['LLMGUARD_DB_PATH'] = str(PREVIEW/'llmguard.db')
os.environ['LLMGUARD_TESTBED_DATABASE_URL'] = 'sqlite:///'+(PREVIEW/'auth.db').as_posix()
os.environ['FIREWALL_ACTIVE'] = 'true'
os.environ['REDTEAM_MODE'] = 'false'
os.environ['APP_ENV'] = 'local'

if __name__ == '__main__':
    from app.auth import seed_development_users
    from app.database import SessionLocal, init_database
    from app.db import init_db
    from app.main import app
    import uvicorn
    init_db()
    init_database()
    with SessionLocal() as db:
        seed_development_users(db)
    if mode=='serve-unavailable':
        from app import comparison_presentation
        from app.portals import admin
        admin.load_comparison_presentation = lambda dataset_path: comparison_presentation.load_comparison_presentation(
            dataset_path,report_path=PREVIEW/'missing-report.json')
    uvicorn.run(app,host='127.0.0.1',port=8775 if mode=='serve' else 8776)

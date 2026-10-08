"""Isolated flag-state previews; real GET/export/stub, no execution engine."""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
mode = sys.argv[1] if len(sys.argv)==2 else ''
if mode not in ('serve-disabled','serve-enabled'):
    raise ValueError('Choose serve-disabled or serve-enabled.')
enabled = mode=='serve-enabled'
PREVIEW = ROOT/'reports/ui/evaluation-redteam'/('preview-enabled' if enabled else 'preview-disabled')
PREVIEW.mkdir(parents=True,exist_ok=True)
os.environ['LLMGUARD_DB_PATH'] = str(PREVIEW/'llmguard.db')
os.environ['LLMGUARD_TESTBED_DATABASE_URL'] = 'sqlite:///'+(PREVIEW/'auth.db').as_posix()
os.environ['FIREWALL_ACTIVE'] = 'true'
os.environ['REDTEAM_MODE'] = 'true' if enabled else 'false'
os.environ['APP_ENV'] = 'local'

if __name__=='__main__':
    from sqlalchemy import select
    from app.auth import seed_development_users
    from app.database import SessionLocal,init_database
    from app.db import init_db
    from app.models import RedteamCase
    from app.main import app
    import uvicorn
    init_db(); init_database()
    with SessionLocal() as db:
        seed_development_users(db)
        if enabled and not db.scalar(select(RedteamCase)):
            for values in [
                {'case_id':'SYNTHETIC-CONTEXT-CASE','name':'Synthetic context injection definition',
                 'attack_type':'indirect_prompt_injection','severity':'high','expected_action':'quarantine'},
                {'case_id':'SYNTHETIC-'+('X'*170),'name':'Synthetic authorization boundary definition',
                 'attack_type':'synthetic_privilege_boundary_'+('Y'*80),'severity':'medium','expected_action':'block'},
            ]:
                db.add(RedteamCase(**values,prompt='SYNTHETIC-PRIVATE-PAYLOAD-NOT-FOR-DISPLAY',
                    expected_label='malicious',user_role='student',portal_scope='student',
                    metadata_json={'raw_context':'SYNTHETIC-PRIVATE-PAYLOAD-NOT-FOR-DISPLAY'}))
            db.commit()
    uvicorn.run(app,host='127.0.0.1',port=8778 if enabled else 8777)

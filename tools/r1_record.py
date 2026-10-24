"""Append R1 actions/results; never record credentials or request headers."""
import json,re,sys,fcntl
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
def record(action,result,status='completed'):
    lock_path=ROOT/'r1/.record.lock';lock_path.parent.mkdir(parents=True,exist_ok=True)
    with lock_path.open('a') as lock:
        fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
        return _record_locked(action,result,status)

def _record_locked(action,result,status='completed'):
    path=ROOT/'r1/events.jsonl';rows=path.read_text().splitlines() if path.exists() else []
    number=len(rows)+1;identifier=f'R1-{number:03}'
    # Defensive log redaction. Raw credentials are never arguments to this tool.
    clean=lambda s:re.sub(r'(?:AIza|AQ\.|ghp_|github_pat_|vcp_|sk-)[A-Za-z0-9_.-]{16,}','[REDACTED]',str(s))
    action,result=clean(action),clean(result)
    event={'id':identifier,'at':datetime.now(timezone.utc).isoformat(),'action':action,'result':result,'status':status}
    with path.open('a') as f:f.write(json.dumps(event)+'\n')
    with (ROOT/'R1.md').open('a') as f:f.write(f'\n### {identifier} — {action}\n**Action:** {action}\n**Result:** {result}\n**Status:** {status}.\n')
    print(identifier,status,action)
if __name__=='__main__':record(sys.argv[1],sys.argv[2],sys.argv[3] if len(sys.argv)>3 else 'completed')

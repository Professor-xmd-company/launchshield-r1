"""Build release cooldowns only from verified upstream responses, NEVER deployment time.

No credentials/network requests. Input artifacts must explicitly prove dispatch and an
upstream429/security checkpoint. Output contains absolute UTC deadlines, no target URLs.
"""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime,timezone

GROUPS={'website_auditor':'website_auditor','website_trigger':'website_auditor','website_read':'website_auditor','xlogs':'xlogs','vibe_check':'vibe_check','vibe_start':'vibe_check','vibe_poll':'vibe_check','mdn_observatory':'mdn_observatory','osv':'osv'}
def timestamp(value):
    if not isinstance(value,str):return None
    try:
        d=datetime.fromisoformat(value.replace('Z','+00:00'))
        return d.astimezone(timezone.utc) if d.tzinfo is not None else None
    except (ValueError,OverflowError):return None

def build_manifest(artifacts,existing=None,now=None):
    now=now or datetime.now(timezone.utc);result={}
    def add(name,value):
        name=GROUPS.get(name)
        if not name or not isinstance(value,dict):return
        until=timestamp(value.get('until'));observed=timestamp(value.get('observed_at'))
        source=value.get('source');status=value.get('http_status')
        valid=(source=='upstream_429' and status==429) or (source=='provider_security_checkpoint' and status in (200,403,429,503)) or (source=='operator_hold' and value.get('explicit') is True)
        if not valid or until is None or observed is None or until<=now or observed>until:return
        normalized={'until':until.isoformat(),'observed_at':observed.isoformat(),'source':source,'http_status':status}
        if source=='operator_hold':normalized['explicit']=True
        if name not in result or timestamp(result[name]['until'])<until:result[name]=normalized
    # Strings from historical deploy scripts are not verified upstream state.
    for key,value in (existing or {}).items():add(key,value)
    for data in artifacts:
        if not isinstance(data,dict) or data.get('mode') not in (None,'live'):continue
        details=data.get('diagnostics',{});reason=data.get('reason_code')
        if not isinstance(details,dict) or details.get('request_sent') is not True:continue
        if reason not in ('upstream_rate_limit','provider_security_checkpoint'):continue
        add(data.get('source'),{'until':data.get('retry_at'),'observed_at':details.get('observed_at'),'source':'upstream_429' if reason=='upstream_rate_limit' else reason,'http_status':data.get('http_status')})
    return result

def from_directory(directory,existing=None,now=None):
    artifacts=[]
    for p in Path(directory).glob('*.json'):
        try:
            data=json.loads(p.read_text())
            if isinstance(data,dict) and 'reason_code' in data:artifacts.append(data)
        except (ValueError,OSError):continue
    return build_manifest(artifacts,existing,now)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('evidence_directory');args=parser.parse_args()
    print(json.dumps(from_directory(args.evidence_directory),indent=2))

"""File-backed dispatch accounting: provider penalties, budgets and target guards are separate.

A permit reserves capacity but is NOT a sent request. Only confirmed transport dispatch
commits sent timestamps. Local rejection never moves a retry deadline or sent counter.
"""
from __future__ import annotations
import math,secrets,time
from datetime import datetime,timezone
from urllib.parse import urlsplit
from .persistence import hash_token

RULES={'xlogs':(60,3600),'vibe_start':(5,60),'vibe_poll':(100,60),'mdn_observatory':(20,60),'website_trigger':(10,3600),'website_read':(120,60),'osv':(60,60)}
FAMILIES={'website_trigger':'website_auditor','website_read':'website_auditor','vibe_start':'vibe_check','vibe_poll':'vibe_check'}
def family(name):return FAMILIES.get(name,name)
def iso(epoch):
    try:return datetime.fromtimestamp(float(epoch),timezone.utc).isoformat()
    except (ValueError,OverflowError,TypeError,OSError):return None

def epoch(value):
    if isinstance(value,(int,float)) and not isinstance(value,bool):
        return float(value) if math.isfinite(value) and value>=0 else None
    if not isinstance(value,str):return None
    try:
        stamp=datetime.fromisoformat(value.replace('Z','+00:00'))
        if stamp.tzinfo is None:return None # No implicit machine-local timezone.
        result=stamp.timestamp();return result if math.isfinite(result) and result>=0 else None
    except (ValueError,OverflowError,OSError):return None

class GateClosed(Exception):
    def __init__(self,until,reason,scope,name):
        self.until,self.reason,self.scope,self.name=until,reason,scope,name
        super().__init__(reason)
class QuotaStateError(Exception):pass

class QuotaLedger:
    def __init__(self,settings,store,clock=None):
        self.settings,self.store,self.clock=settings,store,clock or time.time
        self.path=store.root/'provider-quotas.json';self.warnings=[]
    def _load(self):
        try:data=self.store.read(self.path,{})
        except (ValueError,TypeError):raise QuotaStateError('Unreadable quota file; not silently reset.') from None
        if not isinstance(data,dict):raise QuotaStateError('Invalid quota file shape; not silently reset.')
        for key in ('_pending','_penalties','_reports'):
            if key in data and not isinstance(data[key],dict):raise QuotaStateError('Invalid quota metadata; not silently reset.')
        previous=epoch(data.get('_written_at'))
        if previous is not None and self.clock()+5<previous:raise QuotaStateError('Server clock moved backwards; quota timestamps were not rewritten.')
        return data
    def _write(self,data):
        data['_version']=2;data['_written_at']=self.clock();self.store.write(self.path,data)
    def _interval(self,name):
        if name=='website_trigger':return 3600.0 # Deliberate per-host anti-amplification interval.
        if name=='mdn_observatory':return 60.0
        if name=='xlogs':return max(0,float(getattr(self.settings,'xlogs_target_interval',0)))
        return 0.0
    def target_key(self,name,origin):
        host=urlsplit(origin).hostname or origin
        identity=host if name in ('website_trigger','website_read','mdn_observatory') else origin
        return name+'|'+hash_token(identity) if identity else ''
    def _last_target(self,data,name,origin):
        # Read old host/origin keys without converting a local skip to a new dispatch.
        host=urlsplit(origin).hostname or origin;new=self.target_key(name,origin)
        keys=(new,name+'|'+host,name+'|'+origin,name+'|http://'+host,name+'|https://'+host)
        stamps=[epoch(data.get(key)) for key in keys if key]
        return max((x for x in stamps if x is not None),default=0)
    def _configured(self,name):
        configured=getattr(self.settings,'provider_cooldowns',{})
        if not isinstance(configured,dict):return []
        result=[]
        aliases=('website_trigger','website_read') if family(name)=='website_auditor' else ()
        for key in dict.fromkeys((name,family(name),*aliases)):
            value=configured.get(key)
            if not value:continue
            if isinstance(value,str):
                # Historical deploy scripts fabricated a global hour for this key.
                # Genuine old persisted429 penalties are handled separately below.
                if key=='website_trigger':
                    note='Ignored legacy unscoped website_trigger deploy hold; no dispatch/upstream provenance.'
                    if note not in self.warnings:self.warnings.append(note)
                    continue
                until=epoch(value)
                if until is not None:result.append((until,'legacy_explicit_operator_hold'))
                elif 'Invalid legacy cooldown ignored.' not in self.warnings:self.warnings.append('Invalid legacy cooldown ignored.')
            elif isinstance(value,dict):
                until=epoch(value.get('until'));observed=epoch(value.get('observed_at'));source=value.get('source')
                if until is None or observed is None or until<observed:continue
                if source in ('upstream_429','provider_security_checkpoint') and value.get('http_status') in (200,403,429,503):result.append((until,source))
                elif source=='operator_hold' and value.get('explicit') is True:result.append((until,source))
        return result
    def _deadline(self,data,name,origin,now,include_pending=True):
        reasons=[];group=family(name)
        aliases=('website_trigger','website_read') if group=='website_auditor' else ()
        for key in dict.fromkeys((name,group,*aliases)):
            row=data.get(key,{})
            if not isinstance(row,dict):raise QuotaStateError('Invalid provider quota row.')
            until=epoch(row.get('blocked_until'))
            if until is not None:reasons.append((until,'upstream_cooldown','provider'))
            penalty=data.get('_penalties',{}).get(key,{})
            if isinstance(penalty,dict) and epoch(penalty.get('until')) is not None:reasons.append((epoch(penalty['until']),penalty.get('source','upstream_cooldown'),'provider'))
        reasons.extend((until,why,'provider') for until,why in self._configured(name))
        row=data.get(name,{})
        attempts=row.get('attempts',[]);uncertain=row.get('uncertain_attempts',[])
        if not isinstance(attempts,list) or not isinstance(uncertain,list):raise QuotaStateError('Invalid sent-request timestamps.')
        count,window=RULES.get(name,(60,60))
        valid=sorted(x for raw in attempts+uncertain if (x:=epoch(raw)) is not None and now-window<x<=now+5)
        pending=[p for p in data.get('_pending',{}).values() if isinstance(p,dict) and p.get('quota')==name and (epoch(p.get('expires_at')) or 0)>now]
        if len(valid)>=count:reasons.append((valid[len(valid)-count]+window,'local_provider_budget','provider'))
        elif include_pending and len(valid)+len(pending)>=count:reasons.append((min(epoch(p['expires_at']) for p in pending),'request_in_flight','provider'))
        interval=self._interval(name);last=self._last_target(data,name,origin)
        if interval and last:
            if last>now+5:raise QuotaStateError('Target dispatch timestamp is in the future; not converted into a new cooldown.')
            reasons.append((last+interval,'target_interval','target'))
        key=self.target_key(name,origin)
        if key and include_pending:
            for p in pending:
                if p.get('target_key')==key:reasons.append((epoch(p['expires_at']),'request_in_flight','target'))
        return max((x for x in reasons if x[0]>now),default=(0,None,None))
    def peek(self,name,origin=''):
        with self.store.lock:
            now=self.clock();data=self._load();until,reason,scope=self._deadline(data,name,origin,now)
            row=data.get(name,{});count,window=RULES.get(name,(60,60))
            valid=[x for raw in row.get('attempts',[]) if (x:=epoch(raw)) is not None and now-window<x<=now+5]
            return {'quota':name,'scope':scope,'reason':reason,'next_allowed_at':iso(until) if until else None,'eligible':until<=now,'sent_in_window':len(valid),'sent_total':row.get('sent_total',len(row.get('attempts',[]))),'limit':count,'window_seconds':window,'last_dispatched_at':iso(epoch(row.get('last_dispatched_at')) or max(valid,default=0)) if valid or row.get('last_dispatched_at') else None}
    def acquire(self,name,origin=''):
        with self.store.lock:
            data=self._load();now=self.clock();until,reason,scope=self._deadline(data,name,origin,now)
            if until>now:raise GateClosed(until,reason,scope,name)
            pending={k:p for k,p in data.get('_pending',{}).items() if isinstance(p,dict) and (epoch(p.get('expires_at')) or 0)>now}
            token=secrets.token_hex(12);pending[token]={'quota':name,'target_key':self.target_key(name,origin),'expires_at':now+max(60,float(self.settings.provider_timeout)+15)}
            data['_pending']=pending;self._write(data)
            return {'token':token,'quota':name,'origin':origin,'committed':False}
    def dispatched(self,permit,at=None,confirmed=True):
        if not permit or permit.get('committed'):return
        with self.store.lock:
            data=self._load();pending=data.get('_pending',{});p=pending.get(permit['token'])
            if not p:raise QuotaStateError('Dispatch permit expired or was lost.')
            now=self.clock();stamp=now if at is None else float(at)
            if not math.isfinite(stamp) or stamp>now+5:raise QuotaStateError('Invalid dispatch timestamp.')
            name=permit['quota'];row=data.setdefault(name,{'attempts':[]});_,window=RULES.get(name,(60,60))
            row['attempts']=[x for raw in row.get('attempts',[]) if (x:=epoch(raw)) is not None and now-window<x<=now+5]
            if confirmed:
                row['attempts'].append(stamp);row['sent_total']=row.get('sent_total',len(row['attempts'])-1)+1;row['last_dispatched_at']=stamp
            else:
                values=[x for raw in row.get('uncertain_attempts',[]) if (x:=epoch(raw)) is not None and now-window<x<=now+5]
                row['uncertain_attempts']=values+[stamp];row['last_uncertain_at']=stamp
            if p.get('target_key') and self._interval(name):data[p['target_key']]=stamp
            permit['committed']=True;self._write(data)
    def release(self,permit):
        if not permit:return
        with self.store.lock:
            data=self._load();pending=data.get('_pending',{})
            if permit['token'] in pending:pending.pop(permit['token']);self._write(data)
    def block(self,name,seconds,source='upstream_429',http_status=429):
        now=self.clock();until=now+max(1,float(seconds))
        with self.store.lock:
            data=self._load();key=family(name);penalties=data.setdefault('_penalties',{});old=penalties.get(key,{})
            if (epoch(old.get('until')) or 0)>until:until=epoch(old['until'])
            penalties[key]={'until':until,'observed_at':now,'source':source,'http_status':http_status}
            # Keep the old row readable by older diagnostic clients; never set this on a skip.
            row=data.setdefault(name,{'attempts':[]});row['blocked_until']=max(epoch(row.get('blocked_until')) or 0,until)
            self._write(data)
        return iso(until)
    def report_received(self,name,origin):
        with self.store.lock:
            data=self._load();reports=data.setdefault('_reports',{});row=reports.setdefault(family(name),{'received_total':0})
            row.update(received_total=row['received_total']+1,last_received_at=self.clock())
            key='report|'+self.target_key(family(name),origin);data[key]=self.clock();self._write(data)

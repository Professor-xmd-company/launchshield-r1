"""Per-provider lifecycle trace. Only allowlisted metadata; never headers, bodies or secrets."""
from __future__ import annotations
import time
from contextvars import ContextVar
from urllib.parse import urlsplit,urlunsplit
from .quotas import iso

CURRENT_TRACE=ContextVar('launchshield_dispatch_trace',default=None)

def endpoint(url):
    u=urlsplit(str(url));return urlunsplit((u.scheme,u.netloc,u.path,'',''))

class DispatchTrace:
    def __init__(self,provider,progress,clock=None):
        self.provider,self.progress,self.clock=provider,progress,clock or time.time
        self.events=[];self.requests=[];self.sent=0;self.scan_sent=0;self.uncertain=False;self.report=False;self.cache_hit=False;self.phase='queued';self.next_allowed=None;self.cooldown=None
    def summary(self):
        return {'lifecycle_state':self.phase,'request_sent':True if self.sent else (None if self.uncertain else False),'scan_request_sent':True if self.scan_sent else (None if self.uncertain else False),'requests_sent':self.sent,'scan_requests_sent':self.scan_sent,'report_received':self.report,'local_cache_hit':self.cache_hit,'next_allowed_at':self.next_allowed,'cooldown':self.cooldown,'last_dispatched_at':next((r.get('dispatched_at') for r in reversed(self.requests) if r.get('request_sent')),None),'requests':self.requests[-16:],'events':self.events[-30:]}
    async def emit(self,state,**fields):
        self.phase=state;item={'at':iso(self.clock()),'state':state,**fields};self.events.append(item)
        if self.progress:
            status=state if state in ('request_sent','polling','skipped_cooldown') else 'running'
            await self.progress(status,{'request_sent':'HTTP request dispatched.','polling':'Polling the documented report/status endpoint.','skipped_cooldown':'Scan dispatch skipped by an active, unchanged cooldown.'}.get(state,'Validating provider evidence.'),dispatch=self.summary(),lifecycle_state=state)
    async def begin(self,method,url,operation):
        row={'method':method.upper(),'endpoint':endpoint(url),'operation':operation,'started_at':iso(self.clock()),'request_sent':False,'http_status':None}
        self.requests.append(row)
        if operation in ('poll_report','poll_status','fetch_result'):await self.emit('polling',operation=operation,method=row['method'],endpoint=row['endpoint'])
        return row
    async def dispatched(self,row,at,scan=False,confirmed=True):
        if row.get('dispatched_at') or row.get('dispatch_uncertain'):return
        row.update(request_sent=True if confirmed else None,dispatched_at=iso(at) if confirmed else None)
        if confirmed:self.sent+=1;self.scan_sent+=int(scan)
        else:self.uncertain=True;row['dispatch_uncertain']=True
        await self.emit('request_sent' if confirmed else 'dispatch_uncertain',method=row['method'],endpoint=row['endpoint'],operation=row['operation'],dispatched_at=row.get('dispatched_at'),request_sent=row['request_sent'])
    async def response(self,row,status,category,elapsed_ms,receipt=None):
        row.update(http_status=status,response_category=category,response_at=iso(self.clock()),elapsed_ms=round(max(0,elapsed_ms),2))
        if receipt:
            for key in ('content_type','body_sha256','provider_code','provider_error','provider_request_id','security_checkpoint','retry-after'):
                if key in receipt:row[key]=receipt[key]
        self.events.append({'at':iso(self.clock()),'state':'response_received' if status is not None else 'failed','operation':row['operation'],'http_status':status,'category':category,'elapsed_ms':row['elapsed_ms']})
        if self.progress:
            phase='polling' if row['operation'] in ('poll_report','poll_status','fetch_result') else 'request_sent'
            self.phase=phase
            await self.progress(phase,'HTTP response recorded: '+category+'.',dispatch=self.summary(),lifecycle_state=phase)
    async def skipped(self,error):
        self.next_allowed=error.retry_at;self.cooldown=error.diagnostics.get('cooldown')
        if self.requests:self.requests[-1].update(response_category='skipped_cooldown',request_sent=False,http_status=None)
        await self.emit('skipped_cooldown',reason_code=error.code,next_allowed_at=error.retry_at,request_sent=False)
    async def complete(self,cache_hit=False):
        self.report=True;self.cache_hit=cache_hit
        await self.emit('completed',report_received=True,local_cache_hit=cache_hit)
    async def failed(self,category,retry_at=None):
        if self.phase=='skipped_cooldown':return
        self.next_allowed=retry_at
        await self.emit('failed',category=category,next_allowed_at=retry_at,report_received=False)

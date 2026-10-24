from __future__ import annotations
import asyncio,json,time,random,re,hashlib,math
from urllib.parse import quote
from datetime import datetime,timezone
from email.utils import parsedate_to_datetime
import httpx
from .models import utcnow
from .fixtures import native_fixture
from .diagnostics import response_receipt,security_checkpoint,vibe_modules
from .quotas import QuotaLedger,GateClosed,QuotaStateError,RULES,iso as retry_iso
from .dispatch import CURRENT_TRACE,DispatchTrace,endpoint as safe_endpoint
from .normalize import normalize,SchemaChanged

class ProviderFailure(Exception):
    def __init__(self,message,state='failed',http_status=None,retry_at=None,code='provider_error',diagnostics=None):
        self.message,self.state,self.http_status,self.retry_at=message,state,http_status,retry_at
        self.code,self.diagnostics=code,diagnostics or {}
        super().__init__(message)

CACHE_TTL={'website_auditor':3600,'xlogs':900,'vibe_check':300,'mdn_observatory':60,'osv':3600}
def retry_seconds(raw,quota,now=None):
    fallback=RULES.get(quota,(60,60))[1]
    try:seconds=float(raw)
    except (ValueError,TypeError):
        try:
            value=parsedate_to_datetime(raw)
            if value.tzinfo is None:value=value.replace(tzinfo=timezone.utc)
            seconds=value.timestamp()-(time.time() if now is None else now)
        except Exception:seconds=fallback
    return max(1,seconds) if math.isfinite(seconds) else fallback

class ProviderEngine:
    def __init__(self,settings,store,client_factory=None,clock=None,sleeper=None):
        self.settings,self.store,self.client_factory=settings,store,client_factory
        self.clock=clock or time.time;self.sleep=sleeper or asyncio.sleep;self.quotas=QuotaLedger(settings,store,self.clock)
    def reserve(self,name,origin=''):
        """Acquire an unsent permit; committing sent accounting is a separate operation."""
        try:return self.quotas.acquire(name,origin)
        except GateClosed as e:
            cooldown={'scope':e.scope,'reason':e.reason,'quota':name,'until':retry_iso(e.until)}
            raise ProviderFailure('Request was not dispatched: '+e.reason+'.','skipped_cooldown',retry_at=retry_iso(e.until),code='local_cooldown',diagnostics={'request_sent':False,'quota':name,'cooldown':cooldown}) from None
        except QuotaStateError as e:raise ProviderFailure(str(e),'failed',code='quota_state_invalid',diagnostics={'request_sent':False}) from None
    def block(self,name,seconds,source='upstream_429',http_status=429):return self.quotas.block(name,seconds,source,http_status)
    async def request(self,method,url,quota=None,origin='',operation=None,allow_missing=False,**kwargs):
        operation=operation or ('scan_start' if method.upper()=='POST' else 'read_result')
        attempts=2 if method.upper()=='GET' and operation!='trigger_scan' else 1
        for attempt in range(attempts):
            try:return await self._request_once(method,url,quota,origin,operation=operation,allow_missing=allow_missing,**kwargs)
            except ProviderFailure as error:
                transient=error.state not in ('blocked','skipped_cooldown') and (error.state in ('unavailable','timed_out') or (error.http_status is not None and error.http_status>=500))
                if attempt+1>=attempts or not transient:raise
                await self.sleep(max(2.5 if url.startswith('https://vibecheckscan.com/') else 1,2**attempt)+random.uniform(0,.25))
    def response_error(self,method,url,status,headers,content,quota):
        receipt=response_receipt(method,url,status,headers,content);checkpoint=security_checkpoint(headers,content)
        if checkpoint or status==429:
            source='provider_security_checkpoint' if checkpoint else 'upstream_429'
            seconds=retry_seconds(headers.get('Retry-After'),quota,self.clock())
            until=self.block(quota,seconds,source,status) if quota else retry_iso(self.clock()+seconds)
            if checkpoint:return ProviderFailure('The provider blocked automated access at a security checkpoint; no report was returned.','blocked',status,until,code='provider_security_checkpoint',diagnostics=receipt)
            return ProviderFailure('Provider HTTP429; actual Retry-After or its documented conservative window is preserved.','rate_limited',status,until,code='upstream_rate_limit',diagnostics=receipt)
        code='provider_error' if status>=500 else 'upstream_http_error'
        if status in (200,400,404,422):
            marker=str(receipt.get('provider_code',''))+' '+str(receipt.get('provider_error',''))
            code='invalid_target' if re.search(r'(?i)(invalid[_ -]?(?:url|target|domain)|private[_ -]?(?:ip|address|url)|public urls? only|url must be public|url (?:is )?required)',marker) else 'invalid_request'
        return ProviderFailure('Provider returned HTTP '+str(status)+'. No valid report was inferred.',http_status=status,code=code,diagnostics=receipt)
    async def _request_once(self,method,url,quota=None,origin='',operation=None,allow_missing=False,expect_json=True,timeout=None,**kwargs):
        allowed=('https://websiteauditor.net/','https://xlogs.com/','https://vibecheckscan.com/','https://observatory-api.mdn.mozilla.net/','https://api.osv.dev/')
        if not url.startswith(allowed):raise ProviderFailure('Unapproved provider endpoint.',code='unapproved_endpoint',diagnostics={'request_sent':False})
        operation=operation or ('scan_start' if method.upper()=='POST' else 'read_result')
        trace=CURRENT_TRACE.get() or DispatchTrace(quota or 'provider',None,self.clock)
        row=await trace.begin(method,url,operation);permit=None;response=None;headers_started=False;started=self.clock();timer=time.monotonic()
        scan=operation in ('scan_start','trigger_scan')
        async def committed(confirmed=True):
            if row.get('dispatched_at') or row.get('dispatch_uncertain'):return
            sent_at=self.clock()
            if permit:self.quotas.dispatched(permit,at=sent_at,confirmed=confirmed)
            await trace.dispatched(row,sent_at,scan=scan,confirmed=confirmed)
        async def transport_event(event,info):
            nonlocal headers_started
            # Do not log info: it may contain header values or transport objects.
            if event.endswith('send_request_headers.started'):headers_started=True
            if event.endswith('send_request_headers.complete'):await committed()
        try:
            client=self.client_factory() if self.client_factory else httpx.AsyncClient(timeout=timeout or httpx.Timeout(45,connect=12),follow_redirects=False,trust_env=False)
            async with client:
                request=client.build_request(method,url,headers={'User-Agent':'LaunchShield-R1/1.0 (owner-authorized passive assessment)'},**kwargs)
                request.extensions['trace']=transport_event
                if quota:permit=self.reserve(quota,origin)
                started=self.clock();timer=time.monotonic()
                response=await client.send(request,stream=True)
                # A real response also confirms dispatch for injected/non-httpcore transports.
                await committed()
                body=b''
                async for chunk in response.aiter_bytes():
                    body+=chunk
                    if len(body)>self.settings.maximum_response:
                        raise ProviderFailure('Provider response exceeded the size limit.',http_status=response.status_code,code='response_size_limit')
                status=response.status_code;receipt=response_receipt(method,url,status,response.headers,body)
                if security_checkpoint(response.headers,body) or status==429:raise self.response_error(method,url,status,response.headers,body,quota)
                if status==404 and allow_missing:
                    await trace.response(row,status,'cache_miss',(time.monotonic()-timer)*1000,receipt);return status,None
                if status not in ((200,202) if not expect_json else (200,)):raise self.response_error(method,url,status,response.headers,body,quota)
                if not expect_json:
                    receipt['scan_acceptance_confirmed']=False
                    await trace.response(row,status,'trigger_response_not_report',(time.monotonic()-timer)*1000,receipt);return status,receipt
                try:data=json.loads(body,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON numeric constant')))
                except (ValueError,UnicodeDecodeError):raise ProviderFailure('Provider returned malformed/non-JSON data.',http_status=status,code='invalid_json',diagnostics=receipt) from None
                if isinstance(data,dict) and data.get('ok') is False and data.get('error'):
                    error=self.response_error(method,url,status,response.headers,body,quota)
                    if error.code=='upstream_http_error':error.code='provider_api_error'
                    raise error
                await trace.response(row,status,'json_received',(time.monotonic()-timer)*1000,receipt);return status,data
        except ProviderFailure as error:
            if error.state=='skipped_cooldown':await trace.skipped(error)
            else:await trace.response(row,error.http_status,error.code,(time.monotonic()-timer)*1000,error.diagnostics)
            error.diagnostics={**error.diagnostics,'request_sent':row.get('request_sent',False),'method':method.upper(),'endpoint':safe_endpoint(url),'elapsed_ms':round((time.monotonic()-timer)*1000,2)}
            raise
        except httpx.TimeoutException as error:
            if isinstance(error,httpx.ReadTimeout) and not row.get('dispatched_at'):await committed()
            elif headers_started and not row.get('dispatched_at'):await committed(False)
            code='connect_timeout' if isinstance(error,httpx.ConnectTimeout) else ('pool_timeout' if isinstance(error,httpx.PoolTimeout) else 'network_timeout')
            await trace.response(row,None,code,(time.monotonic()-timer)*1000)
            raise ProviderFailure('Provider transport timed out. A scan-start request was not blindly retried.','timed_out',code=code,diagnostics={'request_sent':row.get('request_sent',False),'method':method.upper(),'endpoint':safe_endpoint(url),'elapsed_ms':round((time.monotonic()-timer)*1000,2)}) from None
        except httpx.HTTPError as error:
            if headers_started and not row.get('dispatched_at'):await committed(False)
            await trace.response(row,None,'network_error',(time.monotonic()-timer)*1000)
            raise ProviderFailure('Provider network transport failed.','unavailable',code='network_error',diagnostics={'request_sent':row.get('request_sent',False),'method':method.upper(),'endpoint':safe_endpoint(url),'error_type':type(error).__name__}) from None
        except asyncio.CancelledError:
            if headers_started and not row.get('dispatched_at'):await committed(False)
            await trace.response(row,None,'cancelled_or_deadline',(time.monotonic()-timer)*1000)
            await trace.failed('cancelled_or_deadline');raise
        except (ValueError,RuntimeError,QuotaStateError) as error:
            raise ProviderFailure('HTTP dispatch could not be prepared safely.','failed',code='dispatch_preparation_failed',diagnostics={'request_sent':row.get('request_sent',False),'method':method.upper(),'endpoint':safe_endpoint(url),'error_type':type(error).__name__}) from None
        finally:
            if response is not None:await response.aclose()
            if permit:self.quotas.release(permit)
    async def trigger_auditor(self,host,origin):
        _,receipt=await self._request_once('GET','https://websiteauditor.net/report/'+quote(host,safe=''),'website_trigger',origin,operation='trigger_scan',expect_json=False,timeout=20)
        return receipt
    async def run(self,name,target,mode,scenario,progress,packages=None):
        trace=DispatchTrace(name,progress,self.clock);token=CURRENT_TRACE.set(trace);result=None
        try:
            result=await self._run(name,target,mode,scenario,progress,packages)
            if result.get('native') is not None:
                if mode=='live':
                    quota={'website_auditor':'website_trigger','vibe_check':'vibe_start'}.get(name,name)
                    try:trace.next_allowed=self.quotas.peek(quota,target.origin)['next_allowed_at']
                    except QuotaStateError:
                        if not result.get('local_cached'):raise
                        trace.events.append({'at':retry_iso(self.clock()),'state':'budget_state_unavailable','category':'invalid_state_cached_report_preserved'})
                normalize(name,result['native'],target.origin) # Valid report, not merely HTTP200.
                await trace.complete(cache_hit=result.get('local_cached',False))
                if mode=='live' and not result.get('local_cached'):self.quotas.report_received(name,target.origin)
            else:trace.phase='completed' # Not-applicable is explicit, report_received stays false.
            result['dispatch']=trace.summary();result['lifecycle_state']=trace.phase
            if self.quotas.warnings:result['dispatch']['state_warnings']=list(self.quotas.warnings)
            return result
        except ProviderFailure as error:
            if error.retry_at is None and name in ('website_auditor','xlogs'):
                quota='website_trigger' if name=='website_auditor' else name
                try:error.retry_at=self.quotas.peek(quota,target.origin)['next_allowed_at']
                except QuotaStateError:pass
            await trace.failed(error.code,error.retry_at);error.diagnostics['dispatch']=trace.summary()
            raise
        except SchemaChanged as error:
            await trace.failed('invalid_report_schema');error.native=result.get('native') if result else None;error.dispatch=trace.summary();raise
        finally:CURRENT_TRACE.reset(token)
    async def _run(self,name,target,mode,scenario,progress,packages=None):
        requested=utcnow();origin=target.origin
        if name=='osv' and not packages:return {'state':'skipped_not_applicable','message':'No reliable package ecosystem/name/exact-version evidence. This is not a clean vulnerability result.','requested_at':requested,'native':None}
        if mode=='mock':
            await self.sleep(self.settings.mock_delay)
            if scenario=='partial_failure' and name=='xlogs':raise ProviderFailure('MOCK: upstream unavailable.','unavailable',503)
            if scenario=='rate_limited' and name=='xlogs':raise ProviderFailure('MOCK: provider quota reached.','rate_limited',429,datetime.fromtimestamp(time.time()+600,timezone.utc).isoformat())
            if scenario=='timeout' and name=='vibe_check':raise ProviderFailure('MOCK: bounded timeout.','timed_out')
            native=native_fixture(name,origin,scenario)
            return self.result(name,native,requested,mode)
        cache_origin=origin
        if name=='osv':cache_origin+='|'+hashlib.sha256(json.dumps(packages,sort_keys=True).encode()).hexdigest()
        cached=self.store.cached(name,cache_origin,CACHE_TTL[name])
        if cached:
            try:
                if not isinstance(cached,dict) or not isinstance(cached.get('native'),dict):raise SchemaChanged('Invalid cached native report.')
                normalize(name,cached['native'],origin)
            except SchemaChanged:
                CURRENT_TRACE.get().events.append({'at':retry_iso(self.clock()),'state':'cache_rejected','category':'invalid_report_schema'})
            else:
                cached.update(local_cached=True,requested_at=requested)
                if cached.get('state')=='completed':cached['state']='cached'
                return cached
        if name=='website_auditor':
            endpoint='https://websiteauditor.net/api/public/audit/'+quote(target.host,safe='')
            status,native=await self.request('GET',endpoint,'website_read',origin,operation='read_cache',allow_missing=True)
            if status==404:
                await progress('running','No cached report; requesting the documented report route once. Scan acceptance is not yet confirmed.')
                try:trigger=await self.trigger_auditor(target.host,origin)
                except ProviderFailure as error:
                    error.diagnostics.update(cache_http_status=404,scan_acceptance_confirmed=False)
                    raise
                polls=0
                for delay in (4,8,12,16,20):
                    await CURRENT_TRACE.get().emit('polling',operation='poll_report',next_poll_in_seconds=delay)
                    await self.sleep(delay);status,native=await self.request('GET',endpoint,'website_read',origin,operation='poll_report',allow_missing=True);polls+=1
                    if status==200:break
                if status!=200:raise ProviderFailure('The provider API still has no cached report after its documented report-page request. A completed scan could not be confirmed.','unavailable',status,code='report_not_generated',diagnostics={'request_sent':True,'cache_http_status':status,'cache_reads':polls+1,'poll_wait_seconds':60,'trigger':trigger,'scan_acceptance_confirmed':False})
        elif name=='xlogs':
            status,native=await self.request('POST','https://xlogs.com/api/v1/scan','xlogs',origin,json={'url':origin})
        elif name=='vibe_check':
            status,start=await self.request('POST','https://vibecheckscan.com/api/scan/start','vibe_start',origin,json={'url':origin})
            scanid=start.get('scanId') if isinstance(start,dict) else None
            if not isinstance(scanid,str) or not re.fullmatch(r'[A-Fa-f0-9]{32}',scanid):raise ProviderFailure('Vibe Check did not return a valid scanId.')
            await progress('running','Remote scan queued.' if start.get('queued') else 'Remote scan started.',external_scan_id=scanid)
            while True:
                await self.sleep(max(2.5,self.settings.poll_interval))
                _,state=await self.request('GET','https://vibecheckscan.com/api/scan/status','vibe_poll',origin,operation='poll_status',params={'id':scanid,'format':'agent'})
                if not isinstance(state,dict):raise ProviderFailure('Invalid Vibe Check status response.')
                if state.get('status')=='error':raise ProviderFailure('Vibe Check returned a terminal provider error.')
                await progress('running','Vibe Check modules: '+json.dumps(state.get('modules',{}))[:700],external_scan_id=scanid)
                if state.get('status')=='completed':
                    native=state.get('result')
                    # format=agent may inline a summary envelope, not full findings.
                    # A summary/grade is never treated as a complete evidence report.
                    if not isinstance(native,dict) or not isinstance(native.get('modules'),dict):
                        _,native=await self.request('GET','https://vibecheckscan.com/api/scan/result','vibe_poll',origin,operation='fetch_result',params={'id':scanid,'format':'full'})
                    break
        elif name=='mdn_observatory':
            status,native=await self.request('POST','https://observatory-api.mdn.mozilla.net/api/v2/scan','mdn_observatory',origin,params={'host':target.host})
        elif name=='osv':
            queries=[p['query'] for p in packages];_,response=await self.request('POST','https://api.osv.dev/v1/querybatch','osv',origin,operation='query_advisories',json={'queries':queries})
            if not isinstance(response,dict) or not isinstance(response.get('results'),list):raise ProviderFailure('OSV batch response schema changed.')
            native={'queries':queries,'results':response['results'],'package_sources':[p['source'] for p in packages]}
        else:raise ProviderFailure('Unsupported provider.')
        if not isinstance(native,dict):raise ProviderFailure('Provider response is not a JSON object.',http_status=status,code='invalid_report_schema')
        result=self.result(name,native,requested,mode)
        if name=='vibe_check':result['external_scan_id']=scanid
        # Cache only after schema validation in the harness, not here.
        result['_cache_origin']=cache_origin
        return result
    def result(self,name,native,requested,mode):
        result={'state':'completed','native':native,'http_status':200,'requested_at':requested,'received_at':utcnow(),'message':'MOCK fixture; no external check ran.' if mode=='mock' else 'Provider response received.','scanned_at':native.get('scannedAt',native.get('scanned_at'))}
        if name=='vibe_check':
            result['scanned_at']=native.get('timestamp',result['scanned_at'])
            summaries=vibe_modules(native);result['module_coverage']=summaries
            warnings=[item['module']+': '+'; '.join(item['notes']) for item in summaries if item['state']=='partial']
            if warnings:
                result['coverage_warnings']=warnings
                result['message']='Provider completed with partial/unknown module coverage: '+'; '.join(warnings)
        if name=='website_auditor' and isinstance(native.get('report'),dict):
            result['cache_source']='provider';stamp=native['report'].get('fetchedAt',native.get('cachedAt'));result['cached_at']=native.get('cachedAt');result['scanned_at']=stamp
            try:
                if isinstance(stamp,(int,float)):epoch=stamp/1000 if stamp>1e12 else stamp
                elif isinstance(stamp,str):epoch=datetime.fromisoformat(stamp.replace('Z','+00:00')).replace(tzinfo=timezone.utc).timestamp() if datetime.fromisoformat(stamp.replace('Z','+00:00')).tzinfo is None else datetime.fromisoformat(stamp.replace('Z','+00:00')).timestamp()
                else:epoch=None
            except (ValueError,OverflowError):epoch=None
            if epoch is not None and time.time()-epoch>86400:result.update(state='stale_result',message='Provider returned a report older than 24 hours; not a fresh scan.')
            else:result['state']='cached'
            if epoch is None:result.update(freshness='unknown',message='Cached report received, but its original scan age was not supplied/recognized; freshness is unknown.')
        return result

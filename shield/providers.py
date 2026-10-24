from __future__ import annotations
import asyncio,json,time,random,re,hashlib,math
from urllib.parse import quote,urlsplit
from datetime import datetime,timezone
from email.utils import parsedate_to_datetime
import httpx
from .models import utcnow
from .fixtures import native_fixture
from .diagnostics import response_receipt,security_checkpoint,vibe_modules

class ProviderFailure(Exception):
    def __init__(self,message,state='failed',http_status=None,retry_at=None,code='provider_error',diagnostics=None):
        self.message,self.state,self.http_status,self.retry_at=message,state,http_status,retry_at
        self.code,self.diagnostics=code,diagnostics or {}
        super().__init__(message)

RULES={'xlogs':(60,3600),'vibe_start':(5,60),'vibe_poll':(100,60),'mdn_observatory':(20,60),'website_trigger':(10,3600),'osv':(60,60)}
CACHE_TTL={'website_auditor':3600,'xlogs':900,'vibe_check':300,'mdn_observatory':60,'osv':3600}
def retry_iso(epoch):
    try:return datetime.fromtimestamp(epoch,timezone.utc).isoformat()
    except (ValueError,OverflowError,OSError):return None

def retry_seconds(raw,quota):
    fallback=RULES.get(quota,(60,60))[1]
    try:seconds=float(raw)
    except (ValueError,TypeError):
        try:seconds=parsedate_to_datetime(raw).timestamp()-time.time()
        except Exception:seconds=fallback
    return max(1,seconds) if math.isfinite(seconds) else fallback

class ProviderEngine:
    def __init__(self,settings,store,client_factory=None):self.settings,self.store,self.client_factory=settings,store,client_factory
    def reserve(self,name,origin=''):
        now=time.time();path=self.store.root/'provider-quotas.json'
        with self.store.lock:
            saved=self.store.read(path,{})
            count,window=RULES.get(name,(60,60));row=saved.get(name,{'attempts':[],'blocked_until':0});attempts=[t for t in row['attempts'] if now-t<window]
            retry=float(row.get('blocked_until',0))
            configured=getattr(self.settings,'provider_cooldowns',{}).get(name)
            if configured:
                try:
                    stamp=datetime.fromisoformat(str(configured).replace('Z','+00:00'))
                    if stamp.tzinfo is None:stamp=stamp.replace(tzinfo=timezone.utc)
                    retry=max(retry,stamp.timestamp())
                except (TypeError,ValueError,OverflowError):raise ProviderFailure('Invalid server cooldown configuration; request not sent.','unavailable') from None
            if len(attempts)>=count:retry=max(retry,attempts[0]+window)
            host_key=name+'|'+(urlsplit(origin).hostname or origin)
            if name in ('mdn_observatory','website_trigger'):
                interval=60 if name=='mdn_observatory' else 3600
                host=urlsplit(origin).hostname or origin
                legacy=max(saved.get(name+'|'+origin,0),saved.get(name+'|http://'+host,0),saved.get(name+'|https://'+host,0))
                retry=max(retry,max(saved.get(host_key,0),legacy)+interval)
            if retry>now:raise ProviderFailure('A preserved local/provider cooldown is active; this scan request was not sent.','rate_limited',retry_at=retry_iso(retry),code='local_cooldown',diagnostics={'request_sent':False,'quota':name,'reason':'Local request budget, per-host interval or operator-preserved cooldown.'})
            row.update(attempts=attempts+[now]);saved[name]=row
            if name in ('mdn_observatory','website_trigger'):saved[host_key]=now
            self.store.write(path,saved)
    def block(self,name,seconds):
        with self.store.lock:
            path=self.store.root/'provider-quotas.json';data=self.store.read(path,{});row=data.setdefault(name,{'attempts':[]});row['blocked_until']=max(row.get('blocked_until',0),time.time()+seconds);self.store.write(path,data)
    async def request(self,method,url,quota=None,origin='',**kwargs):
        # Retry only idempotent result/status reads, never ambiguous scan-start POSTs.
        attempts=2 if method.upper()=='GET' else 1
        for attempt in range(attempts):
            try:return await self._request_once(method,url,quota,origin,**kwargs)
            except ProviderFailure as error:
                transient=error.state in ('unavailable','timed_out') or (error.http_status is not None and error.http_status>=500)
                if attempt+1>=attempts or not transient:raise
                await asyncio.sleep(max(2.5 if url.startswith('https://vibecheckscan.com/') else 1,2**attempt)+random.uniform(0,.25))
    def response_error(self,method,url,status,headers,content,quota):
        receipt=response_receipt(method,url,status,headers,content)
        checkpoint=security_checkpoint(headers,content)
        if checkpoint:
            seconds=retry_seconds(headers.get('Retry-After'),quota)
            if quota:self.block(quota,seconds)
            return ProviderFailure('The provider blocked automated access at a security checkpoint. No scan result was returned; waiting alone may not resolve this.','blocked',status,retry_iso(time.time()+seconds),code='provider_security_checkpoint',diagnostics=receipt)
        if status==429:
            seconds=retry_seconds(headers.get('Retry-After'),quota)
            if quota:self.block(quota,seconds)
            return ProviderFailure('Provider returned HTTP429. Retry-After was honored when supplied; otherwise its conservative window applies. The outbound server IP is shared by LaunchShield users.','rate_limited',429,retry_iso(time.time()+seconds),code='upstream_rate_limit',diagnostics=receipt)
        return ProviderFailure('Provider returned HTTP '+str(status)+'. No clean result can be inferred.',http_status=status,code='upstream_http_error',diagnostics=receipt)
    async def _request_once(self,method,url,quota=None,origin='',**kwargs):
        allowed=('https://websiteauditor.net/','https://xlogs.com/','https://vibecheckscan.com/','https://observatory-api.mdn.mozilla.net/','https://api.osv.dev/')
        if not url.startswith(allowed):raise ProviderFailure('Unapproved provider endpoint.')
        if quota:self.reserve(quota,origin)
        client=self.client_factory() if self.client_factory else httpx.AsyncClient(timeout=httpx.Timeout(45,connect=12),follow_redirects=False,trust_env=False)
        try:
            async with client:
                async with client.stream(method,url,headers={'User-Agent':'LaunchShield-R1/1.0 (owner-authorized passive assessment)'},**kwargs) as response:
                    content=b''
                    async for chunk in response.aiter_bytes():
                        content+=chunk
                        if len(content)>self.settings.maximum_response:raise ProviderFailure('Provider response exceeded the size limit.',code='response_size_limit')
                    status=response.status_code
                    if security_checkpoint(response.headers,content) or status==429:raise self.response_error(method,url,status,response.headers,content,quota)
                    if status==404:return status,None
                    if status!=200:raise self.response_error(method,url,status,response.headers,content,quota)
                    try:data=json.loads(content,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Invalid JSON numeric constant')))
                    except Exception:raise ProviderFailure('Provider returned malformed/non-JSON data.',http_status=status,code='invalid_json',diagnostics=response_receipt(method,url,status,response.headers,content)) from None
                    return status,data
        except httpx.TimeoutException:raise ProviderFailure('Provider network request timed out; a scan-start POST was not blindly retried.','timed_out',code='network_timeout',diagnostics={'request_sent':True,'method':method,'endpoint':url}) from None
        except httpx.HTTPError:raise ProviderFailure('Provider network request failed; no clean result can be inferred.','unavailable',code='network_error',diagnostics={'request_sent':True,'method':method,'endpoint':url}) from None
    async def trigger_auditor(self,host,origin):
        self.reserve('website_trigger',origin)
        client=self.client_factory() if self.client_factory else httpx.AsyncClient(timeout=20,follow_redirects=False,trust_env=False)
        url='https://websiteauditor.net/report/'+quote(host,safe='')
        try:
            async with client:
                async with client.stream('GET',url) as response:
                    # Drain the bounded documented response instead of closing after headers.
                    # Its HTML is never scraped for evidence or executed.
                    body=b''
                    async for chunk in response.aiter_bytes():
                        body+=chunk
                        if len(body)>self.settings.maximum_response:raise ProviderFailure('Website Auditor trigger response exceeded the size limit.',code='response_size_limit')
                    if security_checkpoint(response.headers,body) or response.status_code==429:raise self.response_error('GET',url,response.status_code,response.headers,body,'website_trigger')
                    if response.status_code not in (200,202):raise self.response_error('GET',url,response.status_code,response.headers,body,'website_trigger')
                    receipt=response_receipt('GET',url,response.status_code,response.headers,body);receipt['scan_acceptance_confirmed']=False
                    return receipt
        except httpx.TimeoutException:raise ProviderFailure('Documented Website Auditor trigger request timed out; it was not repeated.','timed_out',code='trigger_network_timeout') from None
        except httpx.HTTPError:raise ProviderFailure('Website Auditor trigger connection failed; acceptance was not confirmed.','unavailable',code='trigger_network_error') from None
    async def run(self,name,target,mode,scenario,progress,packages=None):
        requested=utcnow();origin=target.origin
        if name=='osv' and not packages:return {'state':'skipped_not_applicable','message':'No reliable package ecosystem/name/exact-version evidence. This is not a clean vulnerability result.','requested_at':requested,'native':None}
        if mode=='mock':
            await asyncio.sleep(self.settings.mock_delay)
            if scenario=='partial_failure' and name=='xlogs':raise ProviderFailure('MOCK: upstream unavailable.','unavailable',503)
            if scenario=='rate_limited' and name=='xlogs':raise ProviderFailure('MOCK: provider quota reached.','rate_limited',429,datetime.fromtimestamp(time.time()+600,timezone.utc).isoformat())
            if scenario=='timeout' and name=='vibe_check':raise ProviderFailure('MOCK: bounded timeout.','timed_out')
            native=native_fixture(name,origin,scenario)
            return self.result(name,native,requested,mode)
        cache_origin=origin
        if name=='osv':cache_origin+='|'+hashlib.sha256(json.dumps(packages,sort_keys=True).encode()).hexdigest()
        cached=self.store.cached(name,cache_origin,CACHE_TTL[name])
        if cached:
            cached.update(local_cached=True,requested_at=requested)
            if cached.get('state')=='completed':cached['state']='cached'
            return cached
        if name=='website_auditor':
            endpoint='https://websiteauditor.net/api/public/audit/'+quote(target.host,safe='')
            status,native=await self.request('GET',endpoint)
            if status==404:
                await progress('running','No cached report; requesting the documented report route once. Scan acceptance is not yet confirmed.')
                try:trigger=await self.trigger_auditor(target.host,origin)
                except ProviderFailure as error:
                    error.diagnostics.update(cache_http_status=404,scan_acceptance_confirmed=False)
                    raise
                polls=0
                for delay in (4,8,12,16,20):
                    await asyncio.sleep(delay);status,native=await self.request('GET',endpoint);polls+=1
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
                await asyncio.sleep(max(2.5,self.settings.poll_interval))
                _,state=await self.request('GET','https://vibecheckscan.com/api/scan/status','vibe_poll',origin,params={'id':scanid,'format':'agent'})
                if not isinstance(state,dict):raise ProviderFailure('Invalid Vibe Check status response.')
                if state.get('status')=='error':raise ProviderFailure('Vibe Check returned a terminal provider error.')
                await progress('running','Vibe Check modules: '+json.dumps(state.get('modules',{}))[:700],external_scan_id=scanid)
                if state.get('status')=='completed':
                    native=state.get('result')
                    # format=agent may inline a summary envelope, not full findings.
                    # A summary/grade is never treated as a complete evidence report.
                    if not isinstance(native,dict) or not isinstance(native.get('modules'),dict):
                        _,native=await self.request('GET','https://vibecheckscan.com/api/scan/result','vibe_poll',origin,params={'id':scanid,'format':'full'})
                    break
        elif name=='mdn_observatory':
            status,native=await self.request('POST','https://observatory-api.mdn.mozilla.net/api/v2/scan','mdn_observatory',origin,params={'host':target.host})
        elif name=='osv':
            queries=[p['query'] for p in packages];_,response=await self.request('POST','https://api.osv.dev/v1/querybatch','osv',origin,json={'queries':queries})
            if not isinstance(response,dict) or not isinstance(response.get('results'),list):raise ProviderFailure('OSV batch response schema changed.')
            native={'queries':queries,'results':response['results'],'package_sources':[p['source'] for p in packages]}
        else:raise ProviderFailure('Unsupported provider.')
        if not isinstance(native,dict):raise ProviderFailure('Provider response is not a JSON object.')
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

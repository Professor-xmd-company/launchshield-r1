from __future__ import annotations
import asyncio,secrets,json,hashlib,time
from collections import Counter
from datetime import datetime,timezone
from html import escape
from .models import Settings,ScanRequest,PROVIDERS,PROVIDER_TERMINAL,TERMINAL,utcnow
from .persistence import FileStore,redact,hash_token
from .safety import normalize_target,validate_live,TargetRejected
from .providers import ProviderEngine,ProviderFailure,CACHE_TTL
from .normalize import normalize,packages_from_xlogs,deduplicate,SchemaChanged
from .ai import analyze

LIMITATIONS=[
 'Passive/read-only, public and unauthenticated assessment; not a penetration test.',
 'No exploitation, authentication/business-logic testing or guarantee of finding every vulnerability.',
 'No combined security score is calculated from incompatible provider scores.',
 'Public third-party providers may publish/cache the target and their results; confidentiality is not guaranteed.',
 'Only this application’s own validation requests are IP-pinned; external providers use their own DNS and scope controls.',
 'No database: reports depend on the current host filesystem. Sleep, restart or redeploy may interrupt jobs or erase files.',
 'Stopping local polling cannot guarantee cancellation of an already-started remote provider scan.',
 'Evidence values may be redacted for secrets; original provider findings and confidence distinctions otherwise remain linked.'
]
class JobConflict(ValueError):pass

class JobManager:
    def __init__(self,settings:Settings,store=None,engine=None,validator=None,ai_function=None):
        self.settings=settings;self.store=store or FileStore(settings.data_dir);self.engine=engine or ProviderEngine(settings,self.store)
        self.validator=validator or validate_live;self.ai_function=ai_function or analyze
        self.queue=asyncio.Queue(maxsize=settings.max_queue);self.worker=None;self.cleaner=None;self.current_id=None;self.current_task=None;self.stopping=False
    async def start(self):
        # Never re-submit provider scan-start POSTs merely because the process restarted.
        for job in self.store.all_jobs():
            if job['state'] not in TERMINAL:
                for name,p in job['providers'].items():
                    if p['state'] not in PROVIDER_TERMINAL:self.store.provider(job['id'],name,state='failed',message='Interrupted by process restart; not automatically re-submitted.')
                self.store.update(job['id'],state='failed',completed_at=utcnow(),warnings=job.get('warnings',[])+['interrupted_by_restart'])
                self.save_report(job['id'],self.store.read(self.store.job_dir(job['id'])/'findings-original.json',[]),{'state':'unavailable','message':'Interrupted before analysis.'})
                self.store.event(job['id'],'restart_interrupted',{'automatic_resubmission':False})
        self.store.cleanup(self.settings.retention_seconds)
        self.worker=asyncio.create_task(self._worker());self.cleaner=asyncio.create_task(self._cleaner())
    async def close(self):
        self.stopping=True
        for task in (self.worker,self.cleaner):
            if task:task.cancel()
        await asyncio.gather(*(t for t in (self.worker,self.cleaner) if t),return_exceptions=True)
    async def _cleaner(self):
        while True:
            await asyncio.sleep(60);self.store.cleanup(self.settings.retention_seconds)
    async def create(self,spec:ScanRequest,owner_hash):
        if not spec.authorized:raise TargetRejected('Explicit ownership/permission confirmation is required.')
        if spec.mode=='live' and not spec.public_disclosure:raise TargetRejected('Acknowledge public/cached third-party result visibility before live checks.')
        target=normalize_target(spec.target)
        if spec.mode=='live' and target.origin not in {normalize_target(x).origin for x in self.settings.live_targets}:raise TargetRejected('Live testing is limited to owner-approved origins configured on the server.')
        for job in self.store.all_jobs():
            if job['target']==target.origin and job['mode']==spec.mode and job['state'] not in TERMINAL:
                if job['owner_hash']!=owner_hash:raise JobConflict('That target already has an active job. No private job identifier was disclosed.')
                return self.public(job),None,True
        if self.queue.full():raise JobConflict('R1 job queue is full; retry later.')
        jid=secrets.token_hex(16);token=secrets.token_urlsafe(32)
        job={'id':jid,'owner_hash':owner_hash,'access_hash':hash_token(token),'target':target.origin,'requested_target_had_path_query_or_fragment':target.stripped_path,'mode':spec.mode,'scenario':spec.scenario if spec.mode=='mock' else 'success','ai_enabled':spec.ai,'state':'queued','created_at':utcnow(),'updated_at':utcnow(),'completed_at':None,'authorization':'self_declared_by_submitter','public_disclosure_acknowledged':spec.public_disclosure,'providers':{p:{'state':'queued','message':'Not started.','updated_at':utcnow()} for p in PROVIDERS},'warnings':(['Path/query/fragment was removed; scope is the single normalized origin.'] if target.stripped_path else []),'report_available':False,'queue_position':self.queue.qsize()+int(self.current_id is not None)+1}
        self.store.create(job);await self.queue.put(jid);return self.public(job),token,False
    def public(self,job):
        return {k:v for k,v in job.items() if k not in ('owner_hash','access_hash')}
    async def cancel(self,jid):
        job=self.store.get(jid)
        if job['state'] in TERMINAL:return self.public(job)
        self.store.event(jid,'cancel_requested',{'remote_cancellation_guaranteed':False})
        if self.current_id==jid and self.current_task:self.current_task.cancel()
        else:
            for p,r in job['providers'].items():
                if r['state'] not in PROVIDER_TERMINAL:self.store.provider(jid,p,state='cancelled',message='Cancelled before dispatch.')
            self.store.update(jid,state='cancelled',completed_at=utcnow());self.save_report(jid,[],{'state':'disabled'})
        return self.public(self.store.get(jid))
    async def _worker(self):
        while True:
            jid=await self.queue.get()
            try:
                job=self.store.get(jid)
                if job['state'] in TERMINAL:continue
                self.current_id=jid;self.current_task=asyncio.create_task(self.process(jid))
                try:await asyncio.wait_for(self.current_task,self.settings.job_timeout)
                except asyncio.TimeoutError:
                    await self.terminate(jid,'failed','Overall job deadline reached; remote work may still continue.')
                except asyncio.CancelledError:
                    await self.terminate(jid,'failed' if self.stopping else 'cancelled','Interrupted by shutdown.' if self.stopping else 'Cancelled locally; already-started external scans may continue.')
                    if self.stopping:raise
                except Exception:
                    await self.terminate(jid,'failed','Unexpected orchestration failure; no clean assessment was inferred.')
            finally:self.current_id=None;self.current_task=None;self.queue.task_done()
    async def terminate(self,jid,state,message):
        job=self.store.get(jid)
        for p,r in job['providers'].items():
            if r['state'] not in PROVIDER_TERMINAL:self.store.provider(jid,p,state='cancelled' if state=='cancelled' else 'failed',message=message)
        self.store.update(jid,state=state,completed_at=utcnow(),warnings=job.get('warnings',[])+[message])
        records=self.store.read(self.store.job_dir(jid)/'findings-original.json',[]);self.save_report(jid,records,{'state':'unavailable','message':message})
    async def process(self,jid):
        job=self.store.get(jid);target=normalize_target(job['target']);self.store.update(jid,state='validating',queue_position=0)
        if job['mode']=='live':
            try:validation=await self.validator(target,self.settings.live_targets)
            except (TargetRejected,asyncio.TimeoutError,OSError) as e:
                await self.terminate(jid,'failed','Target validation failed: '+str(e)[:400]);return
        else:validation={'mode':'mock','network_validation_performed':False,'note':'Synthetic fixtures; no target/provider request.'}
        self.store.update(jid,state='running_providers',validation=validation)
        records=[];natives={};semaphore=asyncio.Semaphore(self.settings.provider_concurrency)
        async def run_provider(name,packages=None):
            async with semaphore:
                self.store.provider(jid,name,state='running',message='Reading synthetic fixture.' if job['mode']=='mock' else 'Provider request in progress.',started_at=utcnow())
                async def progress(state,message,**extra):self.store.provider(jid,name,state=state,message=message,**extra)
                try:
                    result=await asyncio.wait_for(self.engine.run(name,target,job['mode'],job['scenario'],progress,packages),self.settings.provider_timeout)
                    native=result.get('native');normalized=[]
                    if native is not None:
                        normalized=normalize(name,native,target.origin)
                        for row in normalized:row['scanned_at']=result.get('scanned_at');row['requested_at']=result.get('requested_at');row['mode']=job['mode']
                    records.extend(normalized)
                    self.store.write(self.store.job_dir(jid)/'findings-original.json',redact(records))
                    natives[name]=native
                    artifact={**result,'source':name,'mode':job['mode'],'native_response_sha256':hashlib.sha256(json.dumps(native,sort_keys=True,default=str).encode()).hexdigest(),'normalized_findings':normalized}
                    cache_origin=artifact.pop('_cache_origin',None)
                    self.store.artifact(jid,name,artifact)
                    if cache_origin and result['state'] in ('completed','cached','stale_result'):self.store.put_cache(name,cache_origin,{k:v for k,v in result.items() if k!='_cache_origin'})
                    self.store.provider(jid,name,**{k:v for k,v in result.items() if k not in ('native','_cache_origin')},finding_records=len(normalized),completed_at=utcnow())
                except SchemaChanged as e:
                    self.store.artifact(jid,name,{'state':'failed','schema_error':str(e),'native':native,'source':name,'mode':job['mode']})
                    self.store.provider(jid,name,state='failed',message='Unrecognized/invalid response schema: '+str(e),completed_at=utcnow())
                except ProviderFailure as e:
                    self.store.provider(jid,name,state=e.state,message=e.message,http_status=e.http_status,retry_at=e.retry_at,completed_at=utcnow())
                    self.store.artifact(jid,name,{'state':e.state,'error':e.message,'http_status':e.http_status,'retry_at':e.retry_at,'source':name,'mode':job['mode']})
                except asyncio.TimeoutError:
                    self.store.artifact(jid,name,{'state':'timed_out','source':name,'mode':job['mode'],'error':'Provider deadline reached.'})
                    self.store.provider(jid,name,state='timed_out',message='Provider deadline reached; other providers continue.',completed_at=utcnow())
                except asyncio.CancelledError:raise
                except Exception:
                    self.store.provider(jid,name,state='failed',message='Adapter failed safely; no clean result was inferred.',completed_at=utcnow())
        await asyncio.gather(*(run_provider(name) for name in PROVIDERS if name!='osv'))
        packages=packages_from_xlogs(natives.get('xlogs'));await run_provider('osv',packages)
        self.store.update(jid,state='normalizing');report=self.build_report(jid,records,{'state':'pending'})
        if not job['ai_enabled']:ai={'state':'disabled','message':'AI is disabled; evidence report remains complete.'}
        elif job['mode']=='mock' and job['scenario']=='ai_failure':ai={'state':'unavailable','message':'MOCK AI failure; report still downloadable.'}
        else:
            self.store.update(jid,state='analyzing')
            if job['mode']=='live' and not self.reserve_ai():ai={'state':'rate_limited','message':'Local AI call budget reached; no key rotation.'}
            else:
                try:ai=await self.ai_function(report,self.settings,force_mock=job['mode']=='mock')
                except Exception:ai={'state':'unavailable','message':'AI failed; original evidence remains available.'}
        states=[r['state'] for r in self.store.get(jid)['providers'].values()]
        successful=any(s in ('completed','cached','stale_result') for s in states)
        warnings=any(s not in ('completed','cached','skipped_not_applicable') for s in states) or (job['ai_enabled'] and ai['state'] not in ('completed','mock'))
        final='failed' if not successful else ('completed_with_warnings' if warnings else 'completed')
        self.store.update(jid,state=final,completed_at=utcnow());self.save_report(jid,records,ai)
    def reserve_ai(self):
        with self.store.lock:
            path=self.store.root/'ai-budget.json';now=time.time();data=self.store.read(path,{'attempts':[]});attempts=[t for t in data['attempts'] if now-t<3600]
            if len(attempts)>=self.settings.ai_calls_per_hour:return False
            self.store.write(path,{'attempts':attempts+[now]});return True
    def build_report(self,jid,records,ai):
        job=self.store.get(jid);findings=deduplicate(records);coverage=[]
        for name,p in job['providers'].items():coverage.append({'provider':name,**p})
        return {'version':'R1','job_id':jid,'target':job['target'],'mode':job['mode'],'synthetic':job['mode']=='mock','state':job['state'],'created_at':job['created_at'],'completed_at':job.get('completed_at'),'authorization':job['authorization'],'coverage':coverage,'findings':findings,'original_finding_records':redact(records),'counts':dict(Counter(f['severity'] for f in findings)),'coverage_counts':dict(Counter(p['state'] for p in coverage)),'limitations':LIMITATIONS,'warnings':job.get('warnings',[]),'ai':ai,'storage':'Temporary file-backed instance; download reports you need.','security_guarantee':False}
    def save_report(self,jid,records,ai):
        report=self.build_report(jid,records,ai);folder=self.store.job_dir(jid)
        self.store.write(folder/'findings.json',report['findings']);self.store.write(folder/'report.json',redact(report))
        html=self.render_html(report);temporary=folder/'report.html.tmp';temporary.write_text(html);temporary.chmod(0o600);temporary.replace(folder/'report.html')
        self.store.update(jid,report_available=True,ai_state=ai.get('state'));self.store.event(jid,'report_available',{'state':report['state'],'unique_findings':len(report['findings']),'original_records':len(records),'ai_state':ai.get('state')})
        return report
    def render_html(self,report):
        esc=lambda x:escape(str(x),quote=True)
        coverage=''.join('<tr><td>'+esc(p['provider'])+'</td><td>'+esc(p['state'])+'</td><td>'+esc(p.get('message',''))+'</td><td>'+esc(p.get('scanned_at','not supplied'))+'</td></tr>' for p in report['coverage'])
        findings=''.join('<section><h3>'+esc(f['title'])+'</h3><p>Severity: '+esc(f['severity'])+' · Source records: '+str(len(f['sources']))+'</p><pre>'+esc(json.dumps(f,indent=2,ensure_ascii=False))+'</pre></section>' for f in report['findings'])
        return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>LaunchShield R1 report</title><style>body{font:15px/1.6 system-ui,sans-serif;max-width:1000px;margin:30px auto;padding:0 20px;color:#17202b}table{border-collapse:collapse;width:100%}td,th{padding:9px;border:1px solid #bbc2ca;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f4f6;padding:15px}section{border-top:1px solid #bbc2ca;padding:15px 0}</style><h1>LaunchShield R1 — '+('MOCK FIXTURE REPORT' if report['synthetic'] else 'Passive assessment report')+'</h1><p>'+esc(report['target'])+' · '+esc(report['state'])+'</p><p>No guarantee of security. No exploitation was performed.</p><h2>Provider coverage</h2><div style="overflow:auto"><table><tr><th>Provider</th><th>State</th><th>Detail</th><th>Scan timestamp</th></tr>'+coverage+'</table></div><h2>Findings and evidence</h2>'+findings+'<h2>AI interpretation — separate from observed evidence</h2><pre>'+esc(json.dumps(report['ai'],indent=2,ensure_ascii=False))+'</pre><h2>Limitations</h2><ul>'+''.join('<li>'+esc(s)+'</li>' for s in report['limitations'])+'</ul></html>'

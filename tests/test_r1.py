import asyncio,json,time,secrets
from pathlib import Path
import pytest,pytest_asyncio,httpx
from app import create_app
from shield.models import Settings,ScanRequest,utcnow
from shield.persistence import FileStore,hash_token,redact
from shield.harness import JobManager
from shield.safety import normalize_target,resolve_public,validate_live,pinned_request,TargetRejected
from shield.providers import ProviderEngine,ProviderFailure
from shield.fixtures import native_fixture
from shield.normalize import normalize,packages_from_xlogs,deduplicate,SchemaChanged
from shield.ai import analyze

@pytest_asyncio.fixture
async def context(tmp_path):
    settings=Settings(data_dir=tmp_path,gemini_key='',mock_delay=.01,provider_timeout=1,job_timeout=5)
    app=create_app(settings)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://shield.test') as client:
            config=(await client.get('/api/config')).json();headers={'X-Client-Token':config['client_token'],'X-CSRF-Token':config['csrf'],'Origin':'https://shield.test'}
            yield app,client,headers

def body(**extra):return {'target':'https://demo.example/path?secret=do-not-forward','mode':'mock','authorized':True,'public_disclosure':False,'ai':True,'scenario':'success',**extra}
async def submit(context,**extra):
    app,c,h=context;r=await c.post('/api/scans',json=body(**extra),headers=h);assert r.status_code==202,r.text
    jid=r.json()['job']['id'];await asyncio.wait_for(app.state.manager.queue.join(),3)
    job=(await c.get('/api/scans/'+jid,headers=h)).json();report=(await c.get('/api/scans/'+jid+'/report',headers=h)).json()
    return jid,job,report

@pytest.mark.asyncio
async def test_success_end_to_end(context):
    jid,job,report=await submit(context)
    assert job['state']=='completed' and report['synthetic'] is True
    assert all(x['state'] in ('completed','cached') for x in report['coverage'])
    csp=[f for f in report['findings'] if f['type']=='header:csp'];assert len(csp)==1 and len(csp[0]['sources'])==2
    assert len(report['original_finding_records'])>len(report['findings'])
    assert not any('SEO' in f['title'] for f in report['findings'])
    assert report['security_guarantee'] is False and report['ai']['state']=='mock'
    assert job['target']=='https://demo.example' and job['requested_target_had_path_query_or_fragment']

@pytest.mark.asyncio
@pytest.mark.parametrize('scenario,provider,state',[('partial_failure','xlogs','unavailable'),('rate_limited','xlogs','rate_limited'),('malformed','website_auditor','failed'),('timeout','vibe_check','timed_out'),('stale_cache','website_auditor','stale_result')])
async def test_partial_failures_preserve_other_results(context,scenario,provider,state):
    _,job,report=await submit(context,scenario=scenario)
    assert job['state']=='completed_with_warnings';assert job['providers'][provider]['state']==state
    assert report['findings'] and job['report_available']
    assert any(c['state'] in ('completed','cached') for c in report['coverage'])
    if scenario=='rate_limited':assert job['providers'][provider]['retry_at']

@pytest.mark.asyncio
async def test_osv_skip_not_clean(context):
    _,job,report=await submit(context,scenario='osv_skip')
    osv=job['providers']['osv'];assert osv['state']=='skipped_not_applicable' and 'not a clean' in osv['message']
    assert job['state']=='completed'

@pytest.mark.asyncio
async def test_ai_failure_does_not_block_exports(context):
    jid,job,report=await submit(context,scenario='ai_failure');assert report['ai']['state']=='unavailable'
    app,c,h=context
    for fmt in ('json','html'):
        r=await c.get('/api/scans/'+jid+'/report?format='+fmt+'&download=true',headers=h);assert r.status_code==200 and 'attachment' in r.headers['content-disposition']
    assert job['state']=='completed_with_warnings'

@pytest.mark.asyncio
async def test_no_ai_still_reports(context):
    _,job,report=await submit(context,ai=False);assert report['ai']['state']=='disabled' and job['state']=='completed'

@pytest.mark.asyncio
async def test_refresh_does_not_restart_job(context):
    jid,job,_=await submit(context);app,c,h=context
    before=len(app.state.manager.store.all_jobs())
    for _ in range(3):assert (await c.get('/api/scans/'+jid,headers=h)).status_code==200
    assert len(app.state.manager.store.all_jobs())==before

@pytest.mark.asyncio
async def test_active_click_deduplication(context):
    app,c,h=context;app.state.settings.mock_delay=.15
    one=await c.post('/api/scans',json=body(),headers=h);two=await c.post('/api/scans',json=body(),headers=h)
    assert one.status_code==202 and two.status_code==200
    assert one.json()['job']['id']==two.json()['job']['id'] and two.json()['deduplicated']
    await app.state.manager.queue.join()

@pytest.mark.asyncio
async def test_owner_scope_and_capability(context):
    jid,job,_=await submit(context);app,c,h=context
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://shield.test') as other:
        for suffix in ('','/findings','/events','/report','/providers/xlogs'):
            assert (await other.get('/api/scans/'+jid+suffix)).status_code==404
        original=app.state.manager.store.get(jid)
        assert 'owner_hash' not in job and 'access_hash' not in job
    # A fresh job token is returned only at creation; cookie-independent access is explicit.
    app.state.settings.mock_delay=.1;r=await c.post('/api/scans',json=body(target='https://another.example'),headers=h);token=r.json()['job_token'];jid2=r.json()['job']['id']
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://shield.test') as other:
        assert (await other.get('/api/scans/'+jid2,headers={'X-Job-Token':token})).status_code==200
        assert (await other.get('/api/scans/'+jid2+'?token='+token)).status_code==404
    await app.state.manager.queue.join()

@pytest.mark.asyncio
async def test_permission_and_disclosure_required(context):
    app,c,h=context
    assert (await c.post('/api/scans',json=body(authorized=False),headers=h)).status_code==422
    assert (await c.post('/api/scans',json=body(mode='live',public_disclosure=False),headers=h)).status_code==422
    assert not app.state.manager.store.all_jobs()

@pytest.mark.asyncio
async def test_live_allowlist_enforced_before_provider(context):
    app,c,h=context
    r=await c.post('/api/scans',json=body(mode='live',public_disclosure=True,target='https://unauthorized.example'),headers=h)
    assert r.status_code==422 and not app.state.manager.store.all_jobs()

@pytest.mark.asyncio
async def test_csrf_origin_and_body_limits(context):
    app,c,h=context
    assert (await c.post('/api/scans',json=body())).status_code==403
    assert (await c.post('/api/scans',json=body(),headers={**h,'Origin':'https://attacker.example'})).status_code==403
    assert (await c.post('/api/scans',content='x',headers={**h,'Content-Type':'text/plain'})).status_code==415
    assert (await c.post('/api/scans',content='x'*33000,headers={**h,'Content-Type':'application/json'})).status_code==413
    assert not app.state.manager.store.all_jobs()

@pytest.mark.asyncio
async def test_no_accounts_terminal_or_data_exposure(context):
    app,c,h=context
    for path in ('/account','/login','/register','/api/exec','/data/.session-key','/docs','/openapi.json'):
        assert (await c.get(path)).status_code==404
    health=(await c.get('/healthz')).json();assert health['accounts'] is False and health['database'] is False
    config=(await c.get('/api/config')).json();assert 'gemini_key' not in config

@pytest.mark.asyncio
async def test_cancel_active_job(context):
    app,c,h=context;app.state.settings.mock_delay=.5
    r=await c.post('/api/scans',json=body(),headers=h);jid=r.json()['job']['id']
    for _ in range(100):
        if app.state.manager.current_id==jid:break
        await asyncio.sleep(.001)
    assert (await c.post('/api/scans/'+jid+'/cancel',json={},headers=h)).status_code==200
    await app.state.manager.queue.join();job=app.state.manager.store.get(jid)
    assert job['state']=='cancelled' and job['report_available']
    assert 'remote' in (await c.get('/api/scans/'+jid+'/report',headers=h)).text.lower()

@pytest.mark.asyncio
async def test_report_pending_and_unknown_formats(context):
    app,c,h=context;app.state.settings.mock_delay=.1
    r=await c.post('/api/scans',json=body(),headers=h);jid=r.json()['job']['id']
    assert (await c.get('/api/scans/'+jid+'/report',headers=h)).status_code==409
    await app.state.manager.queue.join()
    assert (await c.get('/api/scans/'+jid+'/report?format=pdf',headers=h)).status_code==422
    assert (await c.get('/api/scans/'+jid+'/providers/unknown',headers=h)).status_code==404

@pytest.mark.parametrize('url',['http://127.0.0.1','http://0.0.0.0','http://10.0.0.1','http://172.16.2.3','http://192.168.0.2','http://169.254.169.254','http://[::1]','http://[fd00::1]','http://localhost','http://foo.internal','file:///etc/passwd','ftp://example.com','https://user:password@example.com','https://example.com:22','https://example.com\\@evil.com','https://example.com\n/'])
def test_forbidden_targets(url):
    with pytest.raises(TargetRejected):normalize_target(url)

def test_normalization_removes_query_and_path():
    t=normalize_target('HTTPS://Example.COM:443/private?token=secret#x');assert t.origin=='https://example.com' and t.stripped_path

def test_unicode_hostname_normalized():assert normalize_target('https://bücher.de').host=='xn--bcher-kva.de'

@pytest.mark.asyncio
async def test_dns_mixed_private_answers_blocked():
    async def resolver(host,port):return ['93.184.216.34','127.0.0.1']
    with pytest.raises(TargetRejected):await resolve_public(normalize_target('https://owned.example'),resolver)

@pytest.mark.asyncio
async def test_dns_pinning_and_sni():
    seen=[]
    async def resolver(host,port):return ['93.184.216.34']
    async def handler(request):seen.append(request);return httpx.Response(200)
    target=normalize_target('https://owned.example')
    result=await validate_live(target,(target.origin,),resolver,httpx.MockTransport(handler))
    assert result['own_requests_ip_pinned'] and seen[0].url.host=='93.184.216.34'
    assert seen[0].headers['host']=='owned.example' and seen[0].extensions['sni_hostname']=='owned.example'

@pytest.mark.asyncio
async def test_redirect_to_private_or_other_origin_rejected():
    async def resolver(host,port):return ['93.184.216.34']
    for location in ('http://127.0.0.1/','https://elsewhere.example/'):
        calls=[]
        async def handler(request):calls.append(request);return httpx.Response(302,headers={'Location':location})
        with pytest.raises(TargetRejected):await validate_live(normalize_target('https://owned.example'),('https://owned.example',),resolver,httpx.MockTransport(handler))
        assert len(calls)==1

@pytest.mark.asyncio
async def test_redirect_dns_rebinding_rejected():
    count=0;calls=[]
    async def resolver(host,port):
        nonlocal count;count+=1;return ['93.184.216.34'] if count==1 else ['169.254.169.254']
    async def handler(request):calls.append(request);return httpx.Response(302,headers={'Location':'/next'})
    with pytest.raises(TargetRejected):await validate_live(normalize_target('https://owned.example'),('https://owned.example',),resolver,httpx.MockTransport(handler))
    assert len(calls)==1

def test_safe_pinned_request_rejects_private():
    with pytest.raises(TargetRejected):pinned_request(normalize_target('https://owned.example'),'127.0.0.1')

def test_path_traversal_and_atomic_writes(tmp_path):
    store=FileStore(tmp_path)
    with pytest.raises(KeyError):store.job_dir('../secret')
    store.write(tmp_path/'record.json',{'value':1});assert store.read(tmp_path/'record.json')['value']==1
    assert not list(tmp_path.glob('*.tmp'))
    assert (tmp_path/'record.json').stat().st_mode&0o777==0o600

def test_redaction_covers_values_and_key_fields():
    secret='AQ.'+'a'*70;value=redact({'GEMINI_API_KEY':secret,'evidence':'Found '+secret,'db':'postgresql://user:shortpass@host/db','note':'password=shortpass'})
    text=json.dumps(value);assert secret not in text and 'shortpass' not in text

@pytest.mark.asyncio
async def test_restart_marks_interrupted_without_resubmission(tmp_path):
    settings=Settings(data_dir=tmp_path,gemini_key='');store=FileStore(tmp_path);jid=secrets.token_hex(16)
    job={'id':jid,'target':'https://owned.example','owner_hash':'owner','access_hash':'secret','mode':'live','state':'running_providers','providers':{n:{'state':'running'} for n in ('website_auditor','xlogs','vibe_check','mdn_observatory','osv')},'warnings':[],'created_at':utcnow(),'authorization':'self_declared','report_available':False};store.create(job)
    manager=JobManager(settings,store=store);await manager.start()
    try:assert store.get(jid)['state']=='failed' and manager.queue.empty() and 'interrupted_by_restart' in store.get(jid)['warnings']
    finally:await manager.close()

def test_cleanup_never_deletes_active_job(tmp_path):
    store=FileStore(tmp_path)
    for state in ('completed','running_providers'):
        jid=secrets.token_hex(16);store.create({'id':jid,'mode':'mock','target':'https://demo.example','state':state,'completed_at':'2020-01-01T00:00:00+00:00'})
    removed=store.cleanup(60);assert len(removed)==1 and len(store.all_jobs())==1 and store.all_jobs()[0]['state']=='running_providers'

@pytest.mark.asyncio
async def test_provider_429_backoff_no_retry(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);return httpx.Response(429,headers={'Retry-After':'600'},json={'error':'rate limited'})
    settings=Settings(data_dir=tmp_path);engine=ProviderEngine(settings,FileStore(tmp_path),lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    for _ in range(2):
        with pytest.raises(ProviderFailure) as error:await engine.request('POST','https://xlogs.com/api/v1/scan','xlogs','https://owned.example',json={'url':'https://owned.example'})
        assert error.value.state=='rate_limited' and error.value.retry_at
    assert len(calls)==1

@pytest.mark.asyncio
async def test_provider_caps_and_invalid_json(tmp_path):
    for response in (httpx.Response(200,content='x'*100,headers={'Content-Type':'application/json'}),httpx.Response(200,content='not json',headers={'Content-Type':'text/html'})):
        async def handler(request):return response
        engine=ProviderEngine(Settings(data_dir=tmp_path,maximum_response=50),FileStore(tmp_path),lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        with pytest.raises(ProviderFailure):await engine.request('GET','https://websiteauditor.net/api/public/audit/owned.example')

@pytest.mark.asyncio
async def test_provider_no_blind_scan_start_retry(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);raise httpx.ReadTimeout('fixture')
    engine=ProviderEngine(Settings(data_dir=tmp_path),FileStore(tmp_path),lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    with pytest.raises(ProviderFailure) as error:await engine.request('POST','https://vibecheckscan.com/api/scan/start','vibe_start','https://owned.example',json={'url':'https://owned.example'})
    assert error.value.state=='timed_out' and len(calls)==1

@pytest.mark.asyncio
async def test_unapproved_provider_endpoint_blocked(tmp_path):
    engine=ProviderEngine(Settings(data_dir=tmp_path),FileStore(tmp_path))
    with pytest.raises(ProviderFailure):await engine.request('GET','https://evil.example/api')

def test_mdn_summary_does_not_invent_header_evidence():
    rows=normalize('mdn_observatory',native_fixture('mdn_observatory','https://demo.example'),'https://demo.example')
    assert len(rows)==1 and rows[0]['type']=='mdn-summary' and rows[0]['severity']=='info'
    assert 'No specific header' in rows[0]['evidence']['note']

def test_vibe_effective_framing_not_false_positive():
    rows=normalize('vibe_check',native_fixture('vibe_check','https://demo.example'),'https://demo.example')
    assert not any(r['type']=='header:framing' for r in rows)
    assert not any('/health' in r['resource'] for r in rows)

def test_osv_requires_explicit_semver_not_banner_guess():
    assert packages_from_xlogs({'server':'nginx/1.2.3'})==[]
    assert packages_from_xlogs({'sbom':{'libraries':[{'name':'react','version':'18.x'}]}})==[]
    assert packages_from_xlogs({'sbom':{'libraries':[{'name':'unknown','version':'1.2.3'}]}})==[]
    data=native_fixture('xlogs','https://demo.example');packages=packages_from_xlogs(data)
    assert packages[0]['query']['version']=='4.17.20' and packages[0]['source']['field']=='sbom.libraries'

@pytest.mark.parametrize('provider,data',[('xlogs',{'ok':True}),('website_auditor',{'report':{}}),('vibe_check',{'status':'running'}),('mdn_observatory',{'grade':'A'}),('osv',{'queries':[]})])
def test_unknown_schemas_are_not_clean_results(provider,data):
    with pytest.raises(SchemaChanged):normalize(provider,data,'https://demo.example')

def ai_report():return {'target':'https://demo.example','mode':'mock','coverage':[{'provider':'xlogs','state':'completed'}],'findings':[{'id':'f_known','title':'Fixture CSP signal','severity':'medium','sources':[]}],'limitations':['Synthetic evidence.']}
@pytest.mark.asyncio
async def test_real_ai_adapter_with_mock_http_and_strict_ids(tmp_path):
    for identifier,expected in [('f_known','completed'),('f_invented','invalid_or_unavailable')]:
        async def handler(request):
            assert request.headers['x-goog-api-key']=='test-key-not-real'
            assert 'test-key-not-real' not in request.content.decode()
            data={'summary':'Fixture interpretation only.','analysis':[{'finding_id':identifier,'explanation':'Provider observation, not exploitation.','remediation':'Review CSP.','verification':'Repeat check.'}],'limitations':['Passive-only.']}
            return httpx.Response(200,json={'candidates':[{'content':{'parts':[{'text':json.dumps(data)}]}}],'usageMetadata':{'totalTokenCount':120}})
        result=await analyze(ai_report(),Settings(data_dir=tmp_path,gemini_key='test-key-not-real'),lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        assert result['state']==expected

@pytest.mark.asyncio
async def test_ai_unavailable_and_429_are_nonfatal(tmp_path):
    result=await analyze(ai_report(),Settings(data_dir=tmp_path,gemini_key=''));assert result['state']=='unavailable'
    count=0
    async def handler(request):
        nonlocal count;count+=1;return httpx.Response(429,json={'error':'quota'},headers={'Retry-After':'60'})
    result=await analyze(ai_report(),Settings(data_dir=tmp_path,gemini_key='fake-key'),lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert result['state']=='rate_limited' and count==1 and result['retry_after']=='60'

@pytest.mark.asyncio
async def test_ai_unsupported_guarantee_rejected(tmp_path):
    async def handler(request):return httpx.Response(200,json={'candidates':[{'content':{'parts':[{'text':json.dumps({'summary':'This website is 100% secure','analysis':[],'limitations':[]})}]}}]})
    result=await analyze(ai_report(),Settings(data_dir=tmp_path,gemini_key='fake-key'),lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert result['state']=='invalid_or_unavailable'

@pytest.mark.asyncio
async def test_html_report_escapes_untrusted_findings(context):
    _,job,report=await submit(context);manager=context[0].state.manager
    report['findings'][0]['title']='<script>alert(1)</script>';html=manager.render_html(report)
    assert '<script>' not in html and '&lt;script&gt;' in html

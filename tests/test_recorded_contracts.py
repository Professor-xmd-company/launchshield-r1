"""Isolated regressions using recorded public-origin responses; NEVER live scans."""
import asyncio,json,time
from datetime import datetime,timezone
from pathlib import Path
import httpx,pytest
from app import create_app
from shield.models import Settings
from shield.persistence import FileStore
from shield.providers import ProviderEngine,ProviderFailure
from shield.normalize import normalize,SchemaChanged
from shield.fixtures import native_fixture
from shield.safety import normalize_target

EVIDENCE=Path(__file__).resolve().parents[1]/'r1/evidence'
def recorded(name):return json.loads((EVIDENCE/name).read_text())
async def noop(*args,**kwargs):pass

def engine(tmp_path,handler,**extra):
    settings=Settings(data_dir=tmp_path,gemini_key='',**extra)
    return ProviderEngine(settings,FileStore(tmp_path),lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)))

@pytest.mark.asyncio
async def test_real_agent_envelope_fetches_full_same_id_without_restart(tmp_path,monkeypatch):
    agent=recorded('live-vibe_check.json')['native'];full=recorded('vibe-existing-full.json');calls=[]
    async def handler(request):
        calls.append(request)
        if request.url.path=='/api/scan/start':return httpx.Response(200,json={'scanId':agent['scanId']})
        assert request.url.params['id']==agent['scanId']
        if request.url.path=='/api/scan/status':return httpx.Response(200,json={'status':'completed','result':agent})
        assert request.method=='GET' and request.url.path=='/api/scan/result' and request.url.params['format']=='full'
        return httpx.Response(200,json=full)
    monkeypatch.setattr('shield.providers.asyncio.sleep',noop)
    result=await engine(tmp_path,handler).run('vibe_check',normalize_target(full['url']),'live','success',noop)
    assert result['native']==full and len(calls)==3 and sum(r.method=='POST' for r in calls)==1
    assert result['external_scan_id']==agent['scanId'] and normalize('vibe_check',full,full['url'])==[]

def test_recorded_full_vibe_retains_partial_warning_and_native_timestamp(tmp_path):
    full=recorded('vibe-existing-full.json');e=ProviderEngine(Settings(data_dir=tmp_path),FileStore(tmp_path))
    result=e.result('vibe_check',full,'recorded-replay','live')
    assert result['scanned_at']==full['timestamp']
    assert result['coverage_warnings'] and any('apiSurface' in s for s in result['coverage_warnings'])
    assert 'partial' in result['message'] and result['native']==full

@pytest.mark.asyncio
async def test_partial_module_sets_job_and_report_warnings(tmp_path,monkeypatch):
    def partial_fixture(name,origin,scenario):
        data=native_fixture(name,origin,scenario)
        if name=='vibe_check':data['modules']['apiSurface'].update(partial=True,notes=['FIXTURE: some checks timed out.'])
        return data
    monkeypatch.setattr('shield.providers.native_fixture',partial_fixture)
    app=create_app(Settings(data_dir=tmp_path,gemini_key='',mock_delay=0))
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://shield.test') as client:
            config=(await client.get('/api/config')).json();headers={'X-Client-Token':config['client_token'],'X-CSRF-Token':config['csrf'],'Origin':'https://shield.test'}
            response=await client.post('/api/scans',json={'target':'https://fixture.example','authorized':True,'ai':False},headers=headers)
            assert response.status_code==202;jobid=response.json()['job']['id'];await asyncio.wait_for(app.state.manager.queue.join(),3)
            job=(await client.get('/api/scans/'+jobid,headers=headers)).json();report=(await client.get('/api/scans/'+jobid+'/report',headers=headers)).json()
            assert job['state']=='completed_with_warnings' and job['providers']['vibe_check']['state']=='completed'
            assert any('apiSurface' in warning for warning in report['warnings']) and report['security_guarantee'] is False

@pytest.mark.asyncio
@pytest.mark.parametrize('header,minimum',[(None,3600),('7200',7200),('invalid-header',3600)])
async def test_429_uses_conservative_window_and_never_shortens_retry_after(tmp_path,header,minimum):
    calls=[]
    async def handler(request):
        calls.append(request);return httpx.Response(429,json={'error':'MOCK quota'},headers={} if header is None else {'Retry-After':header})
    e=engine(tmp_path,handler);before=time.time()
    with pytest.raises(ProviderFailure) as caught:await e.request('POST','https://xlogs.com/api/v1/scan','xlogs',json={'url':'https://fixture.example'})
    assert caught.value.state=='rate_limited' and len(calls)==1
    assert datetime.fromisoformat(caught.value.retry_at).timestamp()>=before+minimum-1
    assert e.store.read(e.store.root/'provider-quotas.json')['xlogs']['blocked_until']>=before+minimum-1

@pytest.mark.asyncio
async def test_operator_cooldown_survives_empty_ephemeral_quota_store(tmp_path):
    calls=[];until=datetime.fromtimestamp(time.time()+3600,timezone.utc).isoformat()
    async def handler(request):calls.append(request);raise AssertionError('No external request is permitted during cooldown')
    e=engine(tmp_path,handler,provider_cooldowns={'xlogs':until})
    with pytest.raises(ProviderFailure) as caught:await e.run('xlogs',normalize_target('https://fixture.example'),'live','success',noop)
    assert caught.value.state=='rate_limited' and caught.value.http_status is None and not calls
    assert caught.value.retry_at==until

@pytest.mark.parametrize('data',[{'status':'completed','modules':{}},{'status':'completed','summary':{'modules':{'headers':{'score':100}}}}])
def test_empty_or_summary_only_vibe_is_not_a_clean_report(data):
    with pytest.raises(SchemaChanged):normalize('vibe_check',data,'https://fixture.example')

def test_malformed_vibe_native_survives_until_strict_normalization(tmp_path):
    native={'status':'completed','modules':['changed schema']};e=ProviderEngine(Settings(data_dir=tmp_path),FileStore(tmp_path))
    result=e.result('vibe_check',native,'recorded-replay','live')
    assert result['native'] is native
    with pytest.raises(SchemaChanged):normalize('vibe_check',native,'https://fixture.example')

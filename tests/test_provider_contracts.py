"""Adapter-level HTTP contracts: all transports below are MOCKED, no website scan."""
import json,time
import pytest,httpx
from shield.models import Settings
from shield.persistence import FileStore
from shield.providers import ProviderEngine,ProviderFailure
from shield.fixtures import native_fixture
from shield.normalize import normalize,packages_from_xlogs
from shield.safety import normalize_target

async def noop(*args,**kwargs):pass

def engine(tmp_path,handler):
    settings=Settings(data_dir=tmp_path,gemini_key='')
    return ProviderEngine(settings,FileStore(tmp_path),lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)))

@pytest.mark.asyncio
@pytest.mark.parametrize('name,path',[('xlogs','/api/v1/scan'),('mdn_observatory','/api/v2/scan')])
async def test_sync_http_contract(tmp_path,name,path):
    calls=[];target=normalize_target('https://owned.example')
    async def handler(request):
        calls.append(request);assert request.method=='POST' and request.url.path==path
        if name=='xlogs':assert json.loads(request.content)=={'url':target.origin}
        else:assert request.url.params['host']=='owned.example'
        return httpx.Response(200,json=native_fixture(name,target.origin))
    result=await engine(tmp_path,handler).run(name,target,'live','success',noop)
    assert result['http_status']==200 and normalize(name,result['native'],target.origin) and len(calls)==1

@pytest.mark.asyncio
async def test_auditor_documented_trigger_once(tmp_path,monkeypatch):
    calls=[];reads=0;target=normalize_target('https://owned.example')
    async def handler(request):
        nonlocal reads;calls.append(request.url.path)
        if request.url.path.startswith('/api/public/audit/'):
            reads+=1
            return httpx.Response(404,json={'error':'missing'}) if reads==1 else httpx.Response(200,json=native_fixture('website_auditor',target.origin))
        assert request.url.path=='/report/owned.example'
        return httpx.Response(200,text='<html>Ignored documented scan trigger; not scraped.</html>')
    monkeypatch.setattr('shield.providers.asyncio.sleep',noop)
    result=await engine(tmp_path,handler).run('website_auditor',target,'live','success',noop)
    assert result['state']=='cached' and calls.count('/report/owned.example')==1 and reads==2

@pytest.mark.asyncio
async def test_vibe_start_and_documented_poll_cadence(tmp_path,monkeypatch):
    requests=[];delays=[];polls=0;scanid='a'*32;target=normalize_target('https://owned.example')
    async def delay(value):delays.append(value)
    async def handler(request):
        nonlocal polls;requests.append(request)
        if request.url.path=='/api/scan/start':
            assert request.method=='POST';return httpx.Response(200,json={'scanId':scanid,'queued':True})
        assert request.url.path=='/api/scan/status' and request.url.params['id']==scanid and request.url.params['format']=='agent'
        polls+=1
        if polls==1:return httpx.Response(200,json={'status':'running','modules':{'headers':{'status':'running'}}})
        native=native_fixture('vibe_check',target.origin);native['scanId']=scanid
        return httpx.Response(200,json={'status':'completed','result':native})
    monkeypatch.setattr('shield.providers.asyncio.sleep',delay)
    result=await engine(tmp_path,handler).run('vibe_check',target,'live','success',noop)
    assert result['external_scan_id']==scanid and polls==2 and len(requests)==3
    assert delays and all(value>=2.5 for value in delays)
    assert normalize('vibe_check',result['native'],target.origin)

@pytest.mark.asyncio
async def test_osv_http_query_exact_version_and_provenance(tmp_path):
    target=normalize_target('https://owned.example');packages=packages_from_xlogs(native_fixture('xlogs',target.origin));calls=[]
    async def handler(request):
        calls.append(request);body=json.loads(request.content)
        assert body['queries'][0]=={'package':{'ecosystem':'npm','name':'lodash'},'version':'4.17.20'}
        return httpx.Response(200,json={'results':[{'vulns':[{'id':'FIXTURE-ADVISORY-NOT-REAL'}]}]})
    result=await engine(tmp_path,handler).run('osv',target,'live','success',noop,packages)
    assert result['native']['package_sources'][0]['field']=='sbom.libraries' and len(calls)==1

@pytest.mark.asyncio
async def test_safe_get_retry_bounded_with_backoff(tmp_path,monkeypatch):
    calls=[];delays=[]
    async def handler(request):
        calls.append(request)
        return httpx.Response(503,json={'error':'fixture transient'}) if len(calls)==1 else httpx.Response(200,json={'ok':True})
    async def delay(value):delays.append(value)
    monkeypatch.setattr('shield.providers.asyncio.sleep',delay)
    status,data=await engine(tmp_path,handler).request('GET','https://websiteauditor.net/api/public/audit/owned.example')
    assert status==200 and data['ok'] and len(calls)==2 and len(delays)==1 and delays[0]>=1

@pytest.mark.asyncio
async def test_no_post_retry_on_ambiguous_server_failure(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);return httpx.Response(503,json={'error':'fixture'})
    with pytest.raises(ProviderFailure):await engine(tmp_path,handler).request('POST','https://xlogs.com/api/v1/scan',json={'url':'https://owned.example'})
    assert len(calls)==1

@pytest.mark.asyncio
async def test_nonstandard_numeric_json_rejected(tmp_path):
    async def handler(request):return httpx.Response(200,content='{"score": NaN}',headers={'Content-Type':'application/json'})
    with pytest.raises(ProviderFailure):await engine(tmp_path,handler).request('GET','https://websiteauditor.net/api/public/audit/owned.example')

def test_iso_and_second_timestamp_staleness(tmp_path):
    e=ProviderEngine(Settings(data_dir=tmp_path),FileStore(tmp_path))
    for stamp in ('2020-01-01T00:00:00Z',1577836800,1577836800000):
        native=native_fixture('website_auditor','https://owned.example');native['report']['fetchedAt']=stamp
        assert e.result('website_auditor',native,'fixture','mock')['state']=='stale_result'

def test_unknown_cache_age_not_falsely_fresh(tmp_path):
    e=ProviderEngine(Settings(data_dir=tmp_path),FileStore(tmp_path));native=native_fixture('website_auditor','https://owned.example')
    native['cachedAt']=None;native['report']['fetchedAt']=None
    result=e.result('website_auditor',native,'fixture','mock');assert result['freshness']=='unknown' and 'unknown' in result['message']

@pytest.mark.asyncio
async def test_vibe_retry_never_polls_faster_than_documented(tmp_path,monkeypatch):
    calls=[];delays=[]
    async def handler(request):
        calls.append(request);return httpx.Response(503,json={'error':'fixture'}) if len(calls)==1 else httpx.Response(200,json={'status':'running'})
    async def delay(value):delays.append(value)
    monkeypatch.setattr('shield.providers.asyncio.sleep',delay)
    await engine(tmp_path,handler).request('GET','https://vibecheckscan.com/api/scan/status',params={'id':'a'*32})
    assert len(calls)==2 and delays and all(d>=2.5 for d in delays)

"""Isolated diagnostics/reliability contracts. No actual scan, provider call or live TLS peer."""
import json,time,ssl,copy
from datetime import datetime,timezone,timedelta
from pathlib import Path
from types import SimpleNamespace
import httpx,pytest
from shield.models import Settings,utcnow,PROVIDERS
from shield.providers import ProviderEngine,ProviderFailure
from shield.persistence import FileStore
from shield.harness import JobManager
from shield.safety import normalize_target,validate_live,tls_observation
from shield.diagnostics import vibe_modules,inconclusive_expiry
from shield.normalize import normalize

ROOT=Path(__file__).resolve().parents[1]
async def noop(*args,**kwargs):pass
def engine(tmp_path,handler,**kwargs):
    settings=Settings(data_dir=tmp_path,gemini_key='',**kwargs)
    return ProviderEngine(settings,FileStore(tmp_path),lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)))
def full_vibe():return json.loads((ROOT/'r1/evidence/simple-real-only-vibe_check.json').read_text())['native']

@pytest.mark.asyncio
@pytest.mark.parametrize('status',[200,403,429,503])
async def test_security_checkpoint_is_not_mislabeled_json_quota_or_retried(tmp_path,status):
    calls=[]
    async def handler(request):
        calls.append(request);return httpx.Response(status,text='<html><title>Vercel Security Checkpoint</title>DO NOT STORE RAW HTML</html>',headers={'content-type':'text/html','x-vercel-mitigated':'challenge','x-vercel-challenge-token':'ISOLATED-DO-NOT-STORE','Set-Cookie':'ISOLATED-COOKIE-DO-NOT-STORE'})
    e=engine(tmp_path,handler)
    with pytest.raises(ProviderFailure) as caught:await e.request('GET','https://xlogs.com/api/v1/scan','xlogs')
    error=caught.value;assert error.state=='blocked' and error.code=='provider_security_checkpoint' and error.http_status==status and len(calls)==1
    text=json.dumps(error.diagnostics);assert error.diagnostics['request_sent'] is True and 'body_sha256' in error.diagnostics
    assert 'ISOLATED-DO-NOT-STORE' not in text and 'ISOLATED-COOKIE' not in text and 'DO NOT STORE RAW HTML' not in text

@pytest.mark.asyncio
async def test_real_json_quota_preserves_reason_headers_and_full_wait(tmp_path):
    async def handler(request):return httpx.Response(429,json={'code':'rate_limit_exceeded','error':'ISOLATED quota exceeded','request_id':'fixture-request'},headers={'Retry-After':'7200','x-ratelimit-remaining':'0'})
    e=engine(tmp_path,handler);before=time.time()
    with pytest.raises(ProviderFailure) as caught:await e.request('POST','https://xlogs.com/api/v1/scan','xlogs',json={'url':'https://fixture.example'})
    error=caught.value;assert error.state=='rate_limited' and error.code=='upstream_rate_limit' and error.diagnostics['provider_code']=='rate_limit_exceeded'
    assert error.diagnostics['provider_request_id']=='fixture-request' and datetime.fromisoformat(error.retry_at).timestamp()>=before+7199

@pytest.mark.asyncio
async def test_local_cooldown_explicitly_records_request_not_sent(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);raise AssertionError('Transport must not be reached')
    until=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat();e=engine(tmp_path,handler,provider_cooldowns={'xlogs':until})
    with pytest.raises(ProviderFailure) as caught:await e.run('xlogs',normalize_target('https://fixture.example'),'live','success',noop)
    assert caught.value.code=='local_cooldown' and caught.value.diagnostics['request_sent'] is False and not calls

@pytest.mark.asyncio
async def test_auditor_no_report_is_not_faked_as_network_timeout(tmp_path,monkeypatch):
    calls=[];delays=[];drained=[]
    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b'<html>ISOLATED documented trigger';yield b' response, not security evidence.</html>';drained.append(True)
    async def handler(request):
        calls.append(request)
        if request.url.path.startswith('/report/'):return httpx.Response(200,stream=Body(),headers={'content-type':'text/html'})
        return httpx.Response(404,json={'ok':False,'error':'No cached report. Run a scan first.'})
    async def delay(value):delays.append(value)
    monkeypatch.setattr('shield.providers.asyncio.sleep',delay);e=engine(tmp_path,handler);target=normalize_target('https://fixture.example')
    with pytest.raises(ProviderFailure) as caught:await e.run('website_auditor',target,'live','success',noop)
    error=caught.value;assert error.state=='unavailable' and error.code=='report_not_generated' and error.http_status==404
    assert error.diagnostics['cache_reads']==6 and error.diagnostics['scan_acceptance_confirmed'] is False and sum(delays)==60
    assert drained==[True] and sum('/report/' in r.url.path for r in calls)==1
    assert 'ISOLATED documented trigger' not in json.dumps(error.diagnostics)
    before=len(calls)
    with pytest.raises(ProviderFailure) as second:await e.run('website_auditor',target,'live','success',noop)
    assert second.value.diagnostics['cache_http_status']==404 and second.value.diagnostics['scan_acceptance_confirmed'] is False
    assert second.value.code=='local_cooldown' and len(calls)==before+1 # cached read only; no repeated trigger

@pytest.mark.parametrize('name',['website_trigger','mdn_observatory'])
def test_http_https_share_documented_per_hostname_interval(tmp_path,name):
    e=engine(tmp_path,None);e.reserve(name,'https://fixture.example')
    with pytest.raises(ProviderFailure) as caught:e.reserve(name,'http://fixture.example')
    assert caught.value.code=='local_cooldown'

@pytest.mark.parametrize('name',['website_trigger','mdn_observatory'])
def test_legacy_per_origin_quota_is_not_lost_on_hostname_migration(tmp_path,name):
    e=engine(tmp_path,None);e.store.write(e.store.root/'provider-quotas.json',{name+'|https://fixture.example':time.time()})
    with pytest.raises(ProviderFailure):e.reserve(name,'http://fixture.example')

def test_recorded_zero_missing_certificate_date_is_inconclusive_not_medium_finding():
    native=full_vibe();assert inconclusive_expiry(native['modules']['tls'])
    rows=normalize('vibe_check',native,native['url'])
    assert not any(row['native_id']=='tls:certExpiry' for row in rows)
    tls=next(x for x in vibe_modules(native) if x['module']=='tls')
    assert tls['state']=='partial' and any('no certificate date' in note.lower() or 'without a certificate date' in note.lower() for note in tls['notes'])
    assert native['modules']['tls']['findings']['certExpiry']=={'valid':False,'daysUntilExpiry':0,'score':0} # native evidence not changed

def test_negative_expiry_day_report_is_retained_as_unverified_signal():
    native=full_vibe();native['modules']['tls']['findings']['certExpiry']['daysUntilExpiry']=-2
    row=next(x for x in normalize('vibe_check',native,native['url']) if x['native_id']=='tls:certExpiry')
    assert row['interpretation_confidence']=='potential' and row['observation_confidence']=='provider_reported'

def test_null_cors_probes_and_api_request_budget_are_visible_not_passed():
    native=full_vibe();modules={m['module']:m for m in vibe_modules(native)}
    assert modules['cors']['state']=='partial' and modules['cors']['results_unknown']>0
    assert modules['apiSurface']['state']=='partial' and any('80' in note for note in modules['apiSurface']['notes'])
    assert modules['cve']['state']=='not_applicable'

def test_permissions_policy_is_information_not_verified_vulnerability():
    native=full_vibe();native['modules']['headers']['findings']['permissionsPolicy'].update(assessment='missing',present=False)
    row=next(x for x in normalize('vibe_check',native,native['url']) if x['native_id']=='permissionsPolicy')
    assert row['severity']=='info' and row['interpretation_confidence']=='potential'

class FakeSSL:
    context=SimpleNamespace(verify_mode=ssl.CERT_REQUIRED,check_hostname=True)
    def getpeercert(self,binary_form=False):return b'ISOLATED CERTIFICATE BYTES' if binary_form else {'notAfter':'Jan 20 15:33:21 2030 GMT'}
    def version(self):return 'TLSv1.3'
class FakeStream:
    def __init__(self,peer):self.peer=peer
    def get_extra_info(self,name):assert name=='ssl_object';return self.peer

@pytest.mark.asyncio
async def test_tls_metadata_reuses_the_one_pinned_scope_validation_connection(tmp_path):
    calls=[]
    async def resolver(*args):return ['1.1.1.1']
    async def handler(request):calls.append(request);return httpx.Response(200,extensions={'network_stream':FakeStream(FakeSSL())})
    target=normalize_target('https://fixture.example');result=await validate_live(target,(target.origin,),resolver=resolver,transport=httpx.MockTransport(handler))
    assert len(calls)==1 and calls[0].method=='HEAD' and result['tls']['chain_and_hostname_verified'] is True
    assert result['tls']['not_after']=='2030-01-20T15:33:21+00:00' and result['tls']['source']=='existing_scope_validation_tls_handshake'

def test_unverified_or_missing_tls_object_is_not_a_positive_tls_observation():
    peer=FakeSSL();peer.context=SimpleNamespace(verify_mode=ssl.CERT_NONE,check_hostname=False);target=normalize_target('https://fixture.example')
    assert tls_observation(httpx.Response(200,extensions={'network_stream':FakeStream(peer)}),target) is None
    assert tls_observation(httpx.Response(200),target) is None

@pytest.mark.asyncio
@pytest.mark.parametrize('body,status,expected',[({'error':'GET requires x-xlogs-scan:1'},400,'responded_without_scan'),('<html><title>Vercel Security Checkpoint</title></html>',429,'blocked')])
async def test_operator_diagnostic_is_one_no_target_get_not_a_scan(tmp_path,body,status,expected):
    calls=[]
    async def handler(request):
        calls.append(request);assert request.method=='GET' and not request.url.query and 'x-xlogs-scan' not in request.headers and request.content==b''
        return httpx.Response(status,json=body) if isinstance(body,dict) else httpx.Response(status,text=body,headers={'content-type':'text/html'})
    until=(datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat();e=engine(tmp_path,handler,diagnostics_until=until);manager=JobManager(e.settings,store=e.store,engine=e)
    await manager.provider_access_diagnostic();await manager.provider_access_diagnostic()
    result=e.store.read(e.store.root/'provider-access-diagnostic.json');assert len(calls)==1 and result['state']==expected and result['target_submitted'] is False and result['scan_started'] is False

@pytest.mark.asyncio
@pytest.mark.parametrize('offset',[-60,3601])
async def test_disabled_expired_or_overlong_operator_window_sends_nothing(tmp_path,offset):
    async def handler(request):raise AssertionError('No diagnostic allowed')
    until=(datetime.now(timezone.utc)+timedelta(seconds=offset)).isoformat();e=engine(tmp_path,handler,diagnostics_until=until);manager=JobManager(e.settings,store=e.store,engine=e)
    await manager.provider_access_diagnostic();assert not (e.store.root/'provider-access-diagnostic.json').exists()

def test_missing_providers_cannot_yield_a_clean_or_complete_assessment(tmp_path):
    manager=JobManager(Settings(data_dir=tmp_path));jid='a'*32
    manager.store.create({'id':jid,'target':'https://fixture.example','mode':'live','state':'completed_with_warnings','created_at':utcnow(),'authorization':'self_declared_by_submitter','providers':{p:{'state':'completed' if p=='mdn_observatory' else 'unavailable'} for p in PROVIDERS},'validation':{'tls':{'chain_and_hostname_verified':True,'not_after':'2030-01-20T15:33:21Z','protocol':'TLSv1.3'}}})
    report=manager.build_report(jid,[],{'state':'unavailable'});assert report['assessment']['status']=='inconclusive' and report['security_guarantee'] is False
    assert report['scope_verification']['tls']['chain_and_hostname_verified'] is True
    html=manager.render_html(report);assert 'Incomplete assessment' in html and 'Direct TLS connection' in html

def test_simple_ui_keeps_real_flow_and_shows_incomplete_and_specific_causes():
    js=(ROOT/'static/main.js').read_text();html=(ROOT/'static/index.html').read_text()
    assert 'provider_security_checkpoint' in js and 'Next scan attempt not before' in js and 'Security result: inconclusive' in js
    assert 'Module coverage' in js and 'Direct connection verification' in js
    assert html.index('id="coverage-note"')<html.index('class="card overview"') and html.count('<input ')==1

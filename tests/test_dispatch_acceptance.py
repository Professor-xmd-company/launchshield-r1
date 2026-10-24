"""Deterministic acceptance tests. ALL provider transports are injected; no live scans.

These tests verify backend dispatch/cooldown behavior, not just UI strings.
"""
import asyncio,json,copy,ssl
from datetime import datetime,timezone,timedelta
from pathlib import Path
import httpx,pytest
from app import create_app
from shield.models import Settings,PROVIDERS,utcnow
from shield.persistence import FileStore
from shield.providers import ProviderEngine,ProviderFailure
from shield.quotas import GateClosed,QuotaStateError,iso
from shield.safety import normalize_target
from shield.fixtures import native_fixture
from shield.normalize import SchemaChanged
from tools.cooldown_manifest import build_manifest

ORIGIN='https://owned.example'
class Clock:
    def __init__(self):self.now=datetime(2026,10,24,18,tzinfo=timezone.utc).timestamp()
    def __call__(self):return self.now
    def advance(self,seconds):self.now+=seconds
async def noop(*args,**kwargs):pass

def make(tmp_path,handler,clock=None,sleeper=None,**settings):
    conf=Settings(data_dir=tmp_path,gemini_key='',**settings);store=FileStore(tmp_path)
    return ProviderEngine(conf,store,lambda:httpx.AsyncClient(transport=httpx.MockTransport(handler)),clock=clock or Clock(),sleeper=sleeper or noop)
async def run(e,name='xlogs',origin=ORIGIN,progress=noop):return await e.run(name,normalize_target(origin),'live','success',progress)
def quota(e,name):return e.store.read(e.quotas.path,{}).get(name,{})

def auditor_handler(calls,cache_misses=1):
    reads=0
    async def handler(request):
        nonlocal reads;calls.append((request.method,str(request.url)))
        if '/report/' in request.url.path:return httpx.Response(200,text='<html>ISOLATED trigger response; not a report.</html>')
        reads+=1
        if reads<=cache_misses:return httpx.Response(404,json={'ok':False,'error':'No cached report.'})
        return httpx.Response(200,json=native_fixture('website_auditor',ORIGIN))
    return handler

@pytest.mark.asyncio
async def test_first_uncached_target_triggers_and_polls_a_valid_report(tmp_path):
    calls=[];events=[];e=make(tmp_path,auditor_handler(calls))
    async def progress(state,message,**extra):events.append((state,extra))
    result=await run(e,'website_auditor',progress=progress);d=result['dispatch']
    assert [x[0] for x in calls]==['GET','GET','GET'] and '/api/public/audit/owned.example' in calls[0][1] and '/report/owned.example' in calls[1][1]
    assert d['scan_requests_sent']==1 and d['requests_sent']==3 and d['report_received'] is True and d['lifecycle_state']=='completed'
    assert any(x[0]=='request_sent' for x in events) and any(x[0]=='polling' for x in events)
    assert quota(e,'website_trigger')['sent_total']==1 and e.store.read(e.quotas.path)['_reports']['website_auditor']['received_total']==1

@pytest.mark.asyncio
async def test_existing_provider_cache_does_not_dispatch_a_scan_trigger(tmp_path):
    calls=[];e=make(tmp_path,auditor_handler(calls,cache_misses=0));result=await run(e,'website_auditor')
    assert len(calls)==1 and result['dispatch']['requests_sent']==1 and result['dispatch']['scan_request_sent'] is False and result['dispatch']['report_received'] is True
    assert not quota(e,'website_trigger').get('attempts') and not any('/report/' in x[1] for x in calls)

@pytest.mark.asyncio
async def test_legacy_restart_hour_cannot_block_first_uncached_auditor_scan(tmp_path):
    clock=Clock();calls=[];future=iso(clock()+3600)
    e=make(tmp_path,auditor_handler(calls),clock=clock,provider_cooldowns={'website_trigger':future})
    result=await run(e,'website_auditor');assert result['dispatch']['scan_request_sent'] is True and any('/report/' in x[1] for x in calls)
    assert any('legacy unscoped' in x for x in result['dispatch']['state_warnings'])

@pytest.mark.asyncio
async def test_active_target_interval_only_skips_trigger_not_cache_lookup(tmp_path):
    calls=[];e=make(tmp_path,auditor_handler(calls,cache_misses=999));permit=e.reserve('website_trigger',ORIGIN);e.quotas.dispatched(permit);e.quotas.release(permit)
    before=copy.deepcopy(quota(e,'website_trigger'))
    with pytest.raises(ProviderFailure) as caught:await run(e,'website_auditor')
    error=caught.value;d=error.diagnostics['dispatch']
    assert error.state=='skipped_cooldown' and error.diagnostics['cooldown']['scope']=='target'
    assert len(calls)==1 and d['requests_sent']==1 and d['scan_request_sent'] is False and d['report_received'] is False
    assert quota(e,'website_trigger')==before

@pytest.mark.asyncio
async def test_same_target_retry_after_interval_expiry_reaches_transport(tmp_path):
    clock=Clock();calls=[];e=make(tmp_path,auditor_handler(calls,cache_misses=2),clock=clock)
    permit=e.reserve('website_trigger',ORIGIN);e.quotas.dispatched(permit);e.quotas.release(permit)
    with pytest.raises(ProviderFailure):await run(e,'website_auditor')
    clock.advance(3601);result=await run(e,'website_auditor')
    # Cache still missing on retry, so an eligible real trigger and polling now run.
    assert result['dispatch']['report_received'] is True and result['dispatch']['scan_request_sent'] is True
    assert sum('/report/' in u for _,u in calls)==1 # Not skipped again, not retriggered twice.

@pytest.mark.asyncio
async def test_expired_xlogs_cooldown_allows_next_post_without_reinitializing(tmp_path):
    clock=Clock();calls=[];until=iso(clock()+60)
    async def handler(request):calls.append(request);return httpx.Response(200,json=native_fixture('xlogs',ORIGIN))
    e=make(tmp_path,handler,clock=clock,provider_cooldowns={'xlogs':until})
    with pytest.raises(ProviderFailure) as caught:await run(e)
    assert caught.value.state=='skipped_cooldown' and caught.value.retry_at==until and not calls and not quota(e,'xlogs').get('attempts')
    clock.advance(61);result=await run(e)
    assert len(calls)==1 and calls[0].method=='POST' and str(calls[0].url)=='https://xlogs.com/api/v1/scan' and json.loads(calls[0].content)=={'url':ORIGIN}
    assert result['dispatch']['report_received'] and quota(e,'xlogs')['sent_total']==1

@pytest.mark.asyncio
async def test_repeated_blocked_attempts_do_not_change_deadline_file_or_counter(tmp_path):
    clock=Clock();calls=[]
    async def handler(request):calls.append(request);return httpx.Response(429,json={'code':'rate_limit_exceeded','error':'ISOLATED quota'},headers={'Retry-After':'120'})
    e=make(tmp_path,handler,clock=clock)
    with pytest.raises(ProviderFailure) as first:await run(e)
    deadline=first.value.retry_at;snapshot=e.quotas.path.read_bytes()
    for _ in range(6):
        clock.advance(5)
        with pytest.raises(ProviderFailure) as blocked:await run(e)
        assert blocked.value.state=='skipped_cooldown' and blocked.value.retry_at==deadline and blocked.value.diagnostics['dispatch']['request_sent'] is False
        assert e.quotas.path.read_bytes()==snapshot
    assert len(calls)==1 and quota(e,'xlogs')['sent_total']==1
    clock.advance(91)
    with pytest.raises(ProviderFailure) as second:await run(e)
    assert second.value.state=='rate_limited' and len(calls)==2 and quota(e,'xlogs')['sent_total']==2

@pytest.mark.asyncio
async def test_provider_global_rate_limit_applies_to_other_targets_without_sending(tmp_path):
    clock=Clock();calls=[]
    async def handler(request):calls.append(request);return httpx.Response(429,json={'error':'quota'},headers={'Retry-After':'300'})
    e=make(tmp_path,handler,clock=clock)
    with pytest.raises(ProviderFailure):await run(e)
    with pytest.raises(ProviderFailure) as caught:await run(e,origin='https://second.example')
    assert caught.value.diagnostics['cooldown']['scope']=='provider' and len(calls)==1

@pytest.mark.asyncio
async def test_target_interval_does_not_block_a_different_website_target(tmp_path):
    async def handler(request):return httpx.Response(200,json={'ok':True})
    e=make(tmp_path,handler);permit=e.reserve('website_trigger',ORIGIN);e.quotas.dispatched(permit);e.quotas.release(permit)
    with pytest.raises(ProviderFailure):e.reserve('website_trigger','http://owned.example')
    other=e.reserve('website_trigger','https://different.example');e.quotas.release(other)

@pytest.mark.asyncio
async def test_60_xlogs_sent_requests_cap_and_61st_local_skip_is_read_only(tmp_path):
    clock=Clock();calls=[]
    async def handler(request):calls.append(request);return httpx.Response(200,json={'ok':True})
    e=make(tmp_path,handler,clock=clock)
    for _ in range(60):await e.request('POST','https://xlogs.com/api/v1/scan','xlogs',ORIGIN,json={'url':ORIGIN})
    snapshot=e.quotas.path.read_bytes()
    with pytest.raises(ProviderFailure) as caught:await e.request('POST','https://xlogs.com/api/v1/scan','xlogs',ORIGIN,json={'url':ORIGIN})
    assert caught.value.state=='skipped_cooldown' and caught.value.diagnostics['cooldown']['reason']=='local_provider_budget'
    assert len(calls)==60 and len(quota(e,'xlogs')['attempts'])==60 and e.quotas.path.read_bytes()==snapshot
    clock.advance(3601);await e.request('POST','https://xlogs.com/api/v1/scan','xlogs',ORIGIN,json={'url':ORIGIN})
    assert len(calls)==61 and len(quota(e,'xlogs')['attempts'])==1 and quota(e,'xlogs')['sent_total']==61

@pytest.mark.asyncio
async def test_deliberate_xlogs_per_host_protection_is_separate_and_optional(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);return httpx.Response(200,json={'ok':True})
    e=make(tmp_path,handler,xlogs_target_interval=30)
    await e.request('POST','https://xlogs.com/api/v1/scan','xlogs',ORIGIN,json={'url':ORIGIN})
    with pytest.raises(ProviderFailure) as caught:await e.request('POST','https://xlogs.com/api/v1/scan','xlogs',ORIGIN,json={'url':ORIGIN})
    assert caught.value.diagnostics['cooldown']['scope']=='target'
    await e.request('POST','https://xlogs.com/api/v1/scan','xlogs','https://other.example',json={'url':'https://other.example'});assert len(calls)==2

@pytest.mark.asyncio
async def test_unsent_permit_is_not_a_sent_counter_and_releases_without_target_debt(tmp_path):
    e=make(tmp_path,None);p=e.reserve('website_trigger',ORIGIN)
    assert quota(e,'website_trigger').get('sent_total',0)==0 and not quota(e,'website_trigger').get('attempts')
    e.quotas.release(p);again=e.reserve('website_trigger',ORIGIN);e.quotas.release(again)
    assert e.quotas.peek('website_trigger',ORIGIN)['eligible'] is True

@pytest.mark.asyncio
async def test_client_preparation_failure_does_not_consume_a_sent_request(tmp_path):
    e=make(tmp_path,None)
    def failed_client():raise RuntimeError('ISOLATED client configuration failure')
    e.client_factory=failed_client
    with pytest.raises(ProviderFailure) as caught:await run(e)
    assert caught.value.code=='dispatch_preparation_failed' and caught.value.diagnostics['dispatch']['requests_sent']==0
    assert not quota(e,'xlogs').get('attempts') and not e.store.read(e.quotas.path,{}).get('_pending')

@pytest.mark.asyncio
@pytest.mark.parametrize('error,expected_sent',[('ConnectTimeout',0),('PoolTimeout',0),('ReadTimeout',1),('ConnectError',0)])
async def test_timeout_and_connection_failures_track_actual_transport_stage(tmp_path,error,expected_sent):
    calls=[]
    async def handler(request):calls.append(request);raise getattr(httpx,error)('ISOLATED transport failure',request=request)
    e=make(tmp_path,handler)
    with pytest.raises(ProviderFailure) as caught:await run(e)
    assert len(calls)==1 and caught.value.diagnostics['dispatch']['requests_sent']==expected_sent
    assert quota(e,'xlogs').get('sent_total',0)==expected_sent and not e.store.read(e.quotas.path).get('_pending')

@pytest.mark.asyncio
async def test_transport_trace_counts_at_headers_sent_not_at_preparation(tmp_path):
    clock=Clock();observed=[]
    async def handler(request):
        observed.append(quota(e,'xlogs').get('sent_total',0));clock.advance(7)
        await request.extensions['trace']('http11.send_request_headers.started',{'headers':'DO NOT STORE'})
        await request.extensions['trace']('http11.send_request_headers.complete',{'headers':'DO NOT STORE'})
        observed.append(quota(e,'xlogs')['sent_total']);clock.advance(2)
        return httpx.Response(200,json=native_fixture('xlogs',ORIGIN))
    e=make(tmp_path,handler,clock=clock);start=clock();result=await run(e)
    assert observed==[0,1] and result['dispatch']['last_dispatched_at']==iso(start+7) and 'DO NOT STORE' not in json.dumps(result['dispatch'])

@pytest.mark.asyncio
async def test_uncertain_partial_write_is_not_a_confirmed_sent_count_or_blind_retry(tmp_path):
    calls=[]
    async def handler(request):
        calls.append(request);await request.extensions['trace']('http11.send_request_headers.started',{})
        raise httpx.WriteTimeout('ISOLATED partial write',request=request)
    e=make(tmp_path,handler)
    with pytest.raises(ProviderFailure) as caught:await run(e)
    d=caught.value.diagnostics['dispatch'];assert len(calls)==1 and d['request_sent'] is None and d['requests_sent']==0 and len(quota(e,'xlogs')['uncertain_attempts'])==1

@pytest.mark.asyncio
@pytest.mark.parametrize('status,payload,expected',[(429,{'code':'rate_limit_exceeded','error':'quota'},'upstream_rate_limit'),(503,{'error':'provider unavailable'},'provider_error'),(400,{'code':'invalid_url','error':'Invalid URL'},'invalid_target'),(422,{'error':{'code':'invalid_target','message':'URL must be public'}},'invalid_target')])
async def test_actual_status_and_error_body_are_preserved_and_classified(tmp_path,status,payload,expected):
    calls=[]
    async def handler(request):calls.append(request);return httpx.Response(status,json=payload)
    e=make(tmp_path,handler)
    with pytest.raises(ProviderFailure) as caught:await run(e)
    error=caught.value;assert len(calls)==1 and error.http_status==status and error.code==expected
    assert error.diagnostics['dispatch']['requests_sent']==1 and error.diagnostics['dispatch']['report_received'] is False
    row=error.diagnostics['dispatch']['requests'][0];assert row['endpoint']=='https://xlogs.com/api/v1/scan' and row['http_status']==status and row['response_category']==expected and row['elapsed_ms']>=0

@pytest.mark.asyncio
async def test_http200_api_error_is_not_a_received_report(tmp_path):
    async def handler(request):return httpx.Response(200,json={'ok':False,'code':'invalid_target','error':'Invalid URL'})
    e=make(tmp_path,handler)
    with pytest.raises(ProviderFailure) as caught:await run(e)
    assert caught.value.http_status==200 and caught.value.code=='invalid_target' and caught.value.diagnostics['dispatch']['report_received'] is False

@pytest.mark.asyncio
@pytest.mark.parametrize('body',[b'not JSON',b'{"score":NaN}'])
async def test_invalid_json_does_not_mark_report_received_or_get_cached(tmp_path,body):
    async def handler(request):return httpx.Response(200,content=body,headers={'Content-Type':'application/json'})
    e=make(tmp_path,handler)
    with pytest.raises(ProviderFailure) as caught:await run(e)
    assert caught.value.code=='invalid_json' and caught.value.http_status==200 and caught.value.diagnostics['dispatch']['request_sent'] is True and caught.value.diagnostics['dispatch']['report_received'] is False
    assert not e.store.read(e.quotas.path).get('_reports')

@pytest.mark.asyncio
async def test_http200_invalid_report_schema_still_is_not_received(tmp_path):
    async def handler(request):return httpx.Response(200,json={'ok':True,'not':'a scan report'})
    e=make(tmp_path,handler)
    with pytest.raises(SchemaChanged) as caught:await run(e)
    assert caught.value.dispatch['requests_sent']==1 and caught.value.dispatch['report_received'] is False and not e.store.read(e.quotas.path).get('_reports')

@pytest.mark.asyncio
async def test_bounded_cache_miss_polling_never_calls_trigger_twice_or_claims_a_report(tmp_path):
    calls=[];delays=[]
    async def sleeper(value):delays.append(value)
    e=make(tmp_path,auditor_handler(calls,999),sleeper=sleeper)
    with pytest.raises(ProviderFailure) as caught:await run(e,'website_auditor')
    error=caught.value;assert error.code=='report_not_generated' and len(calls)==7 and sum('/report/' in u for _,u in calls)==1
    assert sum(delays)==60 and error.diagnostics['dispatch']['requests_sent']==7 and error.diagnostics['dispatch']['scan_requests_sent']==1 and error.diagnostics['dispatch']['report_received'] is False
    assert error.retry_at==iso(e.clock()+3600) # deadline from sent trigger, never from the final miss

@pytest.mark.asyncio
async def test_true_auditor429_is_provider_wide_and_keeps_exact_retry_after(tmp_path):
    clock=Clock();calls=[]
    async def handler(request):calls.append(request);return httpx.Response(429,json={'error':'rate limit'},headers={'Retry-After':'600'})
    e=make(tmp_path,handler,clock=clock)
    with pytest.raises(ProviderFailure) as first:await run(e,'website_auditor')
    with pytest.raises(ProviderFailure) as second:await run(e,'website_auditor',origin='https://second.example')
    assert first.value.http_status==429 and second.value.state=='skipped_cooldown' and second.value.retry_at==first.value.retry_at and len(calls)==1

@pytest.mark.asyncio
async def test_http_date_retry_after_keeps_utc_offset_and_absolute_expiry(tmp_path):
    clock=Clock()
    async def handler(request):return httpx.Response(429,json={'error':'quota'},headers={'Retry-After':'Sat, 24 Oct 2026 19:00:00 GMT'})
    e=make(tmp_path,handler,clock=clock)
    with pytest.raises(ProviderFailure) as caught:await run(e)
    assert caught.value.retry_at=='2026-10-24T19:00:00+00:00'

@pytest.mark.asyncio
async def test_persisted_budget_survives_process_recreation_without_a_new_window(tmp_path):
    clock=Clock();calls=[]
    async def handler(request):calls.append(request);return httpx.Response(429,json={'error':'quota'},headers={'Retry-After':'30'})
    first=make(tmp_path,handler,clock=clock)
    with pytest.raises(ProviderFailure) as original:await run(first)
    clock.advance(5);second=make(tmp_path,handler,clock=clock)
    with pytest.raises(ProviderFailure) as blocked:await run(second)
    assert blocked.value.retry_at==original.value.retry_at and len(calls)==1
    clock.advance(26)
    with pytest.raises(ProviderFailure) as after:await run(second)
    assert after.value.http_status==429 and len(calls)==2

@pytest.mark.asyncio
async def test_legacy_actual_upstream_penalty_is_migrated_without_reset(tmp_path):
    clock=Clock();e=make(tmp_path,None,clock=clock)
    e.store.write(e.quotas.path,{'xlogs':{'attempts':[clock()-2],'blocked_until':clock()+120}})
    with pytest.raises(ProviderFailure) as caught:await run(e)
    assert caught.value.state=='skipped_cooldown' and caught.value.retry_at==iso(clock()+120)

@pytest.mark.asyncio
async def test_clock_rollback_and_corrupt_state_fail_explicitly_not_as_renewed_cooldown(tmp_path):
    clock=Clock();e=make(tmp_path,None,clock=clock);permit=e.reserve('xlogs',ORIGIN);e.quotas.release(permit);before=e.quotas.path.read_bytes();clock.advance(-100)
    with pytest.raises(ProviderFailure) as caught:await run(e)
    assert caught.value.code=='quota_state_invalid' and caught.value.retry_at is None and e.quotas.path.read_bytes()==before
    e.quotas.path.write_text('{broken JSON')
    with pytest.raises(ProviderFailure) as corrupt:await run(e)
    assert corrupt.value.code=='quota_state_invalid' and e.quotas.path.read_text()=='{broken JSON'

@pytest.mark.asyncio
async def test_naive_or_invalid_config_does_not_create_an_infinite_cooldown(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);return httpx.Response(200,json=native_fixture('xlogs',ORIGIN))
    e=make(tmp_path,handler,provider_cooldowns={'xlogs':'2099-01-01T00:00:00'}) # not an absolute UTC instant
    result=await run(e);assert len(calls)==1 and result['dispatch']['report_received'] is True and result['dispatch']['state_warnings']

@pytest.mark.asyncio
async def test_local_cached_report_does_not_refresh_cache_age_dispatch_or_sent_totals(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);return httpx.Response(200,json=native_fixture('xlogs',ORIGIN))
    e=make(tmp_path,handler);first=await run(e);first.pop('_cache_origin',None);e.store.put_cache('xlogs',ORIGIN,first)
    paths=list(e.store.cache.glob('*.json'));before=paths[0].read_bytes();qbefore=e.quotas.path.read_bytes();result=await run(e)
    assert len(calls)==1 and result['dispatch']['local_cache_hit'] and result['dispatch']['requests_sent']==0 and result['dispatch']['report_received'] is True
    assert paths[0].read_bytes()==before and e.quotas.path.read_bytes()==qbefore

@pytest.mark.asyncio
async def test_future_dated_local_cache_cannot_permanently_hide_a_needed_dispatch(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);return httpx.Response(200,json=native_fixture('xlogs',ORIGIN))
    e=make(tmp_path,handler);e.store.put_cache('xlogs',ORIGIN,{'native':native_fixture('xlogs',ORIGIN),'state':'completed'});path=next(e.store.cache.glob('*.json'));data=json.loads(path.read_text());data['stored_at']=datetime(2099,1,1,tzinfo=timezone.utc).timestamp();e.store.write(path,data)
    result=await run(e);assert len(calls)==1 and result['dispatch']['requests_sent']==1

@pytest.mark.asyncio
async def test_pending_permits_prevent_61_concurrent_dispatches_without_counting_skips(tmp_path):
    e=make(tmp_path,None);permits=[e.reserve('xlogs','https://'+str(i)+'.example') for i in range(60)]
    with pytest.raises(ProviderFailure) as caught:e.reserve('xlogs','https://extra.example')
    assert caught.value.state=='skipped_cooldown' and quota(e,'xlogs').get('sent_total',0)==0
    for p in permits:e.quotas.release(p)
    assert e.quotas.peek('xlogs')['eligible']

@pytest.mark.asyncio
async def test_one_provider_failure_does_not_block_other_providers_and_refresh_is_read_only(tmp_path):
    calls=[];clock=Clock()
    async def handler(request):
        calls.append(request)
        if request.url.host=='xlogs.com':return httpx.Response(429,json={'error':'quota'},headers={'Retry-After':'300'})
        if request.url.host=='websiteauditor.net':return httpx.Response(200,json=native_fixture('website_auditor',ORIGIN))
        if request.url.path=='/api/scan/start':return httpx.Response(200,json={'scanId':'a'*32})
        if request.url.host=='vibecheckscan.com':return httpx.Response(200,json={'status':'completed','result':native_fixture('vibe_check',ORIGIN)})
        return httpx.Response(200,json=native_fixture('mdn_observatory',ORIGIN))
    e=make(tmp_path,handler,clock=clock,allow_public_targets=True)
    async def validator(*args):return {'mode':'ISOLATED TEST','own_requests_ip_pinned':True}
    app=create_app(e.settings,manager=None);manager=app.state.manager;manager.engine=e;manager.store=e.store;manager.validator=validator
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://shield.test') as client:
            cfg=(await client.get('/api/config')).json();headers={'X-Client-Token':cfg['client_token'],'X-CSRF-Token':cfg['csrf'],'Origin':'https://shield.test'}
            response=await client.post('/api/scans',headers=headers,json={'target':ORIGIN,'mode':'live','authorized':True,'public_disclosure':True,'ai':False});assert response.status_code==202
            jid=response.json()['job']['id'];await asyncio.wait_for(manager.queue.join(),3);job=manager.store.get(jid)
            assert job['state']=='completed_with_warnings' and job['providers']['xlogs']['state']=='rate_limited'
            assert all(job['providers'][p]['state'] in ('completed','cached') for p in ('website_auditor','vibe_check','mdn_observatory'))
            events=(await client.get('/api/scans/'+jid+'/events',headers=headers)).json()['events'];assert any(event['details'].get('dispatch',{}).get('requests') for event in events)
            before=e.quotas.path.read_bytes();before_calls=len(calls)
            for _ in range(4):
                for suffix in ('','/report','/events','/providers/xlogs'):assert (await client.get('/api/scans/'+jid+suffix,headers=headers)).status_code==200
            assert e.quotas.path.read_bytes()==before and len(calls)==before_calls
            report=(await client.get('/api/scans/'+jid+'/report',headers=headers)).json();assert next(p for p in report['coverage'] if p['provider']=='xlogs')['dispatch']['request_sent'] is True


def artifact(until,observed,source='xlogs',status=429):return {'mode':'live','source':source,'reason_code':'upstream_rate_limit','http_status':status,'retry_at':until,'diagnostics':{'request_sent':True,'observed_at':observed}}
def test_release_manifest_does_not_fabricate_or_restart_a_cooldown_on_redeploy():
    now=datetime(2026,10,24,18,tzinfo=timezone.utc);until=(now+timedelta(hours=1)).isoformat();source=artifact(until,now.isoformat())
    old={'website_trigger':until,'vibe_start':until,'xlogs':until}
    first=build_manifest([source],old,now);later=build_manifest([source],first,now+timedelta(minutes=20))
    assert list(first)==['xlogs'] and first==later and first['xlogs']['until']==until
    assert build_manifest([source],first,now+timedelta(hours=2))=={}

def test_release_manifest_ignores_locally_skipped_attempt_and_fake_operator_penalty():
    now=datetime(2026,10,24,18,tzinfo=timezone.utc);d=artifact((now+timedelta(hours=1)).isoformat(),now.isoformat(),'website_auditor');d['diagnostics']['request_sent']=False
    assert build_manifest([d],{'website_trigger':'2099-01-01T00:00:00Z'},now)=={}

def test_release_manifest_preserves_a_genuine_website429_and_long_retry_after():
    now=datetime(2026,10,24,18,tzinfo=timezone.utc);d=artifact((now+timedelta(hours=3)).isoformat(),now.isoformat(),'website_auditor')
    result=build_manifest([d],now=now);assert result['website_auditor']['until']==d['retry_at']

def test_ui_has_explicit_dispatch_report_next_time_and_a_user_triggered_retry():
    root=Path(__file__).resolve().parents[1];js=(root/'static/main.js').read_text();html=(root/'static/index.html').read_text()
    for text in ('skipped_cooldown','HTTP requests sent:','Scan-start sent:','Valid report received:','Next attempt allowed:','configureRetry','requestSubmit()','serverOffset'):assert text in js
    assert 'id="retry-test"' in html and html.count('<input ')==1

@pytest.mark.asyncio
async def test_invalid_cached_schema_is_not_received_and_does_not_hide_network_dispatch(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);return httpx.Response(200,json=native_fixture('xlogs',ORIGIN))
    e=make(tmp_path,handler);e.store.put_cache('xlogs',ORIGIN,{'native':{'not':'a report'},'state':'completed'})
    result=await run(e);assert len(calls)==1 and result['dispatch']['report_received'] is True and result['dispatch']['requests_sent']==1
    assert any(x['state']=='cache_rejected' for x in result['dispatch']['events'])

@pytest.mark.asyncio
async def test_cooldown_after_success_is_based_on_actual_trigger_not_report_or_refresh(tmp_path):
    clock=Clock();calls=[]
    e=make(tmp_path,auditor_handler(calls),clock=clock)
    result=await run(e,'website_auditor');trigger_at=quota(e,'website_trigger')['last_dispatched_at']
    assert result['dispatch']['next_allowed_at']==iso(trigger_at+3600)
    assert result['dispatch']['report_received'] is True

@pytest.mark.asyncio
async def test_genuine_structured_website_penalty_blocks_reads_and_other_targets(tmp_path):
    clock=Clock();calls=[]
    async def handler(request):calls.append(request);raise AssertionError('No request permitted')
    hold={'until':iso(clock()+120),'observed_at':iso(clock()-5),'source':'upstream_429','http_status':429}
    e=make(tmp_path,handler,clock=clock,provider_cooldowns={'website_auditor':hold})
    with pytest.raises(ProviderFailure) as caught:await run(e,'website_auditor')
    assert not calls and caught.value.state=='skipped_cooldown' and caught.value.diagnostics['dispatch']['request_sent'] is False

@pytest.mark.asyncio
async def test_legacy_real_website_penalty_applies_to_cached_reads_not_just_triggers(tmp_path):
    clock=Clock();e=make(tmp_path,None,clock=clock)
    e.store.write(e.quotas.path,{'website_trigger':{'attempts':[clock()-5],'blocked_until':clock()+120}})
    with pytest.raises(ProviderFailure) as caught:await run(e,'website_auditor')
    assert caught.value.state=='skipped_cooldown' and caught.value.retry_at==iso(clock()+120)

@pytest.mark.asyncio
async def test_auditor_transient_read_retry_is_bounded_but_trigger_never_blind_retried(tmp_path):
    calls=[]
    async def handler(request):
        calls.append(request)
        if len(calls)==1:return httpx.Response(503,json={'error':'ISOLATED transient'})
        return httpx.Response(200,json=native_fixture('website_auditor',ORIGIN))
    e=make(tmp_path,handler);result=await run(e,'website_auditor');assert len(calls)==2 and all('/api/public/audit/' in r.url.path for r in calls) and result['dispatch']['scan_requests_sent']==0
    calls.clear()
    async def fail_trigger(request):
        calls.append(request)
        return httpx.Response(404,json={'error':'missing'}) if '/api/public/audit/' in request.url.path else httpx.Response(503,json={'error':'ISOLATED trigger failure'})
    e.client_factory=lambda:httpx.AsyncClient(transport=httpx.MockTransport(fail_trigger))
    with pytest.raises(ProviderFailure):await run(e,'website_auditor')
    assert sum('/report/' in r.url.path for r in calls)==1

@pytest.mark.asyncio
async def test_auditor_invalid_json_cache_response_does_not_trigger_or_receive_report(tmp_path):
    calls=[]
    async def handler(request):calls.append(request);return httpx.Response(200,text='not JSON',headers={'Content-Type':'application/json'})
    e=make(tmp_path,handler)
    with pytest.raises(ProviderFailure) as caught:await run(e,'website_auditor')
    assert caught.value.code=='invalid_json' and len(calls)==1 and caught.value.diagnostics['dispatch']['report_received'] is False
    assert not quota(e,'website_trigger').get('attempts')

@pytest.mark.asyncio
async def test_auditor_trigger429_blocks_future_reads_without_extending_deadline(tmp_path):
    clock=Clock();calls=[]
    async def handler(request):
        calls.append(request)
        return httpx.Response(404,json={'error':'missing'}) if '/api/public/audit/' in request.url.path else httpx.Response(429,json={'error':'quota'},headers={'Retry-After':'600'})
    e=make(tmp_path,handler,clock=clock)
    with pytest.raises(ProviderFailure) as first:await run(e,'website_auditor')
    deadline=first.value.retry_at;snapshot=e.quotas.path.read_bytes();clock.advance(5)
    with pytest.raises(ProviderFailure) as second:await run(e,'website_auditor',origin='https://another.example')
    assert first.value.http_status==429 and second.value.state=='skipped_cooldown' and second.value.retry_at==deadline
    assert len(calls)==2 and e.quotas.path.read_bytes()==snapshot and quota(e,'website_trigger')['sent_total']==1

@pytest.mark.asyncio
@pytest.mark.parametrize('kind,sent',[('ReadTimeout',True),('ConnectTimeout',False)])
async def test_auditor_trigger_timeout_never_blind_retries_or_stamps_unsent_target(tmp_path,kind,sent):
    calls=[]
    async def handler(request):
        calls.append(request)
        if '/api/public/audit/' in request.url.path:return httpx.Response(404,json={'error':'missing'})
        raise getattr(httpx,kind)('ISOLATED trigger timeout',request=request)
    e=make(tmp_path,handler)
    with pytest.raises(ProviderFailure) as caught:await run(e,'website_auditor')
    d=caught.value.diagnostics['dispatch'];assert len(calls)==2 and d['scan_request_sent'] is sent and d['report_received'] is False
    assert quota(e,'website_trigger').get('sent_total',0)==int(sent)
    if not sent:
        p=e.reserve('website_trigger',ORIGIN);e.quotas.release(p) # No invented hour from an unsent trigger.

"""Isolated real-only UI/API contracts. Injected adapters below never contact a website.
They verify production routing, not live scanner results, and are not hosted demos.
"""
import asyncio,json
from pathlib import Path
import httpx,pytest,pytest_asyncio
from app import create_app
from shield.models import Settings,ScanRequest,utcnow
from shield.harness import JobManager
from shield.providers import ProviderEngine
from shield.fixtures import native_fixture
from shield.safety import validate_live

ROOT=Path(__file__).resolve().parents[1]

@pytest_asyncio.fixture
async def public_app(tmp_path):
    settings=Settings(data_dir=tmp_path,gemini_key='',allow_mock=False,allow_public_targets=True,live_targets=('https://fixed-owner.example',),mock_delay=0)
    manager=JobManager(settings);calls=[];ai_calls=[];validations=[]
    async def validate(target,allowed):
        validations.append((target.origin,allowed));return {'scope':target.origin,'isolated_test_transport':True}
    async def run(name,target,mode,scenario,progress,packages=None):
        assert mode=='live';calls.append((name,target.origin,mode))
        native=native_fixture(name,target.origin,scenario)
        return ProviderEngine(settings,manager.store).result(name,native,utcnow(),mode)
    async def explain(report,settings,force_mock=False):
        assert force_mock is False;ai_calls.append(report)
        return {'state':'completed','model':'isolated-test-adapter','data':{'summary':'ISOLATED CONTRACT FIXTURE — not a live website result.','analysis':[],'limitations':['Isolated test only.']}}
    manager.validator=validate;manager.engine.run=run;manager.ai_function=explain
    app=create_app(settings,manager)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='https://shield.test') as client:
            config=(await client.get('/api/config')).json();headers={'X-Client-Token':config['client_token'],'X-CSRF-Token':config['csrf'],'Origin':'https://shield.test'}
            yield app,client,headers,calls,ai_calls,validations

def payload(**extra):
    return {'target':'https://customer-owned.example/path?not-forwarded=yes','authorized':True,'public_disclosure':True,'consent_method':'click_through',**extra}

async def finish(ctx,response):
    assert response.status_code==202,response.text
    app,client,headers,*_=ctx;jid=response.json()['job']['id'];await asyncio.wait_for(app.state.manager.queue.join(),3)
    return (await client.get('/api/scans/'+jid,headers=headers)).json(),(await client.get('/api/scans/'+jid+'/report',headers=headers)).json()

def test_default_request_is_live_with_ai():
    spec=ScanRequest(**payload());assert spec.mode=='live' and spec.ai is True and spec.consent_method=='click_through'

@pytest.mark.asyncio
async def test_public_config_does_not_advertise_test_scenarios(public_app):
    _,client,_,*_=public_app;data=(await client.get('/api/config')).json()
    assert data['execution_mode']=='live' and data['public_targets_enabled'] is True
    assert data['mock_execution_enabled'] is False and 'scenarios' not in data

@pytest.mark.asyncio
async def test_production_rejects_mock_post_even_with_valid_session(public_app):
    app,client,headers,calls,ai_calls,_=public_app
    response=await client.post('/api/scans',json=payload(mode='mock'),headers=headers)
    assert response.status_code==422 and not app.state.manager.store.all_jobs() and not calls and not ai_calls

@pytest.mark.asyncio
async def test_public_url_runs_live_and_ai_automatically_without_fixed_allowlist(public_app):
    app,client,headers,calls,ai_calls,validations=public_app
    # Even an API caller cannot turn off the automatic public AI step.
    response=await client.post('/api/scans',json=payload(ai=False),headers=headers);job,report=await finish(public_app,response)
    assert job['mode']=='live' and job['ai_enabled'] is True and job['consent_method']=='click_through'
    assert job['target']=='https://customer-owned.example' and len(calls)==5 and len(ai_calls)==1
    assert validations==[('https://customer-owned.example',('https://customer-owned.example',))]
    assert report['synthetic'] is False and report['ai']['state']=='completed' and report['consent_method']=='click_through'

@pytest.mark.asyncio
@pytest.mark.parametrize('extra',[{'authorized':False},{'public_disclosure':False}])
async def test_click_through_still_requires_explicit_permission_and_disclosure(public_app,extra):
    app,client,headers,calls,_,_=public_app
    response=await client.post('/api/scans',json=payload(**extra),headers=headers)
    assert response.status_code==422 and not app.state.manager.store.all_jobs() and not calls

@pytest.mark.asyncio
@pytest.mark.parametrize('target',['http://127.0.0.1','http://169.254.169.254','http://10.1.1.1','http://[::1]','http://website.local'])
async def test_public_input_does_not_allow_private_targets(public_app,target):
    app,client,headers,calls,_,_=public_app
    response=await client.post('/api/scans',json=payload(target=target),headers=headers)
    assert response.status_code==422 and not app.state.manager.store.all_jobs() and not calls

@pytest.mark.asyncio
@pytest.mark.parametrize('ips',[['127.0.0.1'],['169.254.169.254'],['1.1.1.1','10.0.0.1']])
async def test_public_input_still_rejects_private_or_mixed_dns_before_providers(public_app,ips):
    app,client,headers,calls,_,_=public_app
    async def resolver(*args):return ips
    async def validate(target,allowed):return await validate_live(target,allowed,resolver=resolver)
    app.state.manager.validator=validate
    response=await client.post('/api/scans',json=payload(),headers=headers);job,report=await finish(public_app,response)
    assert job['state']=='failed' and not calls and report['security_guarantee'] is False
    assert any('DNS resolved to a private' in x for x in report['warnings'])

@pytest.mark.asyncio
async def test_public_submissions_do_not_follow_an_unapproved_redirect(public_app):
    app,client,headers,calls,_,_=public_app;requests=[]
    async def resolver(*args):return ['1.1.1.1']
    async def handler(request):requests.append(request);return httpx.Response(302,headers={'Location':'https://different-origin.example/'})
    async def validate(target,allowed):return await validate_live(target,allowed,resolver=resolver,transport=httpx.MockTransport(handler))
    app.state.manager.validator=validate
    response=await client.post('/api/scans',json=payload(),headers=headers);job,_=await finish(public_app,response)
    assert job['state']=='failed' and not calls and len(requests)==1 and requests[0].method=='HEAD'

@pytest.mark.asyncio
async def test_operator_can_still_restrict_public_submissions(public_app):
    app,client,headers,calls,_,_=public_app;app.state.settings.allow_public_targets=False
    response=await client.post('/api/scans',json=payload(),headers=headers)
    assert response.status_code==422 and not calls

@pytest.mark.asyncio
async def test_home_page_is_only_link_test_then_hidden_report_cards(public_app):
    _,client,_,*_=public_app;html=(await client.get('/')).text.lower()
    assert html.count('<input ')==1 and 'id="test-button"' in html and '>test</button>' in html
    assert '<select' not in html and 'type="checkbox"' not in html and '<pre' not in html
    assert 'mock' not in html and 'scenario' not in html and 'execution mode' not in html
    assert 'id="report"' in html and 'id="finding-cards"' in html and 'id="test-form"' in html
    js=(ROOT/'static/main.js').read_text()
    assert "mode:'live',ai:true,authorized:true,public_disclosure:true,consent_method:'click_through'" in js
    assert '.innerHTML' not in js and "data.synthetic!==false" in js

@pytest.mark.asyncio
async def test_report_export_has_readable_ai_overview_and_escapes_it(public_app):
    app,client,headers,_,_,_=public_app
    response=await client.post('/api/scans',json=payload(),headers=headers);_,report=await finish(public_app,response)
    report['ai']['data']['summary']='Review <script>alert(1)</script> before changing anything.'
    html=app.state.manager.render_html(report)
    assert '<h2>AI overview</h2>' in html and 'Verify first' in html and 'Source evidence and confidence' in html
    assert '<script>' not in html and '&lt;script&gt;' in html and 'promptTokenCount' not in html

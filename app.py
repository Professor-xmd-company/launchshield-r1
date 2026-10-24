from __future__ import annotations
import asyncio,hmac,hashlib,secrets,json,time,os
from pathlib import Path
from contextlib import asynccontextmanager
from urllib.parse import urlsplit
from fastapi import FastAPI,Request,HTTPException
from fastapi.responses import FileResponse,JSONResponse
from fastapi.staticfiles import StaticFiles
from shield.models import Settings,ScanRequest,PROVIDERS,SCENARIOS
from shield.harness import JobManager,JobConflict
from shield.safety import TargetRejected
from shield.persistence import hash_token

ROOT=Path(__file__).resolve().parent

def create_app(settings=None,manager=None):
    settings=settings or Settings();manager=manager or JobManager(settings)
    @asynccontextmanager
    async def lifespan(app):
        await manager.start();yield;await manager.close()
    app=FastAPI(title='LaunchShield R1',docs_url=None,redoc_url=None,openapi_url=None,lifespan=lifespan)
    app.state.manager=manager;app.state.settings=settings
    def signature(sid):return hmac.new(manager.store.secret,('client:'+sid).encode(),hashlib.sha256).hexdigest()
    def identify(request):
        token=request.headers.get('X-Client-Token') or request.cookies.get('ls_client','')
        try:
            sid,sig=token.split('.',1)
            if len(sid)==64 and hmac.compare_digest(signature(sid),sig):return sid
        except ValueError:pass
        return None
    def csrf(sid):return hmac.new(manager.store.secret,('csrf:'+sid).encode(),hashlib.sha256).hexdigest()
    def require_mutation(request):
        sid=identify(request)
        if not sid or not hmac.compare_digest(request.headers.get('X-CSRF-Token',''),csrf(sid)):raise HTTPException(403,'Page session is missing or changed. Reload the page.')
        return sid
    def access(request,jid):
        try:job=manager.store.get(jid)
        except KeyError:raise HTTPException(404,'Job unavailable: it may have expired or local files may have been lost after restart/redeploy.') from None
        sid=identify(request);cap=request.headers.get('X-Job-Token','')
        own=sid is not None and hmac.compare_digest(job['owner_hash'],hash_token(sid))
        delegated=bool(cap) and hmac.compare_digest(job['access_hash'],hash_token(cap))
        if not (own or delegated):raise HTTPException(404,'Job not available to this browser session.')
        return job
    attempts={}
    @app.middleware('http')
    async def protections(request,call_next):
        if request.method in ('POST','PUT','PATCH','DELETE'):
            origin=request.headers.get('Origin')
            if origin and urlsplit(origin).netloc.lower()!=request.headers.get('host','').lower():return JSONResponse({'detail':'Cross-origin mutation rejected.'},403)
            if 'application/json' not in request.headers.get('content-type',''):return JSONResponse({'detail':'Use application/json.'},415)
            body=bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body)>32_768:return JSONResponse({'detail':'Request is too large.'},413)
            request._body=bytes(body)
        response=await call_next(request)
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Referrer-Policy']='no-referrer'
        response.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
        response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
        if os.environ.get('LAUNCHSHIELD_EMBED_PREVIEW')=='1':response.headers['Content-Security-Policy']=response.headers['Content-Security-Policy'].replace("frame-ancestors 'none'","frame-ancestors *")
        response.headers['Strict-Transport-Security']='max-age=86400'
        response.headers['Cache-Control']='no-store' if request.url.path.startswith('/api/') else 'no-cache'
        return response
    @app.api_route('/',methods=['GET','HEAD'])
    async def index():return FileResponse(ROOT/'static/index.html',media_type='text/html')
    @app.get('/healthz')
    async def health():return {'ok':manager.worker is not None and not manager.worker.done(),'revision':'R1','accounts':False,'database':False,'storage':'temporary files','gemini_configured':bool(settings.gemini_key)}
    @app.get('/robots.txt')
    async def robots():
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse('User-agent: *\nDisallow: /\n')
    @app.get('/api/config')
    async def config(request:Request):
        sid=identify(request) or secrets.token_hex(32);token=sid+'.'+signature(sid)
        response=JSONResponse({'revision':'R1','client_token':token,'csrf':csrf(sid),'gemini_configured':bool(settings.gemini_key),'gemini_model':settings.gemini_model,'live_targets':list(settings.live_targets),'scenarios':list(SCENARIOS),'retention_seconds':settings.retention_seconds,'limitations':'No database. Files/jobs can be lost on sleep/restart/redeploy. No security guarantee.'})
        response.set_cookie('ls_client',token,httponly=True,secure=True,samesite='strict',max_age=86400,path='/')
        return response
    @app.post('/api/scans')
    async def submit(spec:ScanRequest,request:Request):
        sid=require_mutation(request);key=hash_token((request.client.host if request.client else 'local'))
        now=time.monotonic();recent=[x for x in attempts.get(key,[]) if now-x<60]
        if len(recent)>=20:return JSONResponse({'detail':'Local submission limit reached; wait before retrying.'},429,headers={'Retry-After':'60'})
        attempts[key]=recent+[now]
        try:job,token,reused=await manager.create(spec,hash_token(sid))
        except TargetRejected as e:raise HTTPException(422,str(e)) from None
        except JobConflict as e:raise HTTPException(409,str(e)) from None
        return JSONResponse({'job':job,'job_token':token,'deduplicated':reused},200 if reused else 202)
    @app.get('/api/scans/{jid}')
    async def status(jid:str,request:Request):return manager.public(access(request,jid))
    @app.get('/api/scans/{jid}/events')
    async def events(jid:str,request:Request):
        access(request,jid);p=manager.store.job_dir(jid)/'events.jsonl'
        lines=p.read_text().splitlines() if p.exists() else []
        return {'events':[json.loads(line) for line in lines[-200:]]}
    @app.get('/api/scans/{jid}/findings')
    async def findings(jid:str,request:Request):
        job=access(request,jid);return {'ready':job['report_available'],'findings':manager.store.read(manager.store.job_dir(jid)/'findings.json',[])}
    @app.get('/api/scans/{jid}/report')
    async def report(jid:str,request:Request,format:str='json',download:bool=False):
        job=access(request,jid)
        if not job['report_available']:raise HTTPException(409,'Report is not ready yet.')
        if format not in ('json','html'):raise HTTPException(422,'Supported exports are JSON and HTML.')
        path=manager.store.job_dir(jid)/('report.'+format)
        if not path.exists():raise HTTPException(404,'Report file is unavailable.')
        if format=='json' and not download:return manager.store.read(path)
        manager.store.event(jid,'report_download',{'format':format})
        return FileResponse(path,media_type='application/json' if format=='json' else 'text/html',filename='launchshield-R1-'+jid+'.'+format)
    @app.get('/api/scans/{jid}/providers/{provider}')
    async def provider(jid:str,provider:str,request:Request):
        access(request,jid)
        if provider not in PROVIDERS:raise HTTPException(404,'Unknown provider.')
        value=manager.store.read(manager.store.job_dir(jid)/'providers'/(provider+'.json'))
        if value is None:raise HTTPException(404,'Provider artifact is not available yet.')
        return value
    @app.post('/api/scans/{jid}/cancel')
    async def cancel(jid:str,request:Request):
        require_mutation(request);access(request,jid)
        return await manager.cancel(jid)
    app.mount('/static',StaticFiles(directory=ROOT/'static'),name='static')
    return app

app=create_app()

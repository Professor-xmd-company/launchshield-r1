from __future__ import annotations
import json,os,re,secrets,hashlib,threading,shutil,math
from pathlib import Path
from datetime import datetime,timezone
from .models import PROVIDERS,TERMINAL,utcnow

_SECRET_PATTERNS=[r'-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----',r'\b(?:AIza|AQ\.|github_pat_|ghp_|vcp_|sk-|sb_secret_)[A-Za-z0-9_.-]{16,}',r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',r'(?i)(?:bearer\s+)[A-Za-z0-9_.-]{12,}']
def redact(value):
    if isinstance(value,dict):
        return {str(k):('[REDACTED]' if re.search(r'(?i)(?:password|api[_-]?key|auth[_-]?token|authorization|private[_-]?key|service[_-]?role)',str(k)) and not isinstance(v,(bool,int,float,type(None))) else redact(v)) for k,v in value.items()}
    if isinstance(value,list):return [redact(x) for x in value]
    if isinstance(value,str):
        for pattern in _SECRET_PATTERNS:value=re.sub(pattern,'[REDACTED]',value)
        value=re.sub(r'(?i)(postgres(?:ql)?://[^:\s]+:)[^@\s]+',r'\1[REDACTED]',value)
        value=re.sub(r'(?i)((?:password|api[_-]?key|access[_-]?token|auth[_-]?token|secret)\s*[:=]\s*)[^\s,;\"\']+',r'\1[REDACTED]',value)
        return value
    return value

def hash_token(value):return hashlib.sha256(value.encode()).hexdigest()

class FileStore:
    def __init__(self,root:Path):
        self.root=Path(root);self.jobs=self.root/'jobs';self.cache=self.root/'cache';self.lock=threading.RLock()
        for p in (self.root,self.jobs,self.cache):p.mkdir(parents=True,exist_ok=True);p.chmod(0o700)
        secret=self.root/'.session-key'
        try:
            fd=os.open(secret,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as f:f.write(secrets.token_bytes(32));f.flush();os.fsync(f.fileno())
        except FileExistsError:pass
        self.secret=secret.read_bytes()
        if len(self.secret)!=32:raise RuntimeError('Session signing key is invalid.')
    def job_dir(self,jid):
        if not re.fullmatch(r'[a-f0-9]{32}',str(jid)):raise KeyError('Invalid job identifier')
        return self.jobs/jid
    def write(self,path:Path,value):
        with self.lock:
            path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            temporary=path.with_name(path.name+'.'+secrets.token_hex(6)+'.tmp')
            fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as f:json.dump(value,f,ensure_ascii=False,allow_nan=False);f.flush();os.fsync(f.fileno())
            os.replace(temporary,path)
    def read(self,path,default=None):
        with self.lock:
            try:return json.loads(Path(path).read_text())
            except FileNotFoundError:return default
    def create(self,job):
        path=self.job_dir(job['id']);path.mkdir(mode=0o700)
        self.write(path/'job.json',job);self.event(job['id'],'job_created',{'mode':job['mode'],'authorization':'self_declared','target':job['target']})
    def get(self,jid):
        job=self.read(self.job_dir(jid)/'job.json')
        if job is None:raise KeyError('Job unavailable: it may have expired or local files may have been lost after restart/redeploy.')
        return job
    def update(self,jid,**values):
        with self.lock:
            job=self.get(jid);job.update(values,updated_at=utcnow());self.write(self.job_dir(jid)/'job.json',job);return job
    def provider(self,jid,name,**values):
        if name not in PROVIDERS:raise KeyError('Unknown provider')
        with self.lock:
            job=self.get(jid);job['providers'][name].update(values,updated_at=utcnow());job['updated_at']=utcnow();self.write(self.job_dir(jid)/'job.json',job)
            detail={'provider':name,'state':job['providers'][name]['state'],'detail':job['providers'][name].get('message','')}
            if 'dispatch' in values:detail['dispatch']=values['dispatch']
            self.event(jid,'provider_state',detail)
    def artifact(self,jid,name,value):
        if name not in PROVIDERS:raise KeyError('Unknown provider')
        self.write(self.job_dir(jid)/'providers'/f'{name}.json',redact(value))
        with self.lock:
            job=self.get(jid);job['providers'][name]['artifact_available']=True;self.write(self.job_dir(jid)/'job.json',job)
    def event(self,jid,kind,details):
        with self.lock:
            path=self.job_dir(jid)/'events.jsonl';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
            with os.fdopen(fd,'a') as f:f.write(json.dumps({'at':utcnow(),'event':kind,'details':redact(details)},ensure_ascii=False)+'\n')
    def all_jobs(self):
        return [self.read(p) for p in self.jobs.glob('*/job.json') if self.read(p) is not None]
    def cached(self,provider,origin,max_age):
        key=hash_token(provider+'|'+origin);value=self.read(self.cache/(key+'.json'))
        if not value:return None
        try:age=datetime.now(timezone.utc).timestamp()-float(value['stored_at'])
        except (KeyError,ValueError,TypeError):return None
        return value.get('value') if math.isfinite(age) and 0<=age<max_age else None
    def put_cache(self,provider,origin,value):
        self.write(self.cache/(hash_token(provider+'|'+origin)+'.json'),{'stored_at':datetime.now(timezone.utc).timestamp(),'value':redact(value)})
    def cleanup(self,retention):
        removed=[];now=datetime.now(timezone.utc).timestamp()
        for job in self.all_jobs():
            finished=job.get('completed_at')
            if job['state'] in TERMINAL and finished and now-datetime.fromisoformat(finished).timestamp()>retention:
                shutil.rmtree(self.job_dir(job['id']));removed.append(job['id'])
        return removed

'use strict';
const $=id=>document.getElementById(id);let config=null,current=null,report=null,timer=null,loading=false;
const terminal=new Set(['completed','completed_with_warnings','failed','cancelled','expired']);
const names={website_auditor:'Website Auditor',xlogs:'xlogs',vibe_check:'Vibe Check Scan',mdn_observatory:'MDN Observatory',osv:'OSV.dev'};
function node(tag,text){const el=document.createElement(tag);if(text!==undefined)el.textContent=String(text);return el;}
function displayTime(value){if(typeof value==='number'){const date=new Date(value>1e12?value:value*1000);return Number.isNaN(date.getTime())?String(value):date.toISOString()}return String(value)}
function saved(){try{return JSON.parse(sessionStorage.getItem('ls_last')||'null')}catch{return null}}
function remember(value){current=value;sessionStorage.setItem('ls_last',JSON.stringify(value));$('resume').disabled=false;}
function showError(message){$('error').hidden=!message;$('error').textContent=message||'';}
async function api(path,options={}){
  const headers={'X-Client-Token':config?.client_token||'',...options.headers};
  if(current?.token)headers['X-Job-Token']=current.token;
  if(options.method==='POST'){headers['Content-Type']='application/json';headers['X-CSRF-Token']=config?.csrf||'';}
  const response=await fetch('/api'+path,{...options,headers,credentials:'same-origin'});
  if(!response.ok){let body;try{body=await response.json()}catch{body={detail:'HTTP '+response.status}}throw new Error(typeof body.detail==='string'?body.detail:JSON.stringify(body.detail));}
  return response.json();
}
function modeChanged(){
  const live=$('mode').value==='live';$('scenario-field').hidden=live;$('disclosure').required=live;
  $('mode-note').textContent=live?'REAL MODE: only server-owner allowlisted origins are accepted. Third-party scans may be public/cached; failures reduce coverage.':'MOCK MODE: all findings are synthetic fixtures. No website or scanner provider is contacted.';
  if(live&&config?.live_targets.length&&$('target').value==='https://demo.example')$('target').value=config.live_targets[0];
}
$('mode').addEventListener('change',modeChanged);
async function watchCurrent(){clearInterval(timer);timer=setInterval(refresh,1000);await refresh();}
async function refresh(){
  if(!current||loading)return;loading=true;
  try{
    const job=await api('/scans/'+current.id);showError('');
    $('job-summary').textContent=(job.mode==='mock'?'MOCK FIXTURES · ':'REAL PROVIDER JOB · ')+job.target+' · '+job.state+' · ID '+job.id+(job.state==='queued'?' · queue position at submission '+job.queue_position:'');
    $('cancel').disabled=terminal.has(job.state);$('start').disabled=!terminal.has(job.state);$('refresh').disabled=false;
    const tbody=$('providers');tbody.replaceChildren();
    for(const [name,p] of Object.entries(job.providers)){
      const tr=node('tr');tr.append(node('td',names[name]||name),node('td',p.state));
      const detail=node('td',p.message||'');
      for(const [key,label] of [['scanned_at','Provider scan'],['cached_at','Provider cache'],['retry_at','Retry allowed after']])if(p[key]!==undefined&&p[key]!==null)detail.append(node('p',label+': '+displayTime(p[key])));
      if(p.external_scan_id)detail.append(node('p','External scan ID recorded.'));
      tr.append(detail);const cell=node('td');const b=node('button','View JSON');b.disabled=!p.artifact_available;
      b.addEventListener('click',async()=>{try{$('evidence').textContent=JSON.stringify(await api('/scans/'+current.id+'/providers/'+name),null,2);$('evidence').parentElement.open=true}catch(e){showError(e.message)}});cell.append(b);tr.append(cell);tbody.append(tr);
    }
    const events=await api('/scans/'+current.id+'/events');$('events').textContent=events.events.map(e=>e.at+' '+e.event+' '+JSON.stringify(e.details)).join('\n');
    $('json').disabled=$('html').disabled=!job.report_available;
    if(job.report_available){report=await api('/scans/'+current.id+'/report');renderFindings();$('ai-result').textContent=JSON.stringify(report.ai,null,2);$('result-summary').textContent=(report.synthetic?'SYNTHETIC REPORT — not a real assessment. ':'')+report.findings.length+' grouped finding(s), '+report.original_finding_records.length+' original provider record(s). Coverage: '+JSON.stringify(report.coverage_counts)+'. No overall security score or guarantee.';}
    else{$('result-summary').textContent='Report is not ready. Provider states above are actual stages, not simulated percentages.';}
    if(terminal.has(job.state)){clearInterval(timer);timer=null;$('start').disabled=false;$('submit-status').textContent='Job finished: '+job.state;}
  }catch(e){showError(e.message);clearInterval(timer);timer=null;$('start').disabled=false;$('cancel').disabled=true;}
  finally{loading=false;}
}
function renderFindings(){
  $('findings').replaceChildren();if(!report)return;
  const rows=report.findings.filter(f=>$('severity').value==='all'||f.severity===$('severity').value);
  if(!rows.length){$('findings').append(node('p','No matching reported findings. This is not proof that the target is secure; review provider coverage.'));return;}
  for(const f of rows){const section=node('article');section.className='finding';section.append(node('h3',f.title),node('p','Severity: '+f.severity+' · Confidence: '+JSON.stringify(f.confidence)+' · Sources: '+f.sources.map(s=>names[s.provider]||s.provider).join(', ')));
    const details=node('details');details.append(node('summary','Evidence, native severities and remediation'));details.append(node('pre',JSON.stringify(f,null,2)));section.append(details);$('findings').append(section);}
}
$('severity').addEventListener('change',renderFindings);
$('scan-form').addEventListener('submit',async event=>{
  event.preventDefault();showError('');$('start').disabled=true;$('submit-status').textContent='Submitting…';report=null;$('findings').replaceChildren();$('ai-result').textContent='Not run.';$('json').disabled=$('html').disabled=true;
  try{
    const result=await api('/scans',{method:'POST',body:JSON.stringify({target:$('target').value,mode:$('mode').value,scenario:$('mode').value==='mock'?$('scenario').value:'success',authorized:$('authorized').checked,public_disclosure:$('disclosure').checked,ai:$('ai').checked})});
    const old=saved();remember({id:result.job.id,token:result.job_token||(old?.id===result.job.id?old.token:null)});
    $('submit-status').textContent=result.deduplicated?'Existing job reused; no duplicate provider start.':'Job created.';await watchCurrent();
  }catch(e){showError(e.message);$('start').disabled=false;$('submit-status').textContent='Request not started.';}
});
$('refresh').addEventListener('click',refresh);
$('resume').addEventListener('click',async()=>{const old=saved();if(old){current=old;await watchCurrent()}});
$('cancel').addEventListener('click',async()=>{try{await api('/scans/'+current.id+'/cancel',{method:'POST',body:'{}'});$('submit-status').textContent='Cancellation requested. External work may still continue.';await refresh()}catch(e){showError(e.message)}});
async function download(format){
  try{const response=await fetch('/api/scans/'+current.id+'/report?format='+format+'&download=true',{headers:{'X-Client-Token':config.client_token,'X-Job-Token':current.token||''},credentials:'same-origin'});if(!response.ok)throw new Error('Download failed: HTTP '+response.status);const url=URL.createObjectURL(await response.blob());const a=node('a');a.href=url;a.download='LaunchShield-R1-'+current.id+'.'+format;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000)}catch(e){showError(e.message)}
}
$('json').addEventListener('click',()=>download('json'));$('html').addEventListener('click',()=>download('html'));
(async()=>{try{const token=sessionStorage.getItem('ls_client')||'';const response=await fetch('/api/config',{headers:{'X-Client-Token':token},credentials:'same-origin'});if(!response.ok)throw new Error('Configuration unavailable.');config=await response.json();sessionStorage.setItem('ls_client',config.client_token);$('configuration').textContent='Gemini: '+(config.gemini_configured?config.gemini_model+' configured':'not configured')+'. Live allowlist: '+(config.live_targets.join(', ')||'not configured; mock mode is available')+'.';$('resume').disabled=!saved();$('start').disabled=false;modeChanged();const old=saved();if(old){current=old;await watchCurrent();}}catch(e){showError(e.message);$('start').disabled=true;}})();

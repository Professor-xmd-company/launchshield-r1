'use strict';
const $=id=>document.getElementById(id);
const finished=new Set(['completed','completed_with_warnings','failed','cancelled','expired']);
const received=new Set(['completed','cached','stale_result']);
const providerNames={website_auditor:'Website Auditor',xlogs:'xlogs',vibe_check:'Vibe Check',mdn_observatory:'MDN Observatory',osv:'Package advisories'};
let config=null,current=null,timer=null,polling=false,busy=false,version=0,readFailures=0,renderedId=null;
const element=(tag,text,className)=>{const e=document.createElement(tag);if(text!==undefined)e.textContent=String(text);if(className)e.className=className;return e;};
function getStored(key){try{return sessionStorage.getItem(key)}catch{return null}}
function setStored(key,value){try{if(value===null)sessionStorage.removeItem(key);else sessionStorage.setItem(key,value)}catch{}}
function saved(){try{return JSON.parse(getStored('ls_last')||'null')}catch{return null}}
function remember(job,token){current={id:job.id,token:token||null,target:job.target};setStored('ls_last',JSON.stringify(current));}
function error(message){$('form-error').textContent=message||'';$('form-error').hidden=!message;}
function setBusy(value){busy=value;$('test-button').disabled=value||!config;$('test-button').textContent=value?'Testing…':'Test';$('website').disabled=value;$('test-form').setAttribute('aria-busy',String(value));}
function clearPoll(){clearTimeout(timer);timer=null;}
function schedule(v,delay=1500){clearPoll();timer=setTimeout(()=>refresh(v),delay);}
async function api(path,options={}){
  const headers={'X-Client-Token':config?.client_token||'',...options.headers};
  if(current?.token)headers['X-Job-Token']=current.token;
  if(options.method==='POST'){headers['Content-Type']='application/json';headers['X-CSRF-Token']=config?.csrf||'';}
  const response=await fetch('/api'+path,{...options,headers,credentials:'same-origin'});
  if(!response.ok){let body;try{body=await response.json()}catch{body={}}const e=new Error(typeof body.detail==='string'?body.detail:'The request could not be completed. Check the website link and try again.');e.status=response.status;throw e;}
  return response.json();
}
function normalizeLink(value){const text=value.trim();if(!text)throw new Error('Enter the website link you want to test.');return /^[a-z][a-z0-9+.-]*:/i.test(text)?text:'https://'+text;}
function showProgress(job){
  $('progress').hidden=false;
  let title='Checking your website…',message='Real website checks are running. Your AI report will appear here automatically.';
  if(job.state==='queued'){title='Your test is queued';message='The test will start automatically when the current check finishes.';}
  if(job.state==='validating'){title='Connecting to your website…';message='Checking that the link is a reachable public website.';}
  if(job.state==='normalizing'||job.state==='analyzing'){title='Preparing your AI report…';message='The website checks have finished. Turning the available evidence into a readable report.';}
  $('progress-title').textContent=title;$('progress-message').textContent=message;
}
function dateLabel(value){if(value===undefined||value===null)return null;const d=new Date(typeof value==='number'?(value>1e12?value:value*1000):value);return Number.isNaN(d.getTime())?null:d.toLocaleString(undefined,{dateStyle:'medium',timeStyle:'short'});}
function sourceStatus(p){
  if(p.state==='skipped_not_applicable')return 'Not applicable: no reliable exact package version was detected. This is not a clean advisory result.';
  if(p.state==='rate_limited')return 'Temporarily unavailable because of a request limit. No limit was bypassed.';
  if(p.state==='timed_out')return 'The provider did not return a report in time.';
  if(p.state==='stale_result')return 'Older cached evidence was returned; it may not describe the current website.';
  if(p.state==='cached')return p.freshness==='unknown'?'Cached report received; its original scan age is unknown.':'Cached provider report received.';
  if(p.state==='completed')return p.coverage_warnings?.length?'Report received, but some checks within it did not finish.':'Report received.';
  if(p.state==='cancelled')return 'This check did not finish.';
  return 'No usable report was returned by this provider.';
}
function paragraph(container,text){if(text)container.append(element('p',text));}
function drawReport(data){
  if(data.synthetic!==false||data.mode!=='live')throw new Error('This is not a live website report. Enter a link to run a new test.');
  const coverage=Array.isArray(data.coverage)?data.coverage:[];
  const sites=coverage.filter(p=>p.provider!=='osv');
  const total=sites.filter(p=>received.has(p.state)).length;
  const hasGaps=sites.some(p=>!received.has(p.state)||p.state==='stale_result'||p.freshness==='unknown'||p.coverage_warnings?.length);
  const aiReady=data.ai?.state==='completed'&&typeof data.ai.data?.summary==='string';
  $('report-title').textContent=total?'Your website report':'Assessment could not be completed';
  $('report-website').textContent=data.target;
  $('report-status').textContent=hasGaps?'Limited coverage':'Checks completed';
  $('report-status').className='status-tag'+(hasGaps?' limited':'');
  $('overview-title').textContent=aiReady?'AI overview':'Assessment summary';
  $('overview-text').replaceChildren();
  if(aiReady){for(const text of data.ai.data.summary.split(/\n\s*\n/))paragraph($('overview-text'),text);}
  else{paragraph($('overview-text'),total?'The available website checks have returned. The AI explanation is temporarily unavailable, but the real provider results are included below.':'The checks did not return enough usable evidence to assess this website. This is not a clean security result.');}
  const findings=Array.isArray(data.findings)?data.findings:[];
  $('finding-count').textContent=String(findings.length);$('check-count').textContent=total+' / '+sites.length;
  const note=$('coverage-note');note.hidden=!hasGaps&&aiReady;note.textContent=hasGaps?'Some checks were unavailable or incomplete. This report only describes the evidence that was returned; it does not prove the website is secure.':'AI explanation is unavailable. Provider evidence and downloads remain available.';
  const cards=$('finding-cards');cards.replaceChildren();
  const explanations=new Map((aiReady&&Array.isArray(data.ai.data.analysis)?data.ai.data.analysis:[]).map(a=>[a.finding_id,a]));
  if(!findings.length){const empty=element('article',undefined,'card finding-card');empty.append(element('h3',total?'No findings were reported by the available checks':'No findings can be concluded'),element('p',total?'This is not proof that the website is secure. Review which checks were able to finish.':'The unavailable checks must not be interpreted as a pass.'));cards.append(empty);}
  for(const finding of findings){
    const card=element('article',undefined,'card finding-card');const heading=element('div',undefined,'finding-heading');
    const severity=['critical','high','medium','low','info','unknown'].includes(finding.severity)?finding.severity:'unknown';
    heading.append(element('h3',finding.title),element('span',severity,'severity '+severity));card.append(heading);
    const sources=Array.isArray(finding.sources)?finding.sources:[];const names=[...new Set(sources.map(s=>providerNames[s.provider]||s.provider))].join(', ');
    card.append(element('p','Reported by '+(names||'an external provider')+' · Verify before making changes.','source-note'));
    const explanation=explanations.get(finding.id);paragraph(card,explanation?.explanation||'The provider reported this configuration signal. It has not been independently confirmed as an exploitable vulnerability.');
    const guidance=element('div',undefined,'guidance');guidance.append(element('h4','Verify first'));paragraph(guidance,explanation?.verification||sources.find(s=>s.verification)?.verification||'Confirm the observation against the website’s current configuration before changing anything.');
    const remediation=explanation?.remediation||sources.find(s=>s.remediation)?.remediation;
    if(remediation){guidance.append(element('h4','Suggested next step'));paragraph(guidance,remediation);}card.append(guidance);
    const detail=element('details',undefined,'evidence-detail');detail.append(element('summary','Source & confidence'));
    const confidence=finding.confidence||{};paragraph(detail,'Observation: '+String(confidence.observation||'provider reported')+'. Interpretation: '+String(confidence.interpretation||'requires review')+'.');
    for(const source of sources){if(typeof source.evidence?.details==='string')paragraph(detail,source.evidence.details);const when=dateLabel(source.scanned_at);if(when)paragraph(detail,(providerNames[source.provider]||source.provider)+' observation: '+when);}
    card.append(detail);cards.append(card);
  }
  const list=$('coverage-list');list.replaceChildren();
  for(const provider of coverage){const li=element('li');li.append(element('strong',providerNames[provider.provider]||provider.provider),element('span',sourceStatus(provider)));const when=dateLabel(provider.scanned_at??provider.cached_at);if(when)li.append(element('span','Provider observation: '+when,'source-time'));list.append(li);}
  $('progress').hidden=true;$('report').hidden=false;renderedId=data.job_id;
}
async function refresh(v){
  if(v!==version||!current)return;if(polling){schedule(v,200);return;}polling=true;
  try{
    const job=await api('/scans/'+current.id);if(v!==version)return;
    if(job.mode!=='live'){setStored('ls_last',null);current=null;clearPoll();$('progress').hidden=true;setBusy(false);return;}
    readFailures=0;showProgress(job);
    if(job.report_available){if(renderedId!==job.id){const data=await api('/scans/'+job.id+'/report');if(v!==version)return;drawReport(data);}clearPoll();setBusy(false);return;}
    if(finished.has(job.state))throw new Error('The test ended before a report became available. Please try again.');
    schedule(v);
  }catch(e){
    if(v!==version)return;
    if(e.status===404){setStored('ls_last',null);current=null;$('progress').hidden=true;setBusy(false);error('This report is no longer available. Enter the link to run a new test.');clearPoll();}
    else if(++readFailures<=3){$('progress-title').textContent='Reconnecting…';$('progress-message').textContent='Your test is not being restarted. Waiting to retrieve its report.';schedule(v,3000);}
    else{$('progress').hidden=true;setBusy(false);clearPoll();error('The report could not be retrieved. Reload the page to reconnect; a scan will not be restarted automatically.');}
  }finally{polling=false;}
}
$('test-form').addEventListener('submit',async event=>{
  event.preventDefault();if(busy||!config)return;clearPoll();const v=++version;readFailures=0;renderedId=null;error('');$('report').hidden=true;
  try{
    const target=normalizeLink($('website').value);$('website').value=target;setBusy(true);$('progress').hidden=false;$('progress-title').textContent='Starting your website test…';$('progress-message').textContent='Real checks and the AI report run automatically.';
    const previous=saved();const result=await api('/scans',{method:'POST',body:JSON.stringify({target,mode:'live',ai:true,authorized:true,public_disclosure:true,consent_method:'click_through'})});
    remember(result.job,result.job_token||(previous?.id===result.job.id?previous.token:null));await refresh(v);
  }catch(e){if(v===version){$('progress').hidden=true;setBusy(false);error(e.status?e.message:'Could not confirm the test request. Try again; the server reuses an assessment that is already running.');}}
});
async function download(format){
  if(!current)return;
  try{const response=await fetch('/api/scans/'+current.id+'/report?format='+format+'&download=true',{headers:{'X-Client-Token':config.client_token,'X-Job-Token':current.token||''},credentials:'same-origin'});if(!response.ok)throw new Error('This report could not be downloaded. It may have expired.');const url=URL.createObjectURL(await response.blob());const link=element('a');link.href=url;link.download='LaunchShield-report.'+format;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);}catch(e){error(e.message);}
}
$('download-report').addEventListener('click',()=>download('html'));
$('download-json').addEventListener('click',()=>download('json'));
(async()=>{
  try{
    const response=await fetch('/api/config',{headers:{'X-Client-Token':getStored('ls_client')||''},credentials:'same-origin'});if(!response.ok)throw new Error('Unable to connect. Please reload the page.');config=await response.json();setStored('ls_client',config.client_token);setBusy(false);
    const old=saved();if(old?.id){current=old;try{const job=await api('/scans/'+old.id);if(job.mode!=='live')throw new Error('Not a live report');$('website').value=job.target;setBusy(true);await refresh(++version);}catch{current=null;setStored('ls_last',null);setBusy(false);$('progress').hidden=true;}}
  }catch(e){error(e.message);setBusy(false);}
})();

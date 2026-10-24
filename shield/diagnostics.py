"""Bounded provider diagnostics; no challenge tokens, cookies, HTML or instructions stored."""
from __future__ import annotations
import hashlib,json,re
from urllib.parse import urlsplit,urlunsplit
from .persistence import redact
from .models import utcnow

def security_checkpoint(headers,body):
    if str(headers.get('x-vercel-mitigated','')).lower()=='challenge':return 'vercel_security_checkpoint'
    if str(headers.get('cf-mitigated','')).lower()=='challenge':return 'cloudflare_security_checkpoint'
    if 'html' in str(headers.get('content-type','')).lower() and re.search(rb'<title[^>]*>\s*Vercel Security Checkpoint\s*</title>',body,re.I):return 'vercel_security_checkpoint'
    return None

def response_receipt(method,url,status,headers,body):
    parts=urlsplit(str(url));entry={'observed_at':utcnow(),'request_sent':True,'method':method.upper(),'endpoint':urlunsplit((parts.scheme,parts.netloc,parts.path,'','')),'http_status':status,'content_type':str(headers.get('content-type',''))[:120],'body_sha256':hashlib.sha256(body).hexdigest()}
    # Never retain Set-Cookie, Authorization, challenge-token headers or raw HTML.
    for key in ('retry-after','x-vercel-mitigated','cf-mitigated','x-ratelimit-limit','x-ratelimit-remaining','x-ratelimit-reset'):
        if headers.get(key) is not None:entry[key]=str(headers[key])[:160]
    if status>=400 and 'json' in entry['content_type'].lower():
        try:
            data=json.loads(body)
            if isinstance(data,dict):
                for key in ('code','error','message','request_id'):
                    if isinstance(data.get(key),(str,int,float)):entry['provider_'+key]=redact(str(data[key])[:400])
        except (ValueError,TypeError):pass
    checkpoint=security_checkpoint(headers,body)
    if checkpoint:entry['security_checkpoint']=checkpoint
    return entry

def inconclusive_expiry(tls):
    findings=tls.get('findings',{}) if isinstance(tls,dict) else {}
    expiry=findings.get('certExpiry',{}) if isinstance(findings,dict) else {}
    if not isinstance(expiry,dict) or expiry.get('valid') is not False:return False
    dates=('notAfter','not_after','validTo','valid_to','expiresAt','expires_at','expiryDate','expirationDate')
    # A zero-day default with no actual date is not proof of an expired certificate.
    return expiry.get('daysUntilExpiry') in (0,None) and not any(expiry.get(key) for key in dates) and not expiry.get('evidence') and not expiry.get('error')

def vibe_modules(native):
    modules=native.get('modules') if isinstance(native,dict) else None
    if not isinstance(modules,dict):return []
    result=[]
    for name,module in modules.items():
        if not isinstance(module,dict):continue
        notes=[];state='complete';known=unknown=None
        if module.get('partial') is True or module.get('status') in ('error','timed_out'):
            state='partial';raw=module.get('notes',module.get('note','Provider reported incomplete coverage.'))
            notes.extend(str(x)[:450] for x in (raw if isinstance(raw,list) else [raw]))
        findings=module.get('findings')
        if isinstance(findings,dict):
            assessments=[m.get('assessment') for m in findings.values() if isinstance(m,dict) and 'assessment' in m]
            if assessments:
                unknown=sum(x=='unknown' for x in assessments);known=sum(x not in ('unknown','not_applicable') for x in assessments)
                if unknown:state='partial';notes.append(str(unknown)+' assessments could not be determined; these are not passes.')
        if name=='tls' and isinstance(findings,dict):
            if inconclusive_expiry(module):state='partial';notes.append('Certificate expiry is inconclusive: the provider returned false/zero without a certificate date. No expired-certificate finding is inferred.')
            key=findings.get('keyStrength',{})
            if isinstance(key,dict) and key.get('weakestVerdict')=='unknown':state='partial';notes.append('The provider could not read the certificate key; key strength was not established.')
        if name=='cors' and isinstance(findings,dict) and isinstance(findings.get('probes'),list):
            probes=[x for x in findings['probes'] if isinstance(x,dict)];unknown=sum(not isinstance(x.get('status'),int) or x.get('status',0)<100 for x in probes);known=len(probes)-unknown
            if unknown:state='partial';notes.append(str(unknown)+' of '+str(len(probes))+' CORS probes returned no HTTP result; those cases are untested.')
        if name=='cve':
            if module.get('advisorySource')=='unavailable':state='partial';notes.append('Upstream advisory intelligence was unavailable; not a clean result.')
            elif module.get('rscDetected') is False and module.get('advisorySource')=='not_queried':state='not_applicable';notes.append('No React Server Components detected; this specific RSC advisory check is not a general dependency audit.')
        if name=='apiSurface' and isinstance(module.get('requestsIssued'),int):notes.append(str(module['requestsIssued'])+' requests issued by this bounded provider check; not exhaustive endpoint coverage.')
        item={'module':name,'state':state,'notes':notes}
        if known is not None:item.update(results_observed=known,results_unknown=unknown)
        result.append(item)
    return result

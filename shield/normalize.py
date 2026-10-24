from __future__ import annotations
import hashlib,json,re
from collections import Counter
from urllib.parse import urlsplit,urljoin
from .persistence import redact

class SchemaChanged(ValueError):pass
SEVERITIES={'info':0,'unknown':0,'low':1,'medium':2,'high':3,'critical':4}
SECURITY_MODULE=re.compile(r'(hsts|tls|ssl|https|csp|security|header|cookie|cors|frame|dmarc|spf|dkim|dnssec|expos)',re.I)

def issue_type(value):
    value=str(value).lower()
    if 'csp' in value or 'content-security' in value:return 'header:csp'
    if 'hsts' in value or 'strict-transport' in value:return 'header:hsts'
    if 'frame' in value or 'framing' in value:return 'header:framing'
    if 'contenttype' in value or 'nosniff' in value:return 'header:nosniff'
    if 'referrer' in value:return 'header:referrer'
    return re.sub(r'[^a-z0-9:_-]','-',value)[:120]

def _finding(provider,native_id,title,severity,evidence,origin,observed='provider_reported',interpretation='potential',resource=None,remediation='',verification=''):
    if severity not in SEVERITIES:severity='unknown'
    evidence=redact(evidence)
    return {'provider':provider,'native_id':str(native_id),'type':issue_type(native_id),'title':str(title)[:300],'severity':severity,'provider_severity':None,'resource':str(resource or origin)[:2048],'observation_confidence':observed,'interpretation_confidence':interpretation,'evidence':evidence,'remediation':str(remediation)[:3000],'verification':str(verification)[:2000]}

def normalize(provider,data,origin):
    if not isinstance(data,dict):raise SchemaChanged('Expected a JSON object.')
    rows=[]
    if provider=='website_auditor':
        report=data.get('report')
        if not isinstance(report,dict) or not isinstance(report.get('modules'),list):raise SchemaChanged('Website Auditor report.modules is missing.')
        for m in report['modules']:
            if not isinstance(m,dict) or m.get('status') not in ('warn','fail') or not SECURITY_MODULE.search(str(m.get('id',''))+' '+str(m.get('category',''))):continue
            row=_finding(provider,m.get('id','unknown'),m.get('title',m.get('id','Configuration signal')),'medium' if m['status']=='fail' else 'low',{'details':m.get('details'),'status':m['status'],'mapping_note':'LaunchShield configuration-status mapping, not a provider vulnerability severity.'},origin,remediation=m.get('recommendation',''))
            row['provider_severity']=m['status'];rows.append(row)
    elif provider=='xlogs':
        if data.get('ok') is not True or not isinstance(data.get('findings'),list):raise SchemaChanged('xlogs ok/findings schema is missing.')
        if data.get('reachable') is False:raise SchemaChanged('xlogs could not reach the target; not a clean result.')
        for i,m in enumerate(data['findings']):
            if not isinstance(m,dict) or not m.get('title'):raise SchemaChanged('Invalid xlogs finding.')
            rows.append(_finding(provider,m.get('vulnId',str(i)),m['title'],str(m.get('severity','unknown')).lower(),{'statements':m.get('statements'),'cwe':m.get('cwe'),'interpretationBasis':m.get('interpretationBasis'),'reviewReasons':m.get('reviewReasons',[])},origin,str(m.get('observationConfidence',m.get('confidence','unknown'))),str(m.get('interpretationConfidence','unknown')),resource=m.get('url',origin),remediation='; '.join(m.get('fixSteps',[])),verification=m.get('verify','')))
    elif provider=='vibe_check':
        if data.get('status') not in ('completed','done') or not isinstance(data.get('modules'),dict):raise SchemaChanged('Vibe result is not a completed module report.')
        modules=data['modules'];headers=modules.get('headers',{}).get('findings',{})
        if isinstance(headers,dict):
            for name,m in headers.items():
                if not isinstance(m,dict) or m.get('assessment') not in ('weak','missing','invalid'):continue
                severity='info' if m.get('gradeEligible') is False else 'medium'
                rows.append(_finding(provider,name,name+' configuration: '+m['assessment'],severity,m,origin,interpretation='potential'))
        cors=modules.get('cors',{}).get('findings',{})
        if isinstance(cors,dict):
            for key in ('credentialsWithWildcard','localhostAllowed','nullOriginAllowed'):
                if cors.get(key) is True:rows.append(_finding(provider,'cors:'+key,'CORS policy signal: '+key,'medium',{key:True,'note':'Cross-origin data access/exploitability was not independently verified.'},origin))
        tls=modules.get('tls',{}).get('findings',{})
        if isinstance(tls,dict):
            for key,m in tls.items():
                if isinstance(m,dict) and (m.get('valid') is False or m.get('strength')=='weak' or m.get('weakestVerdict')=='weak'):
                    rows.append(_finding(provider,'tls:'+key,'TLS configuration signal: '+key,'medium',m,origin))
        surface=modules.get('apiSurface',{}).get('findings',[])
        if isinstance(surface,list):
            for i,m in enumerate(surface):
                if not isinstance(m,dict) or m.get('category')=='expectedPublicEndpoint':continue
                # An ordinary public API endpoint is not itself a vulnerability.
                if m.get('severity') not in SEVERITIES and m.get('category') not in ('sensitiveFile','secretExposure','exposedSourceMap','exposedSensitiveFile'):continue
                rows.append(_finding(provider,m.get('kind','surface')+':'+str(i),m.get('title','Provider-reported public exposure indicator'),m.get('severity','low'),m,origin,resource=urljoin(origin+'/',m.get('path','/'))))
        cve=modules.get('cve',{})
        if isinstance(cve,dict) and cve.get('status')=='confirmed_vulnerable':
            for advisory in cve.get('advisories',[]):
                rows.append(_finding(provider,advisory.get('id','advisory'),advisory.get('summary','Provider-reported package advisory match'),'unknown',advisory,origin,interpretation='version_match_not_exploit_verification'))
    elif provider=='mdn_observatory':
        if not {'id','grade','tests_failed','tests_quantity'}.issubset(data) or data.get('error'):raise SchemaChanged('MDN v2 summary is missing or reports an error.')
        if not isinstance(data['tests_failed'],int) or not isinstance(data['tests_quantity'],int):raise SchemaChanged('Invalid MDN test counts.')
        if data['tests_failed']>0:
            rows.append(_finding(provider,'mdn-summary','MDN reports failed HTTP configuration tests (summary only)','info',{'tests_failed':data['tests_failed'],'tests_quantity':data['tests_quantity'],'grade':data['grade'],'details_url':data.get('details_url'),'note':'The v2 summary does not identify individual failed headers. No specific header vulnerability was inferred.'},origin,interpretation='details_require_provider_report'))
    elif provider=='osv':
        if not isinstance(data.get('results'),list) or not isinstance(data.get('queries'),list) or len(data['results'])!=len(data['queries']):raise SchemaChanged('OSV results do not match queries.')
        for query,result in zip(data['queries'],data['results']):
            if not isinstance(result,dict):raise SchemaChanged('Invalid OSV batch entry.')
            package=query.get('package',{})
            for v in result.get('vulns',[]):
                if not isinstance(v,dict) or not isinstance(v.get('id'),str):raise SchemaChanged('Invalid OSV advisory.')
                rows.append(_finding(provider,v['id'],v.get('summary','Advisory '+v['id']+' matches '+str(package.get('name'))+' '+str(query.get('version'))),'unknown',{'advisory_id':v['id'],'package':package,'version':query.get('version'),'package_sources':data.get('package_sources',[]),'note':'Package/version match, not verified website exploitation.'},origin,interpretation='package_version_advisory_match'))
    if provider=='xlogs':
        for row,m in zip(rows,data['findings']):row['provider_severity']=m.get('severity')
    return rows

def packages_from_xlogs(data):
    libraries=data.get('sbom',{}).get('libraries',[]) if isinstance(data,dict) else []
    known_npm={'react','react-dom','next','lodash','jquery','vue','angular','axios','bootstrap','moment','underscore','handlebars','dompurify','marked','socket.io','three','preact'}
    output=[];seen=set()
    for item in libraries if isinstance(libraries,list) else []:
        if not isinstance(item,dict):continue
        name=item.get('name');version=item.get('version');ecosystem=item.get('ecosystem')
        if not isinstance(name,str) or not isinstance(version,str) or not re.fullmatch(r'\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?',version):continue
        if not ecosystem and name in known_npm:ecosystem='npm'
        if ecosystem not in ('npm','PyPI','Go','Maven','crates.io','RubyGems','Packagist'):continue
        key=(ecosystem,name,version)
        if key in seen:continue
        seen.add(key);output.append({'query':{'package':{'ecosystem':ecosystem,'name':name},'version':version},'source':{'provider':'xlogs','field':'sbom.libraries','package':name,'version':version,'ecosystem':ecosystem,'note':'Explicit version supplied by provider SBOM; no banner/AI version guessing.'}})
        if len(output)>=10:break
    return output

def deduplicate(rows):
    groups={}
    for row in rows:
        key=(row['type'],row['resource'])
        if key not in groups:
            groups[key]={'id':'f_'+hashlib.sha256(json.dumps(key).encode()).hexdigest()[:20],'type':row['type'],'title':row['title'],'severity':row['severity'],'resource':row['resource'],'sources':[]}
        group=groups[key];group['sources'].append(row)
        if SEVERITIES[row['severity']]>SEVERITIES[group['severity']]:group['severity']=row['severity']
    for group in groups.values():
        observations={r['observation_confidence'] for r in group['sources']};interpretations={r['interpretation_confidence'] for r in group['sources']}
        group['confidence']={'observation':next(iter(observations)) if len(observations)==1 else 'mixed','interpretation':next(iter(interpretations)) if len(interpretations)==1 else 'mixed'}
        group['overlap_count']=len(group['sources']);group['note']='Related signals grouped; original provider records and distinct confidence fields retained.'
    return sorted(groups.values(),key=lambda f:(-SEVERITIES[f['severity']],f['id']))

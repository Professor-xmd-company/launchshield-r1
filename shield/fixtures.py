"""Explicit synthetic fixtures. These are never presented as real scan evidence."""
from copy import deepcopy
from .models import utcnow
import time

def native_fixture(provider,origin,scenario='success'):
    data={
      'website_auditor':{'ok':True,'cachedAt':int(time.time()*1000),'report':{'domain':'fixture.example','grade':'B','score':82,'fetchedAt':int(time.time()*1000),'modules':[{'id':'hsts','title':'HSTS configuration needs review','status':'warn','details':'SYNTHETIC: HSTS header was not present.','recommendation':'Review HTTPS coverage before enabling HSTS.'},{'id':'seo-title','title':'SEO title too short','status':'fail','details':'Supplementary SEO; not a security finding.'}]}},
      'xlogs':{'ok':True,'apiVersion':'1','scannedAt':utcnow(),'url':origin,'reachable':True,'findings':[{'vulnId':'csp-missing','severity':'medium','confidence':'confirmed','observationConfidence':'confirmed','interpretationConfidence':'potential','interpretationBasis':'configuration','title':'Content Security Policy needs review','statements':{'observed':'SYNTHETIC: no CSP header was observed.','notTested':'No XSS exploitation was performed.'},'fixSteps':['Define a suitable CSP and test in report-only mode.'],'verify':'Repeat the header check.'}], 'sbom':{'libraries':[{'ecosystem':'npm','name':'lodash','version':'4.17.20','source':'SYNTHETIC fixture bundle version'}]}},
      'vibe_check':{'scanId':'mock-scan-not-real','status':'completed','url':origin,'modules':{'headers':{'findings':{'csp':{'assessment':'missing','reason':'SYNTHETIC: no CSP header.','present':False},'permissionsPolicy':{'assessment':'missing','gradeEligible':False,'maxScore':0,'reason':'informational only'},'xFrameOptions':{'assessment':'effective','reason':'CSP frame-ancestors provides effective framing control','present':False}}},'apiSurface':{'findings':[{'category':'expectedPublicEndpoint','path':'/health','status':200,'reason':'public_discovery_endpoint'}]}}},
      'mdn_observatory':{'id':1234,'details_url':'https://developer.mozilla.org/en-US/observatory/','scanned_at':utcnow(),'grade':'B','score':75,'status_code':200,'tests_failed':2,'tests_passed':8,'tests_quantity':10,'error':None},
      'osv':{'queries':[{'package':{'ecosystem':'npm','name':'lodash'},'version':'4.17.20'}],'results':[{'vulns':[{'id':'FIXTURE-ONLY-001','summary':'SYNTHETIC advisory, not a real OSV finding'}]}],'package_sources':[{'provider':'xlogs','field':'sbom.libraries','reliability':'explicit versioned library fixture'}]}
    }
    if scenario=='malformed' and provider=='website_auditor':return {'unexpected':'Synthetic schema change'}
    result=deepcopy(data[provider])
    if scenario=='stale_cache' and provider=='website_auditor':result['cachedAt']=1577836800000;result['report']['fetchedAt']=1577836800000
    if scenario=='osv_skip' and provider=='xlogs':result['sbom']['libraries']=[]
    return result

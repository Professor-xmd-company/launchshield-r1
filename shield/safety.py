from __future__ import annotations
import asyncio,ipaddress,socket,re
from dataclasses import dataclass
from urllib.parse import urlsplit,urlunsplit,urljoin
import httpx

class TargetRejected(ValueError):pass
@dataclass(frozen=True)
class Target:
    origin:str
    host:str
    scheme:str
    port:int
    stripped_path:bool=False


def normalize_target(value:str)->Target:
    value=value.strip()
    if any(ord(c)<33 or ord(c)==127 for c in value) or '\\' in value:raise TargetRejected('URL contains forbidden characters.')
    try:
        parts=urlsplit(value)
        if parts.scheme.lower() not in ('http','https'):raise TargetRejected('Use a public http:// or https:// website URL.')
        if parts.username is not None or parts.password is not None:raise TargetRejected('Credentials in URLs are not accepted.')
        host=parts.hostname
        if not host or '%' in host:raise TargetRejected('Invalid hostname or IPv6 zone identifier.')
        host=host.rstrip('.').encode('idna').decode('ascii').lower()
        if len(host)>253:raise TargetRejected('Hostname is too long.')
        try:
            address=ipaddress.ip_address(host)
            if not address.is_global:raise TargetRejected('Private, reserved, loopback, link-local and metadata addresses are blocked.')
        except ValueError as e:
            if isinstance(e,TargetRejected):raise
            if not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?',host) or '..' in host:raise TargetRejected('Invalid public hostname.')
            if host=='localhost' or host.endswith(('.localhost','.local','.internal','.lan')) or '.' not in host:raise TargetRejected('Internal hostnames are blocked.')
        port=parts.port or (443 if parts.scheme.lower()=='https' else 80)
        if port not in (80,443):raise TargetRejected('R1 supports public web ports 80 and 443 only.')
        shown='['+host+']' if ':' in host else host
        if port!=(443 if parts.scheme.lower()=='https' else 80):shown+=':'+str(port)
        return Target(urlunsplit((parts.scheme.lower(),shown,'','','')),host,parts.scheme.lower(),port,bool(parts.path not in ('','/') or parts.query or parts.fragment))
    except (UnicodeError,ValueError) as e:
        if isinstance(e,TargetRejected):raise
        raise TargetRejected('URL could not be normalized.') from None

async def resolve_public(target:Target,resolver=None):
    if resolver:
        ips=await resolver(target.host,target.port)
    else:
        loop=asyncio.get_running_loop()
        answers=await asyncio.wait_for(loop.getaddrinfo(target.host,target.port,type=socket.SOCK_STREAM),8)
        ips=list(dict.fromkeys(a[4][0] for a in answers))
    if not ips:raise TargetRejected('Hostname has no public address.')
    for ip in ips:
        try:address=ipaddress.ip_address(ip)
        except ValueError:raise TargetRejected('Resolver returned an invalid address.') from None
        if not address.is_global:raise TargetRejected('DNS resolved to a private, reserved or cloud-metadata destination.')
    return sorted(ips,key=lambda x:':' in x)

def pinned_request(target:Target,ip:str,path='/'):
    address=ipaddress.ip_address(ip)
    if not address.is_global:raise TargetRejected('Cannot connect to a non-public address.')
    host='['+ip+']' if ':' in ip else ip
    if target.port!=(443 if target.scheme=='https' else 80):host+=':'+str(target.port)
    authority=urlsplit(target.origin).netloc
    return httpx.Request('HEAD',target.scheme+'://'+host+path,headers={'Host':authority,'User-Agent':'LaunchShield-R1/1.0 (authorized scope validation)'},extensions={'sni_hostname':target.host})

async def validate_live(target:Target,allowed:tuple[str,...],resolver=None,transport=None):
    approved={normalize_target(x).origin for x in allowed}
    if target.origin not in approved:raise TargetRejected('R1 live testing is restricted to the server owner’s explicit target allowlist.')
    # Pin this application's own connection to validated IPs, retain TLS SNI,
    # and inspect redirects manually. External providers have their own DNS.
    current=target;path='/'
    async with httpx.AsyncClient(transport=transport,timeout=12,follow_redirects=False,trust_env=False) as client:
        for hop in range(5):
            ips=await resolve_public(current,resolver)
            response=None;last=None
            for ip in ips:
                try:
                    response=await client.send(pinned_request(current,ip,path),stream=True);break
                except httpx.TransportError as e:last=e
            if response is None:raise TargetRejected('Target could not be reached with validated public DNS and TLS.') from None
            try:
                status=response.status_code;location=response.headers.get('location')
            finally:await response.aclose()
            if status in (301,302,303,307,308) and location:
                redirected=urljoin(current.origin+path,location);nxt=normalize_target(redirected)
                if nxt.origin!=target.origin:raise TargetRejected('Redirect leaves the approved single-origin scope. Submit and approve the final origin explicitly.')
                current=nxt;parts=urlsplit(redirected);path=parts.path or '/'
                if parts.query:raise TargetRejected('Redirect query parameters are not forwarded in R1.')
                continue
            return {'public_addresses_checked':len(ips),'redirects':hop,'target_http_status':status,'scope':target.origin,'own_requests_ip_pinned':True}
    raise TargetRejected('Too many redirects.')

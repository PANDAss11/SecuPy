import re, ipaddress, requests
from urllib.parse import urlparse, urljoin
from .utils import console, warn, ok

SUSP_TLDS = {"zip","top","xyz","click","link","country","gq","tk","ml"}

def analyze_url(url: str):
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    p = urlparse(url)
    reasons = []
    host = p.hostname or ""
    if host.split(".")[-1].lower() in SUSP_TLDS:
        reasons.append("Suspicious TLD")
    if host.count("-") >= 2:
        reasons.append("Hyphenated domain")
    if re.search(r"(login|verify|free|bonus|gift|update|secure)", url, re.I):
        reasons.append("Phishing keyword in URL")
    if _is_ip(host):
        reasons.append("Raw IP host")
    if len(host) > 30:
        reasons.append("Very long host")
    if reasons:
        warn("Potentially risky indicators:")
        for r in reasons: console.print(f" • {r}")
    else:
        ok("No strong phishing indicators found.")
    return reasons

def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s); return True
    except Exception: return False

def check_ip_grabber_link(url: str):
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    p = urlparse(url)
    host = p.hostname or ""
    reasons = []
    if _is_ip(host):
        reasons.append("Host is a raw IP address")
    if host.isdigit():
        reasons.append("Decimal IP host")
    if host.lower().startswith("0x"):
        reasons.append("Hex IP host")
    if re.search(r"^(?:0x[0-9a-fA-F]+|\d+)(?:\.(?:0x[0-9a-fA-F]+|\d+)){1,3}$", host):
        reasons.append("Mixed numeric notation")
    if reasons:
        warn("Potential IP grabbing / obfuscation detected:")
        for r in reasons: console.print(f" • {r}")
    else:
        ok("No obvious IP grabbing indicators detected.")
    return reasons

def expand_shortlink(url: str, max_hops: int = 5):
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    current = url
    for hop in range(1, max_hops+1):
        try:
            r = requests.head(current, allow_redirects=False, timeout=6)
        except Exception as e:
            warn(f"Request failed at hop {hop}: {e}")
            break
        loc = r.headers.get("Location")
        console.print(f"[bold]Hop {hop}:[/] {current}  (status {r.status_code})")
        if loc:
            if loc.lower().startswith("//"):
                loc = "http:" + loc
            if not loc.lower().startswith(("http://","https://")):
                loc = urljoin(current, loc)
            current = loc
        else:
            break
    console.print(f"[bold]Final:[/] {current}")
    return current

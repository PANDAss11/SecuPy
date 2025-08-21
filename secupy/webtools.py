import ssl, socket, datetime, requests
from .utils import console, make_table, warn, ok

COMMON_PATHS = [
    "admin/","login/","dashboard/","wp-login.php","wp-admin/","robots.txt",
    ".git/","server-status","config.php","phpinfo.php",".env"
]
SUB_WORDS = ["www","mail","dev","test","staging","api","blog","shop","portal","vpn"]

def audit_site(url: str):
    if not url.lower().startswith(("http://","https://")):
        url = "http://" + url
    try:
        r = requests.get(url, timeout=6, allow_redirects=True)
    except Exception as e:
        warn(f"Request failed: {e}")
        return
    table = make_table("HTTP Security Audit", ["Check", "Result"])
    # HTTPS redirect check
    table.add_row("Final URL", r.url)
    # Security headers
    headers = {k.lower(): v for k,v in r.headers.items()}
    def has(h): return "Yes" if h in headers else "No"
    table.add_row("Content-Security-Policy", has("content-security-policy"))
    table.add_row("X-Frame-Options", has("x-frame-options"))
    table.add_row("X-Content-Type-Options", has("x-content-type-options"))
    table.add_row("Referrer-Policy", has("referrer-policy"))
    table.add_row("Strict-Transport-Security", has("strict-transport-security"))
    # Cookies
    secure = any(c.get("secure", False) for c in r.cookies)
    httponly = any("httponly" in str(c).lower() for c in r.cookies)
    table.add_row("Cookies Secure", "Yes" if secure else "No/Unknown")
    table.add_row("Cookies HttpOnly", "Yes" if httponly else "No/Unknown")
    console.print(table)

def dir_probe(base_url: str):
    if not base_url.lower().startswith(("http://","https://")):
        base_url = "http://" + base_url
    table = make_table("Directory Probe", ["Path", "Status"])
    for path in COMMON_PATHS:
        url = base_url.rstrip("/") + "/" + path
        try:
            r = requests.get(url, timeout=6, allow_redirects=False)
            table.add_row(path, str(r.status_code))
        except Exception:
            table.add_row(path, "ERR")
    console.print(table)
    ok("Probe finished.")

import socket, ssl, datetime
def tls_expiry_days(hostname: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        exp_str = cert.get('notAfter')
        if not exp_str:
            return None
        expires = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
        delta = expires - datetime.datetime.utcnow()
        return max(0, delta.days)
    except Exception:
        return None

import socket
def subdomain_probe(domain: str):
    table = make_table("Subdomain Probe", ["Host", "A Record"])
    found = 0
    for sub in SUB_WORDS:
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            table.add_row(host, ip)
            found += 1
        except Exception:
            pass
    if found:
        console.print(table)
        ok(f"Found {found} subdomain(s).")
    else:
        warn("No subdomains from the small wordlist were found.")

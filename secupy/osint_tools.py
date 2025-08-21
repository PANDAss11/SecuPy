import socket
from contextlib import closing
import requests

def _whois_query(server: str, query: str, port: int = 43, timeout: float = 8.0) -> str:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            s.connect((server, port))
            s.sendall((query + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
        return data.decode(errors="ignore")
    except Exception:
        return ""

def lookup_whois(domain: str) -> str:
    if "." not in domain:
        return ""
    tld = domain.split(".")[-1]
    iana = _whois_query("whois.iana.org", tld)
    refer = ""
    for line in iana.splitlines():
        if line.lower().startswith("whois:"):
            refer = line.split(":",1)[1].strip()
            break
    server = refer or "whois.verisign-grs.com"
    return _whois_query(server, domain)

def dns_lookup(name: str):
    a = ""
    ptr = ""
    try:
        a = socket.gethostbyname(name)
    except Exception:
        a = ""
    try:
        ptr = socket.gethostbyaddr(name)[0]
    except Exception:
        ptr = ""
    return a, ptr

def geoip_lookup(ip_or_host: str):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip_or_host}", timeout=6)
        j = r.json()
        if j.get("status") != "success":
            return {}
        keep = ["query","country","regionName","city","isp","org","as","lat","lon","timezone"]
        return {k:j.get(k) for k in keep}
    except Exception:
        return {}

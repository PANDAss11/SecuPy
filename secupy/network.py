import socket, subprocess, sys, time, platform
from contextlib import closing
from .utils import run_cmd, have_cmd

TOP100 = [20,21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080] +          [i for i in range(1000,1050)]

def _ping(ip: str, timeout_ms=800):
    count_flag = "-n" if platform.system().lower().startswith("win") else "-c"
    timeout_flag = "-w" if platform.system().lower().startswith("win") else "-W"
    cmd = ["ping", count_flag, "1", timeout_flag, str(int(timeout_ms/1000 if platform.system().lower().startswith("win") else timeout_ms/1000)), ip]
    start = time.time()
    out = run_cmd(cmd, timeout=3)
    if not out:
        return False, None
    ok = "TTL=" in out or "ttl=" in out
    rtt = (time.time() - start) * 1000.0
    return ok, rtt if ok else (False, None)

def _expand_targets(target: str):
    if "/" in target and all(x.isdigit() or x=="." for x in target.replace("/", "")):
        # naive CIDR /24 only
        base, cidr = target.split("/",1)
        if cidr != "24":
            return [base]
        parts = base.split(".")
        if len(parts)!=4: return [base]
        base3 = ".".join(parts[:3])
        return [f"{base3}.{i}" for i in range(1,255)]
    else:
        return [t.strip() for t in target.split(",") if t.strip()]

def discover_hosts(target: str):
    ips = _expand_targets(target)
    live = []
    for ip in ips:
        ok, rtt = _ping(ip)
        if ok:
            live.append((ip, rtt or 0.0))
    return live

def scan_common_ports(host: str, ports="top100", timeout=0.6):
    if ports == "top100":
        plist = TOP100
    else:
        plist = [int(p) for p in ports.split(",") if p.strip().isdigit()]
    open_ports = []
    for p in plist:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            try:
                if s.connect_ex((host, p)) == 0:
                    open_ports.append(p)
            except Exception:
                pass
    return open_ports

def banner_grab_host(host: str, port: int, timeout: float = 1.0) -> str:
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) != 0:
                return ""
            try:
                data = s.recv(128)
                if data:
                    return data.decode(errors="ignore").strip()
            except Exception:
                pass
            try:
                s.sendall(b"\r\n")
                data = s.recv(128)
                if data:
                    return data.decode(errors="ignore").strip()
            except Exception:
                pass
            return ""
    except Exception:
        return ""

import requests
def http_header_probe(host_or_url: str, timeout: float = 4.0) -> str:
    url = host_or_url
    if not url.lower().startswith(("http://","https://")):
        url = "http://" + url
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        server = r.headers.get("Server","")
        xpb = r.headers.get("X-Powered-By","")
        parts = [f"URL: {r.url}", f"Status: {r.status_code}"]
        if server: parts.append(f"Server: {server}")
        if xpb: parts.append(f"X-Powered-By: {xpb}")
        return " | ".join(parts)
    except Exception:
        return ""

def do_traceroute(target: str, max_hops=20):
    if platform.system().lower().startswith("win"):
        out = run_cmd(["tracert", "-d", "-h", str(max_hops), target], timeout=60)
        hosts = []
        if out:
            for line in out.splitlines():
                line=line.strip()
                if line and line[0].isdigit() and "Tracing" not in line:
                    parts = line.split()
                    if parts:
                        hosts.append(parts[-1])
        return hosts
    else:
        out = run_cmd(["traceroute", "-n", "-m", str(max_hops), target], timeout=60)
        hosts = []
        if out:
            for line in out.splitlines():
                line=line.strip()
                if line and line[0].isdigit():
                    parts = line.split()
                    if len(parts)>1:
                        hosts.append(parts[1])
        return hosts

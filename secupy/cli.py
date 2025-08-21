import sys
from rich.console import Console
from rich.text import Text
from .utils import console, hr, info, warn, ok, err, make_table
from .network import discover_hosts, scan_common_ports, banner_grab_host, http_header_probe, do_traceroute
from .webtools import audit_site, dir_probe, subdomain_probe, tls_expiry_days
from .phishing import analyze_url, check_ip_grabber_link, expand_shortlink
from .crypto_tools import identify_hash, compute_hashes, password_strength
from .osint_tools import lookup_whois, dns_lookup, geoip_lookup

try:
    import pyfiglet
    _HAS_FIG = True
except Exception:
    _HAS_FIG = False

def banner():
    if _HAS_FIG:
        ascii_art = pyfiglet.figlet_format("SecuPy", font="slant")
    else:
        ascii_art = """
   (                    (          
 )\ )                 )\ )       
(()/(   (         (  (()/( (     
 /(_)) ))\  (    ))\  /(_)))\ )  
(_))  /((_) )\  /((_)(_)) (()/(  
/ __|(_))  ((_)(_))( | _ \ )(_)) 
\__ \/ -_)/ _| | || ||  _/| || | 
|___/\___|\__|  \_,_||_|   \_, | 
                           |__/  
        """
    text = Text(ascii_art, style="bold cyan")
    console.print(text)
    console.print("[bold magenta]⚡ Ethical Security Toolkit ⚡[/bold magenta]\n")

def ask(prompt):
    return console.input(f"[bold yellow]{prompt}[/bold yellow] ").strip()

def menu(title, options):
    console.rule(f"[bold green]{title}[/bold green]")
    for key, label in options:
        console.print(f"[bold cyan][{key}][/bold cyan] {label}")
    choice = console.input("[bold yellow]>>> Your choice:[/bold yellow] ").strip()
    return choice

def main():
    banner()
    while True:
        choice = menu("Main Menu", [
            ("1", "Network Tools"),
            ("2", "Web Security Tools"),
            ("3", "Phishing & Link Tools"),
            ("4", "Crypto & Files"),
            ("5", "OSINT / WHOIS / DNS / GeoIP"),
            ("0", "Exit"),
        ])

        if choice == "1":
            while True:
                sub = menu("Network Tools", [
                    ("1", "Discover live hosts (ping sweep)"),
                    ("2", "Scan common ports & banners"),
                    ("3", "Traceroute"),
                    ("0", "Back"),
                ])
                if sub == "1":
                    target = ask("Target (CIDR like 192.168.1.0/24 or comma-separated IPs)")
                    hosts = discover_hosts(target)
                    if not hosts:
                        warn("No live hosts found (try admin privileges or smaller scope).")
                    else:
                        table = make_table("Live Hosts", ["IP", "Latency (ms)"])
                        for ip, latency in hosts:
                            table.add_row(ip, f"{latency:.1f}")
                        console.print(table)
                elif sub == "2":
                    ip = ask("Target IP/Host")
                    ports = ask("Ports (comma list or 'top100')") or "top100"
                    results = scan_common_ports(ip, ports=ports, timeout=0.6)
                    table = make_table("Open Ports", ["Port", "Banner/Info (best-effort)"])
                    for p in results:
                        b = banner_grab_host(ip, p, timeout=1.0) or ""
                        table.add_row(str(p), b[:80])
                    http = http_header_probe(ip)
                    if http:
                        table.add_row("HTTP", http[:80])
                    console.print(table)
                elif sub == "3":
                    target = ask("Traceroute to host/IP")
                    hops = do_traceroute(target, max_hops=20)
                    table = make_table("Traceroute", ["Hop", "Host"])
                    for i, h in enumerate(hops, 1):
                        table.add_row(str(i), h)
                    console.print(table)
                elif sub == "0":
                    break
        elif choice == "2":
            while True:
                sub = menu("Web Security Tools", [
                    ("1", "Security audit (headers, cookies, https redirects)"),
                    ("2", "Directory probe"),
                    ("3", "Subdomain probe"),
                    ("4", "TLS/SSL expiry check (days remaining)"),
                    ("0", "Back"),
                ])
                if sub == "1":
                    url = ask("Target URL (e.g. https://example.com)")
                    audit_site(url)
                elif sub == "2":
                    url = ask("Base URL (e.g. https://example.com)")
                    dir_probe(url)
                elif sub == "3":
                    domain = ask("Domain (e.g. example.com)")
                    subdomain_probe(domain)
                elif sub == "4":
                    host = ask("Hostname (e.g. example.com)")
                    days = tls_expiry_days(host)
                    if days is None:
                        warn("Could not determine certificate expiry.")
                    else:
                        ok(f"Certificate expires in ~{days} day(s).")
                elif sub == "0":
                    break
        elif choice == "3":
            while True:
                sub = menu("Phishing & Link Tools", [
                    ("1", "Phishing detector (heuristics)"),
                    ("2", "IP grabber link detector (Don't works properly will update it in future)"),
                    ("3", "Shortlink expander"),
                    ("0", "Back"),
                ])
                if sub == "1":
                    url = ask("URL")
                    analyze_url(url)
                elif sub == "2":
                    url = ask("URL to check")
                    check_ip_grabber_link(url)
                elif sub == "3":
                    url = ask("Short URL to expand")
                    expand_shortlink(url)
                elif sub == "0":
                    break
        elif choice == "4":
            while True:
                sub = menu("Crypto & Files", [
                    ("1", "Identify hash type"),
                    ("2", "Compute file hashes (MD5/SHA1/SHA256)"),
                    ("3", "Password strength (simple)"),
                    ("0", "Back"),
                ])
                if sub == "1":
                    h = ask("Hash string")
                    kinds = identify_hash(h)
                    console.print(f"[bold]Likely:[/bold] {', '.join(kinds) if kinds else 'Unknown'}")
                elif sub == "2":
                    path = ask("File path")
                    digests = compute_hashes(path)
                    table = make_table("File Hashes", ["Algo", "Digest"])
                    for k, v in digests.items():
                        table.add_row(k, v)
                    console.print(table)
                elif sub == "3":
                    pw = ask("Password")
                    score, tips = password_strength(pw)
                    console.print(f"[bold]Score:[/bold] {score}/4")
                    for t in tips:
                        warn(t)
                elif sub == "0":
                    break
        elif choice == "5":
            while True:
                sub = menu("OSINT / WHOIS / DNS / GeoIP", [
                    ("1", "WHOIS lookup"),
                    ("2", "DNS A/PTR lookup"),
                    ("3", "GeoIP (ip-api.com)"),
                    ("0", "Back"),
                ])
                if sub == "1":
                    dom = ask("Domain (example.com)")
                    text = lookup_whois(dom) or "WHOIS not available."
                    console.print(text)
                elif sub == "2":
                    name = ask("Host or IP")
                    a, ptr = dns_lookup(name)
                    table = make_table("DNS", ["Type", "Value"])
                    table.add_row("A", a or "-")
                    table.add_row("PTR", ptr or "-")
                    console.print(table)
                elif sub == "3":
                    ip = ask("IP or domain")
                    info = geoip_lookup(ip)
                    if not info:
                        warn("No GeoIP data available.")
                    else:
                        table = make_table("GeoIP", ["Field", "Value"])
                        for k, v in info.items():
                            table.add_row(k, str(v))
                        console.print(table)
                elif sub == "0":
                    break
        elif choice == "0":
            console.print("[bold red]Exiting...[/bold red]")
            sys.exit(0)
        else:
            warn("Invalid choice.")

if __name__ == "__main__":
    main()

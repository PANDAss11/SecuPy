# SecuPy 

A professional, terminal-based **ethical security toolkit**. Everything is non-destructive and designed for learning and blue-team workflows.

## Features
- **Network**: host discovery (ping), common port scan, banner grab, HTTP header probe, traceroute
- **Web**: security header audit, cookie flag checker, TLS/SSL expiry check, directory probe, subdomain probe
- **Phishing/Links**: phishing heuristics, IP grabber/obfuscation detection, shortlink expander
- **Crypto/Files**: hash identify + file hashes, password strength check (simple rules)
- **OSINT**: WHOIS (basic), DNS A/PTR, GeoIP (ip-api.com)

## Install
```bash
pip install -r requirements.txt
```
## Run
```bash
cd Secupy
```

## Then Run

```bash
python -m secupy.cli
```

**Note (Windows)**: For traceroute, the tool uses `tracert`. For ping, it uses the built-in `ping` command. Run Command Prompt or PowerShell.

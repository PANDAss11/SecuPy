import hashlib, os, re

def identify_hash(h: str):
    h = h.strip()
    c = []
    if re.fullmatch(r"[a-fA-F0-9]{32}", h): c.append("MD5")
    if re.fullmatch(r"[a-fA-F0-9]{40}", h): c.append("SHA1")
    if re.fullmatch(r"[a-fA-F0-9]{64}", h): c.append("SHA256")
    if re.fullmatch(r"[a-fA-F0-9]{96}", h): c.append("SHA384")
    if re.fullmatch(r"[a-fA-F0-9]{128}", h): c.append("SHA512")
    return c

def compute_hashes(path: str):
    algos = {"MD5": hashlib.md5(), "SHA1": hashlib.sha1(), "SHA256": hashlib.sha256()}
    if not os.path.exists(path):
        return {k:"<file not found>" for k in algos}
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            for h in algos.values():
                h.update(chunk)
    return {k:v.hexdigest() for k,v in algos.items()}

def password_strength(pw: str):
    score = 0
    tips = []
    if len(pw) >= 12: score += 1
    else: tips.append("Use at least 12 characters.")
    if re.search(r"[A-Z]", pw): score += 1
    else: tips.append("Add uppercase letters.")
    if re.search(r"[0-9]", pw): score += 1
    else: tips.append("Add digits.")
    if re.search(r"[^A-Za-z0-9]", pw): score += 1
    else: tips.append("Add symbols.")
    return score, tips

"""Check model findings, link them across parts, merge into one report."""
import re
from collections import Counter

from . import config
from .logindex import IPV4
from .memory import EXFIL_WORDS
from .prompts import ATTACK_TYPES, SEVERITIES

SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
ATTACK_FLAGS = {"auth_fail", "auth_ok", "sqli", "traversal", "cmdi", "xss", "scan_path", "scanner_ua",
                "denied", "admin", "rate", "inj"}
CHAIN_ORDER = ["Scanning", "Brute Force", "SQL Injection", "Path Traversal", "XSS", "Command Injection",
               "Unauthorized Access", "High Request Rate", "Log Injection Attempt", "Other",
               "Account Compromise", "Data Exfiltration"]
TYPE_KEYWORDS = [
    ("compromise", "Account Compromise"), ("takeover", "Account Compromise"),
    ("brute", "Brute Force"), ("password spray", "Brute Force"), ("credential", "Brute Force"),
    ("failed login", "Brute Force"), ("login attempt", "Brute Force"),
    ("sql", "SQL Injection"), ("travers", "Path Traversal"), ("lfi", "Path Traversal"),
    ("xss", "XSS"), ("cross-site", "XSS"), ("command", "Command Injection"), ("rce", "Command Injection"),
    ("scan", "Scanning"), ("recon", "Scanning"), ("enumerat", "Scanning"), ("probe", "Scanning"),
    ("rate", "High Request Rate"), ("dos", "High Request Rate"), ("flood", "High Request Rate"),
    ("unauthor", "Unauthorized Access"), ("forbidden", "Unauthorized Access"), ("privilege", "Unauthorized Access"),
    ("exfil", "Data Exfiltration"), ("export", "Data Exfiltration"),
    ("injection attempt", "Log Injection Attempt"), ("prompt", "Log Injection Attempt"), ("log inj", "Log Injection Attempt"),
]
# which line flags back up each finding type
SUPPORT = {
    "Brute Force": {"auth_fail"}, "Account Compromise": {"auth_ok"}, "SQL Injection": {"sqli"},
    "Path Traversal": {"traversal"}, "XSS": {"xss"}, "Command Injection": {"cmdi"},
    "Scanning": {"scan_path", "scanner_ua", "n404"}, "High Request Rate": {"rate"},
    "Unauthorized Access": {"denied", "admin"}, "Log Injection Attempt": {"inj"},
    "Data Exfiltration": set(), "Other": set(),
}
DEFAULT_ACTION = {
    "Brute Force": "Block or rate-limit the IP, enforce MFA and account lockout.",
    "Account Compromise": "Disable the account, revoke its sessions, reset the password, review activity.",
    "SQL Injection": "Block the IP, confirm parameterized queries, review WAF and DB logs.",
    "Path Traversal": "Block the IP, validate file paths server-side, check files served.",
    "XSS": "Block the IP, encode output and review input validation on the endpoint.",
    "Command Injection": "Block the IP, audit the endpoint for shell calls, check host for compromise.",
    "Scanning": "Block or tarpit the IP; confirm probed files are not exposed.",
    "High Request Rate": "Keep the rate limit, block the IP if it persists, check for scraping/DoS.",
    "Unauthorized Access": "Review access controls on the targeted endpoints; block the IP.",
    "Data Exfiltration": "Revoke the session, identify exported data, start incident response.",
    "Log Injection Attempt": "Treat as hostile input; keep analysis tooling from acting on log text.",
    "Other": "Investigate the cited lines.",
}


def norm_type(t):
    t = str(t or "").strip()
    if t in ATTACK_TYPES:
        return t
    low = t.lower()
    for kw, canon in TYPE_KEYWORDS:
        if kw in low:
            return canon
    return "Other"


def norm_sev(s):
    s = str(s or "").strip().capitalize()
    return s if s in SEV_RANK else "Medium"


def _lines(raw):
    """Accept [12, 15], ["L12", "15-17"] or "L12" and return a list of ints."""
    out = []
    for x in raw if isinstance(raw, list) else [raw]:
        if isinstance(x, bool):
            continue
        if isinstance(x, int):
            out.append(x)
        elif isinstance(x, str):
            for a, b in re.findall(r"L?(\d+)(?:\s*-\s*L?(\d+))?", x):
                a = int(a)
                b = int(b) if b else a
                out.extend(range(a, min(b, a + 50) + 1))
    return out


def validate(raw, chunk, index, state):
    """Keep only findings whose evidence really exists in this part. Returns (findings, dropped, notes)."""
    out, dropped, notes = [], 0, []
    findings = raw.get("findings") if isinstance(raw, dict) else None
    if not isinstance(findings, list):
        return out, 0, ["reply had no findings list"]
    for f in findings[:8]:
        if not isinstance(f, dict):
            dropped += 1
            continue
        ftype = norm_type(f.get("type"))
        sev = norm_sev(f.get("severity"))
        lines = sorted({n for n in _lines(f.get("lines", [])) if chunk["start"] <= n <= chunk["end"]})
        ip = str(f.get("ip") or "").strip()
        line_ips = [x for x in (index.info.get(n, {}).get("ip") for n in lines) if x]
        if line_ips and (not ip or not IPV4.fullmatch(ip) or ip not in line_ips):
            fixed = Counter(line_ips).most_common(1)[0][0]
            if ip and ip != fixed:
                notes.append(f"corrected IP {ip} -> {fixed}")
            ip = fixed
        if not lines:
            dropped += 1
            notes.append(f"dropped {ftype}: no valid line numbers in this part")
            continue
        flags = set()
        for n in lines:
            flags.update(index.info.get(n, {}).get("flags", []))
        e = state["entities"].get(ip, {})
        comp = e.get("compromise")
        if not (flags & ATTACK_FLAGS) and not (ftype == "Data Exfiltration" and comp):
            dropped += 1
            notes.append(f"dropped {ftype} on {ip or '?'}: cited lines are routine traffic or normal errors")
            continue
        # failed logins for this IP so far = earlier parts + this part
        fails = e.get("counts", {}).get("auth_fail", 0) + sum(
            1 for n in range(chunk["start"], chunk["end"] + 1)
            if index.info.get(n, {}).get("ip") == ip and "auth_fail" in index.info.get(n, {}).get("flags", []))
        only_logins = flags & ATTACK_FLAGS <= {"auth_fail", "auth_ok"}
        if ftype in ("Unauthorized Access", "Other") and only_logins and "auth_ok" in flags \
                and fails >= config.COMPROMISE_MIN_FAILS:
            ftype = "Account Compromise"      # same event the real model labelled twice
        if only_logins and fails < config.COMPROMISE_MIN_FAILS and not comp:
            dropped += 1                      # e.g. one wrong password then success
            notes.append(f"dropped {ftype} on {ip}: only {fails} failed login(s) - normal user error")
            continue
        confirmed = bool(SUPPORT.get(ftype, set()) & flags)
        if ftype == "Account Compromise":
            confirmed = "auth_ok" in flags and (fails >= config.COMPROMISE_MIN_FAILS or bool(comp))
        if ftype == "Data Exfiltration":
            confirmed = bool(comp) and any(n > comp["ok_line"] for n in lines)
        if ftype == "Brute Force":
            confirmed = fails >= config.BRUTE_MIN_FAILS
        if not confirmed:
            cap = "Low" if ftype == "Account Compromise" else "Medium"
            if SEV_RANK[sev] > SEV_RANK[cap]:
                sev = cap
        out.append({
            "type": ftype, "severity": sev, "ip": ip or "unknown", "lines": lines[:20],
            "reason": str(f.get("reason") or "")[:240], "action": str(f.get("action") or "")[:240],
            "confirmed": confirmed, "part": chunk["i"] + 1, "source": "model",
        })
    return out, dropped, notes
# ---------------------------------------------------------------- linking across parts
def _f(ftype, sev, ip, lines, reason, users=None):
    return {"type": ftype, "severity": sev, "ip": ip, "lines": sorted(set(lines)), "reason": reason,
            "action": DEFAULT_ACTION[ftype], "confirmed": True, "source": "correlator", "users": users or []}


def correlate(state, index):
    """Rules over the memory of the WHOLE file (runs once, after the last part)."""
    out = []
    for ip, e in state["entities"].items():
        c, L = e["counts"], e["lines"]
        parts = e["parts"]
        span = f"parts {parts[0]}-{parts[-1]}" if len(parts) > 1 else f"part {parts[0]}"
        fails = c.get("auth_fail", 0)
        if fails >= config.BRUTE_MIN_FAILS:
            sev = "High" if fails >= config.BRUTE_HIGH_FAILS or e["compromise"] else "Medium"
            out.append(_f("Brute Force", sev, ip, L.get("auth_fail", []),
                          f"{fails} failed logins for {', '.join(e['users']) or 'accounts'} spread over {span}.",
                          e["users"]))
        comp = e["compromise"]
        if comp:
            fl = L.get("auth_fail", [])
            user = [comp["user"]] if comp.get("user") else []
            out.append(_f("Account Compromise", "Critical", ip, fl[:2] + fl[-2:] + [comp["ok_line"]],
                          f"Successful login for {comp.get('user') or 'an account'} at L{comp['ok_line']} after "
                          f"{comp['fails_before']} failed attempts from the same IP.", user))
            exfil = []
            for n in e["post"]:
                info = index.info.get(n, {})
                path = (info.get("path") or "").lower()
                if info.get("status", 0) < 400 and (any(w in path for w in EXFIL_WORDS) or "admin" in info.get("flags", [])):
                    exfil.append(n)
            if exfil:
                out.append(_f("Data Exfiltration", "Critical", ip, [comp["ok_line"]] + exfil,
                              f"After the suspicious login the same IP accessed admin/export endpoints "
                              f"({len(exfil)} request(s), all successful).", user))
        if c.get("sqli"):
            ok = [n for n in L["sqli"] if 200 <= index.info.get(n, {}).get("status", 0) < 300]
            sev = "High" if ok or c["sqli"] >= 3 else "Medium"
            blocked = "" if ok else " All were rejected by the server (4xx)."
            out.append(_f("SQL Injection", sev, ip, L["sqli"],
                          f"{c['sqli']} requests with SQL injection payloads over {span}.{blocked}"))
        for flag, ftype in (("traversal", "Path Traversal"), ("cmdi", "Command Injection"), ("xss", "XSS")):
            if c.get(flag):
                ok = [n for n in L[flag] if 200 <= index.info.get(n, {}).get("status", 0) < 300]
                out.append(_f(ftype, "High" if ok else "Medium", ip, L[flag],
                              f"{c[flag]} request(s) with {ftype.lower()} payloads"
                              + (" (some succeeded)." if ok else " (all blocked).")))
        scan_hits = c.get("scan_path", 0) + c.get("scanner_ua", 0)
        if scan_hits >= config.SCAN_MIN_HITS or len(e["paths404"]) >= config.SCAN_MIN_404_PATHS or \
                (c.get("scanner_ua") and scan_hits >= 2):
            ev = L.get("scan_path", []) + L.get("scanner_ua", []) + L.get("n404", [])
            out.append(_f("Scanning", "High" if scan_hits >= 30 else "Medium", ip, ev,
                          f"Probed {max(scan_hits, len(e['paths404']))} sensitive/non-existent paths "
                          f"(e.g. {', '.join(e['paths404'][:3]) or 'config files'})."))
        if e["peak_rpm"] >= config.RATE_MEDIUM_RPM:
            ev = L.get("rate", []) or [e["peak_line"]]
            sev = "High" if e["peak_rpm"] >= config.RATE_HIGH_RPM else "Medium"
            throttled = sum(1 for n in L.get("rate", []) if index.info.get(n, {}).get("status") == 429)
            out.append(_f("High Request Rate", sev, ip, ev,
                          f"Peak about {e['peak_rpm']} requests/min from one IP"
                          + (f"; {throttled}+ answered 429 (rate limited)." if throttled else ".")))
        admin_denied = [n for n in L.get("denied", []) if "admin" in index.info.get(n, {}).get("flags", [])]
        if admin_denied or c.get("denied", 0) >= config.DENIED_MIN:
            ev = admin_denied or L.get("denied", [])
            out.append(_f("Unauthorized Access", "Medium", ip, ev,
                          f"{len(ev)} denied request(s) to restricted resources"
                          + (" incl. admin endpoints." if admin_denied else ".")))
        if c.get("inj"):
            out.append(_f("Log Injection Attempt", "Medium", ip, L["inj"],
                          "Request body contains instructions aimed at an AI/log analyst; treated as data and ignored."))
    for user, u in state["users"].items():          # one account attacked from many IPs
        if u["fail"] >= config.BRUTE_MIN_FAILS and len(u["ips"]) >= 3:
            out.append(_f("Brute Force", "High", ",".join(u["ips"][:4]), u["fail_lines"],
                          f"Distributed login failures for '{user}' from {len(u['ips'])} IPs.", [user]))
    return out


# ---------------------------------------------------------------- merging
def merge(model_findings, rule_findings, index, max_evidence=15):
    """Same (type, IP) from any part or source -> one finding."""
    buckets = {}
    for f in rule_findings + model_findings:
        key = (f["type"], f["ip"])
        b = buckets.setdefault(key, {"type": f["type"], "ip": f["ip"], "severity": f["severity"],
                                     "lines": set(), "reasons": [], "actions": [], "sources": set(),
                                     "parts": set(), "confirmed": False, "users": set(), "rule_sev": None})
        b["lines"].update(f["lines"])
        if f.get("reason") and f["reason"] not in b["reasons"]:
            b["reasons"].append(f["reason"])
        if f.get("action") and f["action"] not in b["actions"]:
            b["actions"].append(f["action"])
        b["sources"].add(f["source"])
        if f.get("part"):
            b["parts"].add(f["part"])
        b["confirmed"] = b["confirmed"] or f["confirmed"]
        b["users"].update(x for x in f.get("users", []) if x)
        if f["source"] == "correlator":
            b["rule_sev"] = f["severity"]
        b["severity"] = max(b["severity"], f["severity"], key=lambda s: SEV_RANK[s])
    for b in buckets.values():                # the model may raise a rule's severity by one level at most
        if b["rule_sev"]:
            cap = SEVERITIES[min(SEV_RANK[b["rule_sev"]] + 1, 3)]
            if SEV_RANK[b["severity"]] > SEV_RANK[cap]:
                b["severity"] = cap

    merged = []
    for b in buckets.values():
        lines = sorted(b["lines"])
        merged.append({
            "type": b["type"], "severity": b["severity"],
            "status": "confirmed" if b["confirmed"] else "suspected",
            "ip": b["ip"], "users": sorted(b["users"]),
            "first_line": lines[0] if lines else None, "last_line": lines[-1] if lines else None,
            "evidence_lines": lines, "evidence_count": len(lines),
            "evidence": [{"line": n, "text": index.line_text(n)[:500]} for n in lines[:max_evidence]],
            "reason": b["reasons"][0] if b["reasons"] else "", "model_reasons": b["reasons"][1:4],
            "action": b["actions"][0] if b["actions"] else DEFAULT_ACTION[b["type"]],
            "sources": sorted(b["sources"]), "model_parts": sorted(b["parts"]),
        })
    merged.sort(key=lambda f: (-SEV_RANK[f["severity"]], f["status"] != "confirmed", f["first_line"] or 0))
    for i, f in enumerate(merged, 1):
        f["id"] = f"F{i}"
    return merged


def build_chains(findings, part_of_line):
    """Findings on one IP, in time order, as one story (brute force -> compromise -> exfiltration)."""
    by_ip = {}
    for f in findings:
        if f["ip"] and f["ip"] != "unknown":
            by_ip.setdefault(f["ip"], []).append(f)

    def key_line(f):
        ev = f["evidence_lines"]
        if f["type"] == "Account Compromise":                  # happens at the successful login
            return ev[-1] if ev else 0
        if f["type"] == "Data Exfiltration" and len(ev) > 1:   # first request AFTER the login
            return ev[1]
        return ev[0] if ev else 0

    chains = []
    for ip, fs in by_ip.items():
        lines = sorted(n for f in fs for n in f["evidence_lines"])
        parts = sorted({part_of_line(n) for n in lines if part_of_line(n)})
        if len(fs) < 2 and len(parts) < 2:
            continue
        fs = sorted(fs, key=lambda f: (key_line(f), CHAIN_ORDER.index(f["type"])))
        for f in fs:
            f["related"] = [g["id"] for g in fs if g is not f]
        steps = [{"id": f["id"], "type": f["type"], "severity": f["severity"], "first_line": key_line(f)}
                 for f in fs]
        worst = max(fs, key=lambda f: SEV_RANK[f["severity"]])["severity"]
        chains.append({"ip": ip, "severity": worst, "parts": parts, "steps": steps,
                       "narrative": " -> ".join(f"{s['type']} (L{s['first_line']})" for s in steps)
                                    + (f", across parts {parts[0]}-{parts[-1]}" if len(parts) > 1 else "")})
    chains.sort(key=lambda c: -SEV_RANK[c["severity"]])
    return chains


def benign_noise(index):
    """Errors that were seen but are NOT treated as attacks (listed so reviewers can check)."""
    groups, first = Counter(), {}
    for n, info in index.info.items():
        flags = info.get("flags", [])
        st = info.get("status")
        if set(flags) & {"auth_fail", "sqli", "traversal", "cmdi", "xss", "scan_path",
                         "scanner_ua", "denied", "rate", "inj"}:
            continue
        if "error" in flags or (st and st >= 500) or st in (404, 422):
            key = f"status {st} {info.get('path', '')[:40]}" if st else "ERROR log entry (no HTTP status)"
            groups[key] += 1
            first.setdefault(key, n)
    return [{"what": k, "count": c, "first_line": first[k]} for k, c in groups.most_common(12)]
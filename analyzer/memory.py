"""Memory carried between model calls.

`entities` (per IP) and `users` are built part by part from the line facts and from the
model's own findings. Before each call the most relevant entries are written as
"EARLIER FACTS" so the model can link events across parts. It is plain JSON and is
saved in the job checkpoint after every part.
"""
from . import config

SCORE = {"auth_fail": 2, "sqli": 4, "traversal": 4, "cmdi": 4, "xss": 3, "scan_path": 2,
         "scanner_ua": 3, "denied": 1, "rate": 2, "inj": 3}
HINT_FLAGS = ["auth_fail", "auth_ok", "sqli", "traversal", "cmdi", "xss", "scan_path",
              "scanner_ua", "denied", "rate", "inj"]
FLAG_LABEL = {"auth_fail": "failed login", "auth_ok": "successful login", "sqli": "SQLi pattern",
              "traversal": "path traversal pattern", "cmdi": "command-injection pattern",
              "xss": "XSS pattern", "scan_path": "probe of sensitive path", "scanner_ua": "scanner user-agent",
              "denied": "denied (401/403)", "rate": "rate-limit / burst", "inj": "AI-instruction text"}
EXFIL_WORDS = ("export", "download", "dump", "backup", "/admin/users", "bulk")


def _cap_append(lst, n, cap=14):
    """Keep at most `cap` line numbers: the earliest half stays, the latest half rolls."""
    if lst and lst[-1] == n:
        return
    if len(lst) < cap:
        lst.append(n)
    else:
        del lst[cap // 2]
        lst.append(n)


def new_state():
    return {"entities": {}, "users": {}, "facts": [], "total_requests": 0}


def _entity(state, ip):
    e = state["entities"].get(ip)
    if e is None:
        e = {"req": 0, "first": None, "last": None, "parts": [], "counts": {}, "lines": {},
             "users": [], "paths404": [], "peak_rpm": 0, "peak_line": None, "mb": None, "mc": 0,
             "fails_before_ok": 0, "compromise": None, "post": [], "model": {}}
        state["entities"][ip] = e
    return e


def apply_part(state, index, chunk):
    """Add the facts of one part to the memory (called exactly once per part)."""
    part_no = chunk["i"] + 1
    for n in range(chunk["start"], chunk["end"] + 1):
        info = index.info.get(n)
        if not info:
            continue
        flags = info.get("flags", [])
        user = info.get("user")
        ip = info.get("ip")
        if user and ("auth_fail" in flags or "auth_ok" in flags):
            u = state["users"].setdefault(user, {"fail": 0, "ok": 0, "ips": [], "fail_lines": [],
                                                 "ok_after_fail": None})
            if ip and ip not in u["ips"] and len(u["ips"]) < 10:
                u["ips"].append(ip)
            if "auth_fail" in flags:
                u["fail"] += 1
                _cap_append(u["fail_lines"], n)
            else:
                u["ok"] += 1
                if u["fail"] >= config.COMPROMISE_MIN_FAILS and u["ok_after_fail"] is None:
                    u["ok_after_fail"] = n
        if not ip:
            continue
        e = _entity(state, ip)
        state["total_requests"] += 1
        e["req"] += 1
        e["first"] = e["first"] or n
        e["last"] = n
        if part_no not in e["parts"]:
            e["parts"].append(part_no)
        if user and user not in e["users"] and len(e["users"]) < 5:
            e["users"].append(user)
        for f in flags:
            e["counts"][f] = e["counts"].get(f, 0) + 1
            if f != "error":
                _cap_append(e["lines"].setdefault(f, []), n)
        if "n404" in flags and info.get("path") and len(e["paths404"]) < 25 \
                and info["path"] not in e["paths404"]:
            e["paths404"].append(info["path"][:80])
        # request rate: server-reported window if present, else requests per minute from timestamps
        rpm = info.get("rpm")
        if rpm is None and "ts" in info:
            mb = info["ts"] // 60
            if mb == e["mb"]:
                e["mc"] += 1
            else:
                e["mb"], e["mc"] = mb, 1
            rpm = e["mc"]
        if rpm and rpm > e["peak_rpm"]:
            e["peak_rpm"], e["peak_line"] = rpm, n
        # failures -> success -> what the IP did afterwards
        if "auth_fail" in flags and e["compromise"] is None:
            e["fails_before_ok"] += 1
        if "auth_ok" in flags and e["compromise"] is None \
                and e["fails_before_ok"] >= config.COMPROMISE_MIN_FAILS:
            e["compromise"] = {"ok_line": n, "fails_before": e["fails_before_ok"], "user": user,
                               "session": info.get("session")}
        elif e["compromise"] and n != e["compromise"]["ok_line"] and len(e["post"]) < 20:
            e["post"].append(n)


def note_model_findings(state, findings):
    for f in findings:
        ip = f.get("ip")
        if ip in state["entities"]:
            m = state["entities"][ip]["model"]
            if f["type"] not in m:
                m[f["type"]] = f["severity"]


def note_facts(state, part_no, facts):
    if isinstance(facts, str) and facts.strip():
        state["facts"].append(f"part {part_no}: {facts.strip()[:160]}")
        state["facts"] = state["facts"][-3:]


def score(e):
    s = sum(SCORE.get(f, 0) * c for f, c in e["counts"].items())
    if e["peak_rpm"] >= config.RATE_MEDIUM_RPM:
        s += 6
    if e["compromise"]:
        s += 20
    return s + 3 * len(e["model"])


def _span(lines):
    if not lines:
        return ""
    return f"L{lines[0]}" if len(lines) == 1 else f"L{lines[0]}..L{lines[-1]}"


def describe_entity(ip, e, in_part):
    c = e["counts"]
    bits = []
    if c.get("auth_fail"):
        users = ",".join(e["users"][:2])
        bits.append(f"{c['auth_fail']} failed logins {_span(e['lines'].get('auth_fail', []))}"
                    + (f" user {users}" if users else ""))
    if c.get("auth_ok"):
        bits.append(f"{c['auth_ok']} successful login(s) {_span(e['lines'].get('auth_ok', []))}")
    if e["compromise"]:
        bits.append(f"LOGIN SUCCESS after {e['compromise']['fails_before']} failures at L{e['compromise']['ok_line']}")
    for f in ("sqli", "traversal", "cmdi", "xss", "scan_path", "scanner_ua", "inj"):
        if c.get(f):
            bits.append(f"{c[f]} {FLAG_LABEL[f]} {_span(e['lines'].get(f, []))}")
    if c.get("denied"):
        bits.append(f"{c['denied']} denied {_span(e['lines'].get('denied', []))}")
    if e["peak_rpm"] >= config.RATE_MEDIUM_RPM:
        bits.append(f"peak {e['peak_rpm']} req/min at L{e['peak_line']}")
    if e["model"]:
        bits.append("flagged " + ", ".join(f"{t}/{s}" for t, s in list(e["model"].items())[:3]))
    parts = e["parts"]
    where = f"parts {parts[0]}-{parts[-1]}" if len(parts) > 1 else f"part {parts[0]}"
    return f"- {ip}: " + "; ".join(bits) + f" ({where})" + (" <- ALSO IN THIS PART" if in_part else "")


def render_earlier(state, part_ips, part_users, max_tokens, count_tokens):
    """EARLIER FACTS block: suspicious IPs, those also in this part first."""
    cands = [(ip, e) for ip, e in state["entities"].items() if score(e) >= 2]
    cands.sort(key=lambda x: (x[0] not in part_ips, -score(x[1])))
    lines = [describe_entity(ip, e, ip in part_ips) for ip, e in cands[:10]]
    for user, u in state["users"].items():
        if user in part_users and u["fail"] >= config.COMPROMISE_MIN_FAILS:
            lines.append(f"- user {user}: {u['fail']} failed logins from {len(u['ips'])} IP(s) "
                         f"{_span(u['fail_lines'])}, {u['ok']} success")
    if state["facts"]:
        lines.append("- notes: " + " | ".join(state["facts"][-2:]))
    return _fit(lines, max_tokens, count_tokens)


def render_hints(index, chunk, max_tokens, count_tokens):
    """PRE-SCAN FLAGS block: suspicious lines our patterns found in THIS part."""
    groups = {}
    for n in range(chunk["start"], chunk["end"] + 1):
        info = index.info.get(n)
        if not info:
            continue
        for f in info.get("flags", []):
            if f in HINT_FLAGS:
                groups.setdefault((f, info.get("ip", "-")), []).append(n)
    lines = []
    for (f, ip), ns in sorted(groups.items(), key=lambda kv: kv[1][0]):
        lines.append(f"- {FLAG_LABEL[f]} ip={ip} x{len(ns)} at " + ",".join(f"L{x}" for x in ns[:6])
                     + ("..." if len(ns) > 6 else ""))
    return _fit(lines, max_tokens, count_tokens)


def part_ids(index, chunk):
    ips, users = set(), set()
    for n in range(chunk["start"], chunk["end"] + 1):
        info = index.info.get(n)
        if info:
            if info.get("ip"):
                ips.add(info["ip"])
            if info.get("user"):
                users.add(info["user"])
    return ips, users


def _fit(lines, max_tokens, count_tokens):
    """Drop lines from the end until the block fits its token allowance."""
    if max_tokens <= 0:
        return ""
    while lines:
        text = "\n".join(lines)
        if count_tokens(text) <= max_tokens:
            return text
        lines = lines[:-1]
    return ""
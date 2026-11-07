"""Line index + cheap pre-scan of every line.

The uploaded file stays on disk. We keep only:
  * the byte position where each line starts (8 bytes per line)
  * entry boundaries (multi-line entries like stack traces stay together)
  * a few parsed facts per line (ip, time, status, flags)
Log text is re-read from disk one part at a time when the model needs it.
"""
import calendar
import json
import re
from array import array
from urllib.parse import unquote_plus

# ---------------------------------------------------------------- patterns
IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])")
HTTP_REQ = re.compile(r"\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)")
STATUS_PATTERNS = [
    re.compile(r"HTTP/\d(?:\.\d)?\"?\s+(\d{3})\b"),
    re.compile(r"\b(?:status|code|response|resp)[\"']?\s*[=:]\s*[\"']?(\d{3})\b", re.I),
    re.compile(r"\"\s+(\d{3})\s+(?:\d+|-)\b"),
    re.compile(r"(?:->|=>)\s*(\d{3})\b"),
]
TS_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")
TS_APACHE = re.compile(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})")
TS_SYSLOG = re.compile(r"^(\w{3})\s+(\d{1,2})\s(\d{2}):(\d{2}):(\d{2})")
MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
USER_PATTERNS = [
    re.compile(r"for (?:invalid user )?([\w.@-]{1,64}) from", re.I),
    re.compile(r"\buser(?:name)?[\"']?\s*[=:]\s*[\"']?([\w.@-]{1,64})", re.I),
    re.compile(r"\buser\s+[\"']?([\w.@-]{1,64})[\"']?\s+(?:failed|logged|login|authenticated|authentication)", re.I),
]

AUTH_FAIL = re.compile(
    r"failed password|login failed|failed login|authentication fail|auth(?:entication)? failure|"
    r"invalid (?:user|password|credentials|login)|incorrect password|bad password|wrong password|"
    r"access denied for user|login attempt failed|unsuccessful login|failed to authenticate", re.I)
AUTH_OK = re.compile(
    r"accepted (?:password|publickey)|login success|successful login|logged in|login ok\b|"
    r"authentication succeeded|auth(?:entication)? success|session opened for user|login succeeded", re.I)
LOGIN_PATH = re.compile(r"/(?:login|signin|sign-in|logon|auth\b|authenticate|wp-login\.php|user/login|session|"
                        r"api/(?:v\d+/)?(?:auth|login|session|token))", re.I)
SQLI = re.compile(
    r"union(?:\s|\+|/\*.*?\*/)+(?:all(?:\s|\+)+)?select|'\s*or\s*'?\w+'?\s*=\s*'?\w|\bor\s+1\s*=\s*1|"
    r"'\s*(?:--|#)|;\s*drop\s+table|\bsleep\s*\(\s*\d|benchmark\s*\(|information_schema|waitfor\s+delay|"
    r"xp_cmdshell|\bselect\b.{0,40}\bfrom\b.{0,40}\b(?:users|passwords?|accounts)\b", re.I)
XSS = re.compile(r"<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+src", re.I)
TRAVERSAL = re.compile(r"\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini|/proc/self", re.I)
CMDI = re.compile(r"[;|&]\s*(?:cat|ls|id|whoami|wget|curl|nc|bash|sh|uname|rm)(?:\s|$|;|\|)|\$\([^)]*\)|`[^`]+`", re.I)
SCANNER_UA = re.compile(r"nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|dirb\b|wfuzz|ffuf|nuclei|"
                        r"acunetix|nessus|openvas|w3af|hydra|medusa|wpscan|feroxbuster|zap\b", re.I)
SCAN_PATH = re.compile(
    r"/(?:\.env|\.git|\.svn|\.htaccess|\.ds_store|wp-admin|wp-login|wp-config|phpmyadmin|pma\b|admin\.php|"
    r"config\.php|server-status|actuator|cgi-bin|backup|[\w-]*\.bak\b|shell\.php|xmlrpc\.php|"
    r"vendor/phpunit|solr|manager/html|\.aws|id_rsa|web\.config|\.well-known/security)", re.I)
ADMIN_PATH = re.compile(r"/(?:admin|administrator|manage|management|internal|private|root|api/(?:v\d+/)?admin)\b", re.I)
DENIED_TEXT = re.compile(r"unauthori[sz]ed|forbidden|permission denied|access denied|not authorized", re.I)
PROMPT_INJ = re.compile(
    r"ignore (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions|prompts|rules)|"
    r"disregard (?:all |the )?(?:above|previous|prior)|you are now|system prompt|<\|im_start\|>|"
    r"<\|im_end\|>|\[/?INST\]|mark (?:this|all|these)(?: log| lines?)? as (?:safe|benign|normal)|"
    r"(?:report|say|answer) (?:that )?(?:there are )?no (?:attacks|findings)|new instructions?:", re.I)
CONTINUATION = re.compile(r"^(?:\s|at\s|Caused by|\.\.\.\s*\d+\s+more|Traceback|File \"|\})")


def _parse_ts(line):
    m = TS_ISO.search(line)
    if m:
        y, mo, d, h, mi, s = map(int, m.groups())
        try:
            return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))
        except (ValueError, OverflowError):
            return None
    m = TS_APACHE.search(line)
    if m:
        d, mon, y, h, mi, s = m.groups()
        mo = MONTHS.get(mon.lower())
        if mo:
            return calendar.timegm((int(y), mo, int(d), int(h), int(mi), int(s), 0, 0, 0))
    m = TS_SYSLOG.search(line)
    if m:
        mon, d, h, mi, s = m.groups()
        mo = MONTHS.get(mon.lower())
        if mo:
            return calendar.timegm((2000, mo, int(d), int(h), int(mi), int(s), 0, 0, 0))
    return None


def deep_unquote(s, rounds=3):
    """URL-decode repeatedly so double-encoded payloads (%252e%252e) become visible."""
    for _ in range(rounds):
        if "%" not in s and "+" not in s:
            break
        nxt = unquote_plus(s)
        if nxt == s:
            break
        s = nxt
    return s


# field names commonly used by JSON loggers
J_IP = ("client_ip", "ip", "remote_addr", "src_ip", "source_ip", "clientip", "remote_ip")
J_TIME = ("time", "timestamp", "@timestamp", "ts", "datetime")
J_USER = ("username", "user", "user_name", "account", "login")
STD_KEYS = {"time", "timestamp", "@timestamp", "app", "host", "service", "level", "client_ip", "ip",
            "request_id", "method", "path", "url", "status", "response_bytes", "bytes", "duration_ms",
            "user_agent", "ua"}


def try_json(line):
    s = line.lstrip()
    if not s.startswith("{"):
        return None
    try:
        d = json.loads(s)
        return d if isinstance(d, dict) else None
    except (ValueError, RecursionError):
        return None


def _first(d, keys):
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return v
    return None

def parse_line(line):
    """Return a small dict of facts about one log line (never the line text itself)."""
    info = {}
    j = try_json(line)
    path = ""
    if j is not None:                       # JSON log line: read the fields directly
        ip = _first(j, J_IP)
        if isinstance(ip, str) and IPV4.fullmatch(ip.strip()):
            info["ip"] = ip.strip()
        t = _first(j, J_TIME)
        if isinstance(t, str):
            ts = _parse_ts(t)
            if ts is not None:
                info["ts"] = ts
        if isinstance(j.get("method"), str):
            info["method"] = j["method"].upper()[:10]
        p = j.get("path") or j.get("url")
        if isinstance(p, str):
            path = p[:300]
            info["path"] = path
        st = j.get("status")
        if isinstance(st, int) or (isinstance(st, str) and st.isdigit()):
            info["status"] = int(st)
        u = _first(j, J_USER)
        if isinstance(u, str):
            info["user"] = u[:64]
        if isinstance(j.get("session_id"), str):
            info["session"] = j["session_id"][:64]
        riw, ws = j.get("requests_in_window"), j.get("window_seconds")
        if isinstance(riw, (int, float)) and isinstance(ws, (int, float)) and ws > 0:
            info["rpm"] = int(riw * 60 / ws)    # server-reported request rate, per minute
        if set(j.keys()) - STD_KEYS:
            info["extra"] = 1                  # has unusual fields -> never "routine"
    # plain-text log lines (Apache, Nginx, syslog...): fall back to patterns
    if "ip" not in info:
        m = IPV4.search(line)
        if m:
            info["ip"] = m.group(0)
    if "ts" not in info:
        ts = _parse_ts(line)
        if ts is not None:
            info["ts"] = ts
    if "method" not in info:
        req = HTTP_REQ.search(line)
        if req:
            info["method"] = req.group(1)
            path = req.group(2)[:300]
            info["path"] = path
    if "status" not in info:
        for p in STATUS_PATTERNS:
            sm = p.search(line)
            if sm:
                info["status"] = int(sm.group(1))
                break
    if "user" not in info:
        for p in USER_PATTERNS:
            um = p.search(line)
            if um and um.group(1).lower() not in ("agent", "-", "none", "null"):
                info["user"] = um.group(1)[:64]
                break

    decoded = deep_unquote(line)
    status = info.get("status")
    flags = []
    is_login_req = bool(path and LOGIN_PATH.search(path))
    auth_result = str(j.get("auth_result", "")).lower() if j is not None else ""
    # for JSON, only system-written fields count: user-typed text could fake "failed login"
    auth_text = line if j is None else " ".join(
        str(j.get(k, "")) for k in ("message", "msg", "event", "auth_result", "error", "reason"))
    if (AUTH_FAIL.search(auth_text) or (is_login_req and status in (401, 403))
            or any(w in auth_result for w in ("fail", "invalid", "denied", "wrong"))):
        flags.append("auth_fail")
    elif (AUTH_OK.search(auth_text) or auth_result in ("success", "ok", "succeeded")
          or (is_login_req and info.get("method") == "POST" and status in (200, 302))):
        flags.append("auth_ok")
    if status == 429 or info.get("rpm", 0) >= 60:
        flags.append("rate")
    if SQLI.search(decoded):
        flags.append("sqli")
    if XSS.search(decoded):
        flags.append("xss")
    if TRAVERSAL.search(decoded):
        flags.append("traversal")
    if CMDI.search(decoded) and (info.get("method") or "cmd" in decoded.lower()):
        flags.append("cmdi")
    if SCANNER_UA.search(line):
        flags.append("scanner_ua")
    if path and SCAN_PATH.search(path):
        flags.append("scan_path")
    if status in (401, 403) or DENIED_TEXT.search(auth_text):
        if "auth_fail" not in flags:
            flags.append("denied")
    if path and ADMIN_PATH.search(path):
        flags.append("admin")
    if status == 404:
        flags.append("n404")
    if PROMPT_INJ.search(decoded):
        flags.append("inj")
    if re.search(r"\b(?:ERROR|CRITICAL|FATAL)\b", line):
        flags.append("error")
    if flags:
        info["flags"] = flags
    return info


def is_routine(info):
    """A plain successful GET with nothing suspicious."""
    return (info.get("method") in ("GET", "HEAD") and info.get("status") is not None
            and 200 <= info["status"] < 400 and not info.get("flags") and not info.get("extra"))


class LogIndex:
    def __init__(self, path):
        self.path = path
        self.offsets = array("Q")   # byte position where each line starts
        self.size = 0
        self.entries = []           # [(start_line, end_line)], 1-based, inclusive
        self.info = {}              # line number -> parsed facts
        self.n_lines = 0

    def build(self):
        offsets = self.offsets
        pos = 0
        entry_start = None
        with open(self.path, "rb") as f:
            for n, raw in enumerate(f, 1):
                offsets.append(pos)
                pos += len(raw)
                text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if entry_start is None:
                    entry_start = n
                elif text.strip() and not CONTINUATION.match(text):
                    self.entries.append((entry_start, n - 1))   # new entry starts here
                    entry_start = n
                if text.strip():
                    facts = parse_line(text)
                    if facts:
                        self.info[n] = facts
        self.n_lines = len(offsets)
        self.size = pos
        if entry_start is not None:
            self.entries.append((entry_start, self.n_lines))
        return self

    def read_lines(self, start, end):
        """Read lines start..end straight from disk (no copy of the whole file in memory)."""
        if start < 1 or end > self.n_lines or start > end:
            return []
        begin = self.offsets[start - 1]
        stop = self.offsets[end] if end < self.n_lines else self.size
        with open(self.path, "rb") as f:
            f.seek(begin)
            data = f.read(stop - begin)
        # split on b"\n" exactly like build() did, so line numbers always match
        parts = data.split(b"\n")
        if parts and parts[-1] == b"":
            parts.pop()
        return [p.rstrip(b"\r").decode("utf-8", errors="replace") for p in parts[: end - start + 1]]

    def line_text(self, n):
        lines = self.read_lines(n, n)
        return lines[0] if lines else ""
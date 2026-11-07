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
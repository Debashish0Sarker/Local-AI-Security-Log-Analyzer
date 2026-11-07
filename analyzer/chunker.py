"""Turn the indexed log into parts that fit the model's token budget.

* Every rendered line starts with its ORIGINAL line number ("L196|").
* Multi-line entries (stack traces) are never split unless one entry is bigger than a whole part.
* JSON lines are rendered compactly (noise dropped, URLs decoded) so more log fits per call.
  The report still shows the raw original line as evidence.
* Optional: runs of plain 2xx/3xx GETs are folded into one summary line, keeping the line range.
"""
import re
from collections import Counter

from . import config
from .logindex import deep_unquote, is_routine, try_json

CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
DROP_KEYS = {"host", "request_id", "response_bytes", "bytes", "duration_ms"}
BROWSER_UA = re.compile(r"^Mozilla/5\.0 \(", re.I)


def sanitize(text, limit=None):
    """Make log text safe to embed as data: no control chars, no fake delimiters or chat tokens."""
    text = CTRL.sub(" ", text)
    text = text.replace("<<<", "‹‹‹").replace(">>>", "›››").replace("<|", "‹|").replace("|>", "|›")
    limit = limit or config.MAX_LINE_CHARS
    if len(text) > limit:
        text = text[:limit] + f"…[+{len(text) - limit} chars]"
    return text


def compact_json(d):
    parts = []
    t = d.get("time") or d.get("timestamp") or d.get("@timestamp")
    if isinstance(t, str):
        m = re.search(r"\d{2}:\d{2}:\d{2}", t)
        parts.append(m.group(0) if m else t[:25])
    for k in ("app", "service", "level"):
        if d.get(k) not in (None, ""):
            parts.append(str(d[k]).replace(" ", "_"))
    ip = d.get("client_ip") or d.get("ip")
    if ip:
        parts.append(f"ip={ip}")
    if d.get("method") or d.get("path"):
        path = str(d.get("path") or d.get("url") or "")
        parts.append(f"{d.get('method', '')} {deep_unquote(path)}".strip())
    if d.get("status") is not None:
        parts.append(f"status={d['status']}")
    ua = d.get("user_agent") or d.get("ua")
    if isinstance(ua, str):
        parts.append("ua=browser" if BROWSER_UA.match(ua) else f"ua={ua[:40]}")
    used = {"time", "timestamp", "@timestamp", "app", "service", "level", "client_ip", "ip",
            "method", "path", "url", "status", "user_agent", "ua"} | DROP_KEYS
    for k, v in d.items():
        if k in used:
            continue
        if isinstance(v, (dict, list)):
            v = str(v)
        parts.append(f"{k}={str(v)[:140]}")
    return " ".join(parts)


def render_line(n, raw):
    j = try_json(raw)
    body = compact_json(j) if j is not None else raw.strip()
    return f"L{n}| {sanitize(body)}"


def render_routine_run(start, end, ips):
    top = Counter(ips).most_common(3)
    who = " ".join(f"{ip}x{c}" for ip, c in top)
    more = len(set(ips)) - len(top)
    return f"L{start}-L{end}| [{end - start + 1} routine 2xx/3xx GET lines: {who}{' +%d ips' % more if more > 0 else ''}]"


def build_units(index):
    """Units are what we pack: ['e', start, end] = a log entry, ['r', start, end] = folded routine run."""
    units, run = [], []
    compress = config.COMPRESS_ROUTINE

    def flush():
        if len(run) >= config.ROUTINE_RUN_MIN:
            units.append(["r", run[0], run[-1]])
        else:
            units.extend(["e", n, n] for n in run)
        run.clear()

    for start, end in index.entries:
        info = index.info.get(start)
        if compress and start == end and info and is_routine(info):
            run.append(start)
            if len(run) >= config.ROUTINE_RUN_MAX:
                flush()
            continue
        flush()
        units.append(["e", start, end])
    flush()
    return units


def render_unit(index, unit, lines=None):
    kind, start, end = unit
    if kind == "r":
        ips = [index.info.get(n, {}).get("ip", "?") for n in range(start, end + 1)]
        return render_routine_run(start, end, ips)
    lines = lines if lines is not None else index.read_lines(start, end)
    return "\n".join(render_line(n, t) for n, t in zip(range(start, end + 1), lines))


def render_units(index, units):
    """Render a whole part, reading its line range from disk once."""
    if not units:
        return ""
    s, e = units[0][1], units[-1][2]
    all_lines = index.read_lines(s, e)
    out = []
    for u in units:
        if u[0] == "r":
            out.append(render_unit(index, u))
        else:
            out.append(render_unit(index, u, all_lines[u[1] - s: u[2] - s + 1]))
    return "\n".join(out)


def plan_chunks(index, count_tokens, budget, progress=None):
    """Greedy packing: add units to a part until the next one would exceed the token budget."""
    units = build_units(index)
    chunks, cur, cur_tok = [], [], 0
    for i, u in enumerate(units):
        tok = count_tokens(render_unit(index, u)) + 1          # +1 for the joining newline
        if tok > budget and u[0] == "e" and u[2] > u[1]:
            pieces = [["e", n, n] for n in range(u[1], u[2] + 1)]   # huge entry: split by line
        else:
            pieces = [u]
        for p in pieces:
            ptok = tok if len(pieces) == 1 else count_tokens(render_unit(index, p)) + 1
            ptok = min(ptok, budget)
            if cur and cur_tok + ptok > budget:
                chunks.append({"units": cur, "est_tokens": cur_tok})
                cur, cur_tok = [], 0
            cur.append(p)
            cur_tok += ptok
        if progress and i % 25 == 0:
            progress(i, len(units))
    if cur:
        chunks.append({"units": cur, "est_tokens": cur_tok})
    for i, c in enumerate(chunks):
        c["i"] = i
        c["start"] = c["units"][0][1]
        c["end"] = c["units"][-1][2]
    return chunks
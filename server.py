"""Local AI Security Log Analyzer - web server (Python standard library only).

Run:  python server.py        then open http://127.0.0.1:8000
"""
import json
import os
import re
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from analyzer import config
from analyzer.jobs import ACTIVE, Manager
from analyzer.llm import make_client
from analyzer.logindex import LogIndex
from analyzer.report_md import to_markdown
from analyzer.sysinfo import snapshot

STATIC = os.path.join(config.BASE_DIR, "static")
ALLOWED_EXT = (".log", ".txt")
MANAGER = None
_health_cache = {"t": 0, "v": None}


class UploadError(Exception):
    pass


def validate_upload(path, filename, size):
    if not filename.lower().endswith(ALLOWED_EXT):
        raise UploadError("Only .log or .txt files are accepted.")
    if size == 0:
        raise UploadError("The file is empty.")
    with open(path, "rb") as f:
        head = f.read(65536)
    if b"\x00" in head:
        raise UploadError("This looks like a binary file, not a text log.")
    text = head.decode("utf-8", errors="replace")
    if text.count("\ufffd") > max(20, len(text) * 0.05):
        raise UploadError("The file is not readable UTF-8 text.")
    if not text.strip():
        raise UploadError("The file has no log lines.")


def model_health():
    now = time.time()
    if now - _health_cache["t"] > 3:
        ok, detail = MANAGER.client.health()
        _health_cache.update(t=now, v={"ok": ok, "detail": detail})
    return _health_cache["v"]


class Handler(BaseHTTPRequestHandler):
    server_version = "LogAnalyzer/1.0"

    def log_message(self, fmt, *args):
        line = args[0] if args else ""
        if isinstance(line, str) and line.startswith("GET /api/"):
            return                                 # keep the console quiet during polling
        sys.stderr.write("%s - %s\n" % (self.log_date_time_string(), fmt % args))

    def _json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, msg, status=400):
        self._json({"error": msg}, status)

    def _send(self, body, ctype, download=None):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
        self.end_headers()
        self.wfile.write(body)

    def _job(self, jid):
        job = MANAGER.jobs.get(jid)
        if not job:
            self._error("job not found", 404)
        return job

    # ---------------------------------------------------------- GET
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                return self._send(f.read(), "text/html; charset=utf-8")
        if path == "/api/status":
            busy = any(j.state["status"] in ACTIVE for j in MANAGER.jobs.values())
            return self._json({"model": MANAGER.client.describe(), "health": model_health(),
                               "memory": snapshot(), "busy": busy,
                               "limits": {"n_ctx": config.N_CTX, "max_upload_mb": config.MAX_UPLOAD_MB}})
        if path == "/api/jobs":
            jobs = sorted(MANAGER.jobs.values(), key=lambda j: j.state["created"], reverse=True)
            return self._json([{k: j.state.get(k) for k in ("id", "filename", "status", "created", "lines")}
                               for j in jobs])
        m = re.fullmatch(r"/api/jobs/([\w-]+)(/report(?:\.md|\.json)?)?", path)
        if m:
            job = self._job(m.group(1))
            if not job:
                return
            if not m.group(2):
                return self._json(job.summary())
            rep = job.report()
            if rep is None:
                return self._error("report not ready", 409)
            if m.group(2) == "/report.md":
                return self._send(to_markdown(rep).encode("utf-8"), "text/markdown; charset=utf-8",
                                  f"report-{job.id}.md")
            if m.group(2) == "/report.json":
                return self._send(json.dumps(rep, ensure_ascii=False, indent=1).encode("utf-8"),
                                  "application/json", f"report-{job.id}.json")
            return self._json(rep)
        self._error("not found", 404)

    # ---------------------------------------------------------- POST
    def do_POST(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/upload":
                return self._upload()
            if path == "/api/model":
                return self._switch_model()
            m = re.fullmatch(r"/api/jobs/([\w-]+)/(start|cancel|retry)", path)
            if m:
                job = self._job(m.group(1))
                if not job:
                    return
                act = m.group(2)
                if act == "start" and not MANAGER.start(job.id):
                    return self._error("job is already running", 409)
                if act == "cancel":
                    MANAGER.cancel(job.id)
                if act == "retry" and not MANAGER.retry_failed(job.id):
                    return self._error("no failed parts to retry", 409)
                return self._json(job.summary())
        except UploadError as e:
            return self._error(str(e), 400)
        self._error("not found", 404)

    def _upload(self):
        filename = os.path.basename(self.headers.get("X-Filename", "") or "upload.log")[:120]
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            raise UploadError("No file received.")
        if length > config.MAX_UPLOAD_MB * 2**20:
            raise UploadError(f"File too large (limit {config.MAX_UPLOAD_MB} MB).")
        tmp_dir = os.path.join(config.DATA_DIR, "uploads")
        os.makedirs(tmp_dir, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=tmp_dir, suffix=".part")
        try:
            remaining = length
            with os.fdopen(fd, "wb") as out:          # stream to disk in 64 KB pieces
                while remaining > 0:
                    piece = self.rfile.read(min(65536, remaining))
                    if not piece:
                        raise UploadError("Upload was interrupted.")
                    out.write(piece)
                    remaining -= len(piece)
            validate_upload(tmp, filename, length)
            idx = LogIndex(tmp).build()
            job = MANAGER.create_job(filename, tmp, idx.n_lines, idx.size)
        except Exception:
            if os.path.exists(tmp):
                os.remove(tmp)
            raise
        return self._json(job.summary(), 201)

    def _switch_model(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(min(n, 65536)) or b"{}")
        except ValueError:
            raise UploadError("invalid JSON body")
        if any(j.state["status"] in ACTIVE for j in MANAGER.jobs.values()):
            return self._error("cannot switch model while a job is running", 409)
        backend = str(body.get("backend") or config.LLM_BACKEND)
        if backend not in ("llamacpp", "ollama"):
            return self._error("backend must be llamacpp or ollama")
        MANAGER.client = make_client(backend, body.get("url") or None, body.get("model") or None)
        _health_cache["t"] = 0
        return self._json({"model": MANAGER.client.describe()})


def main():
    global MANAGER
    os.makedirs(config.DATA_DIR, exist_ok=True)
    MANAGER = Manager()
    srv = ThreadingHTTPServer((config.HOST, config.PORT), Handler)
    srv.daemon_threads = True
    print(f"Log analyzer on http://{config.HOST}:{config.PORT}  (model: {config.LLM_BACKEND} @ {MANAGER.client.url})")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("stopping")


if __name__ == "__main__":
    main()
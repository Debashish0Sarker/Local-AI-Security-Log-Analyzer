"""TEST DOUBLE ONLY - imitates llama-server's HTTP API so retries and error handling can be tested
without a model. Never used for real analysis.

  python tools/mock_llama_server.py --port 8081 --faults "json:2,timeout:4,trunc:6,halluc:3"

Faults (by call number): json = garbage reply, timeout = never answers, trunc = JSON cut off,
halluc = cites a line outside the part.
"""
import argparse
import json
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOK = re.compile(r"\d|[A-Za-z]{1,4}|[^\w\s]|\s+")
CALLS = {"n": 0}
FAULTS = {}
DELAY = {"s": 0.05}


def ntok(s):
    return len(TOK.findall(s))


def fake_findings(user_text):
    m = re.search(r"<<<LOG\n(.*)\nLOG>>>", user_text, re.S)
    found = {}
    for line in (m.group(1) if m else "").splitlines():
        lm = re.match(r"L(\d+)", line)
        if not lm:
            continue
        n = int(lm.group(1))
        ipm = re.search(r"ip=([\d.]+)", line)
        ip = ipm.group(1) if ipm else "unknown"
        rules = [("status=401", "Brute Force", "Medium"), ("OR 1=1", "SQL Injection", "High"),
                 ("UNION SELECT", "SQL Injection", "High"), ("status=429", "High Request Rate", "Medium"),
                 ("etc/passwd", "Path Traversal", "High"), ("/.env", "Scanning", "Medium"),
                 ("Ignore previous", "Log Injection Attempt", "Medium"),
                 ("auth_result=success", "Account Compromise", "Critical"),
                 ("status=500", "Other", "High")]          # deliberate false positive
        for needle, t, sev in rules:
            if needle in line:
                f = found.setdefault((t, ip), {"type": t, "severity": sev, "ip": ip, "lines": [],
                                               "reason": "mock", "action": "investigate"})
                f["lines"].append(n)
    return {"findings": list(found.values())[:5], "facts": "mock facts"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/health":
            return self._send({"status": "ok"})
        if self.path == "/props":
            return self._send({"model_path": "MOCK", "default_generation_settings": {"n_ctx": 2048}})
        self._send({"error": "nf"}, 404)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if self.path == "/tokenize":
            return self._send({"tokens": list(range(ntok(body.get("content", ""))))})
        if self.path == "/apply-template":
            p = "".join(f"<|im_start|>{m['role']}\n{m['content']}<|im_end|>\n" for m in body["messages"])
            return self._send({"prompt": p + "<|im_start|>assistant\n"})
        if self.path == "/v1/chat/completions":
            CALLS["n"] += 1
            fault = FAULTS.get(CALLS["n"])
            user = body["messages"][-1]["content"]
            ptok = sum(ntok(m["content"]) for m in body["messages"])
            if fault == "timeout":
                time.sleep(9999)
            if "VERIFIED FINDINGS" in user:
                content = json.dumps({"summary": "Mock summary.", "priorities": ["Block attacker IPs"]})
            else:
                obj = fake_findings(user)
                if fault == "halluc" and obj["findings"]:
                    obj["findings"][0]["lines"] = [999999]
                content = json.dumps(obj)
                if fault == "json":
                    content = "Sure! Here are the findings: type=Brute Force ..."
                if fault == "trunc":
                    content = content[: max(20, len(content) * 2 // 3)]
            time.sleep(DELAY["s"])
            return self._send({"choices": [{"message": {"content": content}, "finish_reason": "stop"}],
                               "usage": {"prompt_tokens": ptok, "completion_tokens": ntok(content)}})
        self._send({"error": "nf"}, 404)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--faults", default="")
    ap.add_argument("--delay", type=float, default=0.05)
    a = ap.parse_args()
    DELAY["s"] = a.delay
    for item in filter(None, a.faults.split(",")):
        k, v = item.split(":")
        FAULTS[int(v)] = k
    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()
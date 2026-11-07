"""Runtime settings. Every value can be overridden with an environment variable."""
import os


def _env(name, default):
    raw = os.environ.get(name)
    raw = raw.strip() if raw is not None else None
    if raw is None or raw == "":
        return default
    if isinstance(default, bool):
        return raw.lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        return int(raw)
    if isinstance(default, float):
        return float(raw)
    return raw


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---- server ----
HOST = _env("HOST", "127.0.0.1")
PORT = _env("PORT", 8000)
DATA_DIR = _env("DATA_DIR", os.path.join(BASE_DIR, "data"))
MAX_UPLOAD_MB = _env("MAX_UPLOAD_MB", 20)

# ---- local model ----
LLM_BACKEND = _env("LLM_BACKEND", "llamacpp")      # "llamacpp" or "ollama"
LLM_URL = _env("LLM_URL", "http://127.0.0.1:8080")
LLM_MODEL = _env("LLM_MODEL", "qwen3.5-2b")
LLM_TIMEOUT = _env("LLM_TIMEOUT", 240)             # seconds per model call
LLM_MAX_ATTEMPTS = _env("LLM_MAX_ATTEMPTS", 3)
LLM_TEMPERATURE = _env("LLM_TEMPERATURE", 0.1)

# ---- token budget (everything must fit in N_CTX) ----
N_CTX = _env("N_CTX", 2048)
REPLY_TOKENS = _env("REPLY_TOKENS", 440)      # kept free for the model's answer
CONTEXT_TOKENS = _env("CONTEXT_TOKENS", 300)  # memory from earlier parts + hints
SAFETY_TOKENS = _env("SAFETY_TOKENS", 48)     # slack for rounding
MAX_LINE_CHARS = _env("MAX_LINE_CHARS", 360)  # very long lines are cut for the model only

# ---- splitting ----
COMPRESS_ROUTINE = _env("COMPRESS_ROUTINE", True)  # fold boring 200-OK lines into one summary line
ROUTINE_RUN_MIN = _env("ROUTINE_RUN_MIN", 4)
ROUTINE_RUN_MAX = _env("ROUTINE_RUN_MAX", 60)
RULE_HINTS = _env("RULE_HINTS", True)

# ---- thresholds for linking attacks across parts ----
BRUTE_MIN_FAILS = _env("BRUTE_MIN_FAILS", 5)
BRUTE_HIGH_FAILS = _env("BRUTE_HIGH_FAILS", 15)
COMPROMISE_MIN_FAILS = _env("COMPROMISE_MIN_FAILS", 3)
RATE_MEDIUM_RPM = _env("RATE_MEDIUM_RPM", 60)
RATE_HIGH_RPM = _env("RATE_HIGH_RPM", 120)
SCAN_MIN_HITS = _env("SCAN_MIN_HITS", 5)
SCAN_MIN_404_PATHS = _env("SCAN_MIN_404_PATHS", 8)
DENIED_MIN = _env("DENIED_MIN", 3)
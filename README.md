# Local AI Security Log Analyzer

A small web app that finds possible attacks in server logs with a **local** language model
(Qwen3.5-2B, 4-bit, CPU only). The log is larger than the model's 2,048-token window, so the app
splits it into token-measured parts, analyzes them one call at a time, carries what it learned into
the next call, and merges everything into one report with linked, cross-part attack chains.

* Backend: **Python standard library only** (no pip packages) - ~34 MB RAM.
* Model server: **llama.cpp `llama-server`** (exact model tokenizer via `/tokenize`, JSON-schema
  constrained output). Ollama is supported as a second backend.
* Works fully offline after the one-time model download.

```
upload ─► line index (byte offsets) ─► entries ─► compact render ─► token-budgeted parts
                                                                        │ one call at a time
          ┌─────────── carried memory (per-IP / per-user facts) ◄───────┤
          ▼                                                             ▼
   EARLIER FACTS + pre-scan flags + part ──► local model ──► JSON repair ──► evidence check
                                                                        │ checkpoint after every part
                                                                        ▼
                     cross-part correlator ──► merge / dedupe ──► chains ──► summary call ──► report
```

## Setup

### Option A - run directly (Windows, Linux, macOS)
1. Install llama.cpp (`winget install llama.cpp`, `brew install llama.cpp`, or a release zip from
   https://github.com/ggml-org/llama.cpp/releases).
2. Download the model (1.28 GB) into `models/`:
   `powershell scripts/download_model.ps1` (Windows) or `sh scripts/download_model.sh`, or fetch
   `Qwen3.5-2B-Q4_K_M.gguf` from https://huggingface.co/unsloth/Qwen3.5-2B-GGUF.
3. Start the model server with the assessment limits (CPU only, 2 threads, one 2048-token slot):
   ```
   llama-server -m models/Qwen3.5-2B-Q4_K_M.gguf -c 2048 -np 1 -t 2 -ngl 0 --jinja --port 8080
   ```
   `-np 1` matters: otherwise newer builds split the 2048 context across parallel slots.
4. In a second terminal start the app (Python 3.9+): `python server.py` and open http://127.0.0.1:8000.

### Option B - Docker (reproduces the 4 GB / 2 vCPU / no-GPU box)
```bash
sh scripts/download_model.sh
docker compose up --build             # open http://localhost:8000
```
`docker-compose.yml` caps the model container at 3.4 GB / 1.75 CPU and the app at 512 MB / 0.25 CPU.

### Using Ollama instead
```
ollama pull qwen3.5:2b
$env:LLM_BACKEND="ollama"; $env:LLM_MODEL="qwen3.5:2b"; python server.py
```
Ollama has no tokenize endpoint, so token counts are estimated (cautious chars/token, corrected from
`prompt_eval_count` after every call) - llama.cpp is the recommended backend.

### Try one part against the real model
```
python tools/try_part.py tests/sample_server.log 196        # part with line 196, with memory + hints
python tools/try_part.py tests/sample_server.log 217 bare   # model alone, no memory, no hints
```

### Tests (no model needed)
```
python -m unittest discover tests
python tools/mock_llama_server.py --port 8081 --faults "json:2,timeout:4,trunc:6,halluc:3"
$env:LLM_URL="http://127.0.0.1:8081"; $env:LLM_TIMEOUT="3"; python tools/analyze_cli.py tests/sample_server.log
```
The mock is a fake model server that injects failures (garbage reply, timeout, cut-off JSON, made-up
line numbers) to test error handling. It is never used for analysis.

## Model details
| | |
|---|---|
| Model | Qwen3.5-2B, GGUF Q4_K_M (1.28 GB), text only |
| Runtime | llama.cpp `llama-server`, `-c 2048 -np 1 -t 2 -ngl 0` |
| Generation | temperature 0.1 (0 on retries), max 440 output tokens, thinking disabled |
| Output format | JSON schema sent as `response_format`; tolerant parser as a second line of defence |
| RAM (measured, Windows) | model server ~2.8 GB, backend ~34 MB, total ~2.84 GB < 4 GB |
| Speed (measured) | ~45 tokens/s reading, ~9.4 tokens/s writing, 18-51 s per call, ~7 min for the sample log |
| Switching | `LLM_BACKEND`, `LLM_URL`, `LLM_MODEL` env vars, or `POST /api/model` |

## How the log is split
1. **Index, don't copy.** The upload is streamed to disk in 64 KB pieces. The indexer keeps only the
   byte position of every line (8 bytes/line) and a few parsed facts per line (IP, time, method, path,
   status, user, flags). Log text is re-read from disk one part at a time.
2. **Entries, not lines.** Continuation lines (indented, `at ...`, `Caused by`, `Traceback`) stay with
   the entry above, so stack traces are never cut. Only an entry bigger than a whole part is split.
3. **Compact rendering.** JSON lines become e.g.
   `L196| 10:10:10 cultive8_workspace gateway INFO ip=203.0.113.44 POST /api/v1/auth/login status=200 ...`
   - noise fields dropped, URLs fully decoded (`%252e%252e` → `../`), browser user-agents shortened.
   Every line keeps its **original line number**; the report shows the raw original line as evidence.
4. **Routine folding.** Runs of 4+ plain 2xx/3xx GET lines become one line,
   `L6-L10| [5 routine 2xx/3xx GET lines: ...]`. Set `COMPRESS_ROUTINE=false` to send every line.
5. **Token-measured packing.** Every unit is measured with the model's own tokenizer and packed into
   parts that fit the log budget. Before each call the full prompt is measured again; on overflow,
   memory is trimmed first, then hints, then the part is split in two.

### Token budget per call (2,048)
| Slice | Tokens | Notes |
|---|---|---|
| System prompt + part header | 383 (measured) | identical every call, so llama.cpp reuses its cache |
| Memory + pre-scan flags | ≤ 300 | trimmed line by line to fit |
| Log text | 877 (= 2048 − 383 − 300 − 440 − 48) | measured with `/tokenize` |
| Model reply | 440 reserved | max 5 findings, short reasons |
| Slack | 48 | rounding |

The sample log (258 lines) becomes **12 parts**.

## Linking events across parts
After each part the app updates a small **memory** (saved in the checkpoint): per IP - failed and
successful logins with line numbers, SQLi / traversal / scan hits, denied requests, peak request rate,
users targeted, which parts it appeared in, what the model already flagged; per user - failures and
source IPs. Before each call the most relevant entries (IPs that are also in the current part first)
are written into the prompt as `EARLIER FACTS`, e.g.

```
- 203.0.113.44: 11 failed logins L5..L153 user workspace.admin (parts 1-7) <- ALSO IN THIS PART
```

so when part 9 contains `auth_result=success` from that IP, the model can call it an account
compromise - which the real model did, although part 9 itself shows only one failed login.

After the last part a **correlator** runs over the same memory for the whole file: brute force →
success → admin/export requests, SQLi repeated across parts, scanning → traversal → admin access,
request bursts. Findings with the same (type, IP) are merged, and findings on one IP become an
ordered **attack chain**.

## Accuracy safeguards
* **Evidence check:** a model finding is kept only if it cites line numbers inside its part and at least
  one cited line has a security signal. Wrong IPs are corrected from the cited lines. Made-up or
  routine-only findings are dropped and counted ("Rejected findings" - 5 in the real run).
* **Normal errors are not attacks:** a single wrong password followed by success, DB timeouts, 500s,
  503s during a deploy and isolated 404s are rejected or listed under "Seen but not treated as attacks".
* **Confirmed vs suspected:** model findings not backed by the pre-scan are capped at Medium and marked
  `suspected`; the model can raise a rule-backed severity by one level at most.
* **Prompt injection:** log text is fenced in `<<<LOG ... LOG>>>`, look-alike delimiters and chat tokens
  are neutralised, the prompt says log text is data, and instruction-like text is reported as a
  `Log Injection Attempt`. Nothing in a log is executed. The dashboard inserts log text as plain text only.

## Reliability
* One model call at a time (one worker thread + a lock) - stays inside the RAM budget.
* Per-call timeout (240 s), up to 3 attempts with backoff, temperature 0 and a "JSON only" reminder on
  retry, split into two smaller calls after repeated bad JSON.
* Broken JSON: `<think>` / fence stripping, auto-closing of cut-off replies, cut-back repair, salvage of
  single findings - never crashes.
* Checkpoint (atomic write) after every part. **Restarting the server resumes the job** from the next
  unfinished part; completed findings are kept. Failed parts can be retried from the dashboard.
* Upload checks: extension, size limit, empty file, binary file, unreadable text.

## Known limits
* A 2B model on 2 CPU threads is slow (~7 min for the sample log). Qwen3.5-0.8B is faster but less reliable.
* The model alone did not report the L217 injection text (it never obeyed it either); the correlator does.
* Severity and chains lean on the deterministic correlator; the model adds per-part judgement, reasons
  and actions. Model-only findings without backing signals stay `suspected`.
* Timestamps: ISO-8601, Apache/Nginx and syslog formats; others still work but rate detection then
  relies on server-reported counters or on the model.
* IPv6 addresses are not tracked as IDs yet (the model still sees them).
* Ollama token counts are estimates; llama.cpp counts are exact.
* Model RAM is shown only when the model server runs on the same machine (needs `psutil` on Windows).
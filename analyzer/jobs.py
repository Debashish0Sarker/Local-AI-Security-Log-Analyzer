"""Job storage, the single model worker, checkpoints and resume."""
import json
import os
import queue
import threading
import time
import traceback
import uuid

from . import config, prompts
from .chunker import plan_chunks, render_units
from .findings import build_chains, benign_noise, correlate, merge, validate, SEV_RANK
from .jsonfix import parse_model_json
from .llm import LLMError, LLMTimeout, make_client
from .logindex import LogIndex
from .memory import (apply_part, new_state, note_facts, note_model_findings, part_ids,
                     render_earlier, render_hints)

ACTIVE = ("queued", "planning", "running", "summarizing")


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def atomic_write_json(path, obj):
    """Write to a temp file, then swap it in: a crash mid-write never leaves a broken file."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


class PartOverflow(Exception):
    pass


class Job:
    def __init__(self, job_dir, state):
        self.dir = job_dir
        self.state = state
        self.lock = threading.RLock()
        self._index = None

    @property
    def id(self):
        return self.state["id"]

    @property
    def log_path(self):
        return os.path.join(self.dir, "input.log")

    @property
    def index(self):
        if self._index is None:
            self._index = LogIndex(self.log_path).build()
        return self._index

    def save(self):
        with self.lock:
            atomic_write_json(os.path.join(self.dir, "state.json"), self.state)

    def event(self, msg, level="info"):
        with self.lock:
            ev = self.state.setdefault("events", [])
            ev.append({"t": _now(), "level": level, "msg": msg})
            del ev[:-300]

    def report(self):
        p = os.path.join(self.dir, "report.json")
        if os.path.exists(p):
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        return None

    def summary(self):
        """What the dashboard polls: progress, per-part timing, events, memory preview."""
        with self.lock:
            s = self.state
            parts = s.get("parts", [])
            done = sum(1 for p in parts if p["status"] in ("done", "failed"))
            times = [p["ms"] for p in parts if p.get("ms")]
            avg = int(sum(times) / len(times)) if times else None
            remaining = sum(1 for p in parts if p["status"] not in ("done", "failed"))
            return {
                "id": s["id"], "filename": s["filename"], "status": s["status"], "created": s["created"],
                "phase": s.get("phase", ""), "lines": s.get("lines"), "bytes": s.get("bytes"),
                "parts_total": len(parts), "parts_done": done,
                "parts_failed": sum(1 for p in parts if p["status"] == "failed"),
                "current_part": s.get("current_part"), "avg_call_ms": avg,
                "eta_s": int(avg * remaining / 1000) if avg else None,
                "budget": s.get("budget"),
                "parts": [{k: p.get(k) for k in ("i", "start", "end", "status", "attempts", "ms", "est_tokens",
                                                 "prompt_tokens", "server_prompt_tokens", "completion_tokens",
                                                 "findings", "dropped", "json", "error")} for p in parts],
                "live_findings": len(s.get("model_findings", [])),
                "context_preview": s.get("context_preview", ""),
                "events": s.get("events", [])[-40:], "error": s.get("error"),
                "stats": s.get("stats", {}), "has_report": s["status"] == "done",
            }


class Manager:
    def __init__(self, data_dir=None, client=None):
        self.data_dir = os.path.join(data_dir or config.DATA_DIR, "jobs")
        os.makedirs(self.data_dir, exist_ok=True)
        self.client = client or make_client()
        self.jobs = {}
        self.q = queue.Queue()
        self.client_lock = threading.Lock()       # one model call at a time
        self._load_existing()
        self.worker = threading.Thread(target=self._loop, name="model-worker", daemon=True)
        self.worker.start()

    # ------------------------------------------------------------ storage
    def _load_existing(self):
        """On startup: reload every job; jobs that were running are resumed from their checkpoint."""
        for jid in sorted(os.listdir(self.data_dir)):
            sp = os.path.join(self.data_dir, jid, "state.json")
            if not os.path.exists(sp):
                continue
            try:
                with open(sp, encoding="utf-8") as f:
                    state = json.load(f)
            except (OSError, ValueError):
                continue
            job = Job(os.path.join(self.data_dir, jid), state)
            self.jobs[jid] = job
            if state.get("status") in ACTIVE:
                done = sum(1 for p in state.get("parts", []) if p["status"] in ("done", "failed"))
                state["status"] = "queued"
                job.event(f"Server restarted: resuming from checkpoint ({done} part(s) already done).", "warn")
                job.save()
                self.q.put(jid)

    def create_job(self, filename, src_path, n_lines, n_bytes):
        jid = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        jdir = os.path.join(self.data_dir, jid)
        os.makedirs(jdir)
        os.replace(src_path, os.path.join(jdir, "input.log"))     # move, no extra copy
        state = {"id": jid, "filename": filename, "created": _now(), "status": "uploaded",
                 "lines": n_lines, "bytes": n_bytes, "parts": [], "memory": new_state(),
                 "model_findings": [], "events": [], "stats": {}}
        job = Job(jdir, state)
        job.event(f"Uploaded {filename}: {n_lines} lines, {n_bytes} bytes.")
        job.save()
        self.jobs[jid] = job
        return job

    def start(self, jid):
        job = self.jobs[jid]
        with job.lock:
            if job.state["status"] in ACTIVE:
                return False
            job.state["status"] = "queued"
            job.state["cancel"] = False
            job.event("Queued for analysis.")
            job.save()
        self.q.put(jid)
        return True

    def retry_failed(self, jid):
        job = self.jobs[jid]
        with job.lock:
            n = 0
            for p in job.state["parts"]:
                if p["status"] == "failed":
                    p["status"], p["error"] = "pending", None
                    n += 1
            if not n:
                return 0
            job.state["status"] = "queued"
            job.event(f"Retrying {n} failed part(s); completed findings are kept.")
            job.save()
        self.q.put(jid)
        return n

    def cancel(self, jid):
        job = self.jobs[jid]
        with job.lock:
            job.state["cancel"] = True
            job.event("Cancel requested; stopping after the current call.", "warn")
            job.save()

    # ------------------------------------------------------------ worker
    def _loop(self):
        while True:
            jid = self.q.get()
            job = self.jobs.get(jid)
            if not job or job.state["status"] != "queued":
                continue
            try:
                self._run(job)
            except Exception as e:          # a bug in one job must never kill the worker
                with job.lock:
                    job.state["status"] = "failed"
                    job.state["error"] = f"{type(e).__name__}: {e}"
                    job.event("Unexpected error: " + "".join(traceback.format_exception_only(type(e), e)).strip(), "error")
                    job.save()

    def _wait_for_model(self, job, tries=30):
        for i in range(tries):
            ok, detail = self.client.health()
            if ok:
                return True
            if i == 0:
                job.event(f"Waiting for local model server ({detail})...", "warn")
            time.sleep(2)
        return False

    def _set(self, job, **kw):
        with job.lock:
            job.state.update(kw)
            job.save()

    def _run(self, job):
        self._set(job, status="planning", phase="checking model server", error=None)
        if not self._wait_for_model(job):
            self._set(job, status="failed", phase="",
                      error="Local model server is not reachable. Start it and press Start again.")
            return
        index = job.index
        st = job.state
        if not st["parts"]:
            self._plan(job, index)
        st["status"] = "running"
        job.save()
        t_start = time.time()
        for p in st["parts"]:
            if st.get("cancel"):
                self._set(job, status="cancelled", phase="cancelled by user", current_part=None)
                return
            if p["status"] in ("done", "failed"):       # already finished before a restart
                continue
            self._set(job, current_part=p["i"] + 1, phase=f"analyzing part {p['i'] + 1}/{len(st['parts'])}")
            p["status"] = "running"
            self._do_part(job, index, p)
        self._finalize(job, index, time.time() - t_start)

    def _plan(self, job, index):
        st = job.state
        count = self.client.count_tokens
        empty_user = prompts.user_prompt(1, 99, 1, 99999, "", "", "")
        base = self.client.count_prompt([{"role": "system", "content": prompts.SYSTEM_PROMPT},
                                         {"role": "user", "content": empty_user}])
        budget = config.N_CTX - config.REPLY_TOKENS - config.CONTEXT_TOKENS - config.SAFETY_TOKENS - base
        if budget < 200:
            raise RuntimeError(f"token budget too small ({budget}); lower REPLY_TOKENS/CONTEXT_TOKENS")
        st["budget"] = {"n_ctx": config.N_CTX, "prompt_base": base, "context": config.CONTEXT_TOKENS,
                        "reply": config.REPLY_TOKENS, "safety": config.SAFETY_TOKENS, "log_per_part": budget,
                        "exact_tokenizer": self.client.exact_tokens}
        job.event(f"Token budget per call: {config.N_CTX} = prompt {base} + memory/hints {config.CONTEXT_TOKENS} "
                  f"+ log {budget} + reply {config.REPLY_TOKENS} + slack {config.SAFETY_TOKENS}.")

        def prog(i, total):
            self._set(job, phase=f"splitting: measuring tokens {i}/{total} units")

        chunks = plan_chunks(index, count, budget, prog)
        st["parts"] = [{"i": c["i"], "start": c["start"], "end": c["end"], "units": c["units"],
                        "est_tokens": c["est_tokens"], "status": "pending", "attempts": 0, "applied": False}
                       for c in chunks]
        st["entries"] = len(index.entries)
        job.event(f"Split {index.n_lines} lines ({len(index.entries)} entries) into {len(chunks)} parts.")
        job.save()
        
    def _messages(self, part, total, earlier, hints, log_text, strict):
        return [{"role": "system", "content": prompts.SYSTEM_PROMPT},
                {"role": "user", "content": prompts.user_prompt(part["i"] + 1, total, part["start"], part["end"],
                                                                earlier, hints, log_text, strict)}]

    def _call_model(self, job, index, part, units, total, strict, temperature):
        """Build a prompt that provably fits, call the model, parse its JSON."""
        st = job.state
        mem = st["memory"]
        count = self.client.count_tokens
        sub = dict(part, start=units[0][1], end=units[-1][2])
        ips, users = part_ids(index, sub)
        hint_budget = int(config.CONTEXT_TOKENS * 0.45) if config.RULE_HINTS else 0
        hints = render_hints(index, sub, hint_budget, count) if hint_budget else ""
        earlier = render_earlier(mem, ips, users, config.CONTEXT_TOKENS - (count(hints) if hints else 0), count)
        log_text = render_units(index, units)
        msgs = self._messages(sub, total, earlier, hints, log_text, strict)
        n = self.client.count_prompt(msgs)
        limit = config.N_CTX - config.REPLY_TOKENS
        if n > limit:                       # shrink memory first, then hints, else split the part
            over = n - limit + 8
            earlier = render_earlier(mem, ips, users, max(0, count(earlier) - over), count) if earlier else ""
            msgs = self._messages(sub, total, earlier, hints, log_text, strict)
            n = self.client.count_prompt(msgs)
            if n > limit:
                hints = ""
                msgs = self._messages(sub, total, earlier, hints, log_text, strict)
                n = self.client.count_prompt(msgs)
            if n > limit:
                raise PartOverflow(f"{n} prompt tokens > {limit}")
        with job.lock:
            st["context_preview"] = (f"[part {part['i'] + 1}] prompt={n} tokens (+{config.REPLY_TOKENS} reply)\n"
                                     f"EARLIER FACTS:\n{earlier or 'none yet'}\n\nPRE-SCAN FLAGS:\n{hints or 'none'}")
        with self.client_lock:
            text, meta = self.client.chat(msgs, config.REPLY_TOKENS, temperature, prompts.SCHEMA)
        meta["prompt_tokens_counted"] = n
        obj, how = parse_model_json(text)
        return obj, how, meta, sub, text

    def _do_part(self, job, index, part):
        st = job.state
        total = len(st["parts"])
        last_err = None
        results = []
        stats = st.setdefault("stats", {})
        for k in ("calls", "retries", "timeouts", "json_repaired", "json_failed", "dropped", "split_parts", "model_ms"):
            stats.setdefault(k, 0)
        t0 = time.time()
        units_list = [part["units"]]        # a part may be split into smaller calls if needed
        attempt = 0
        while units_list and attempt < config.LLM_MAX_ATTEMPTS + 2:
            units = units_list[0]
            attempt += 1
            part["attempts"] = attempt
            strict = last_err == "json"
            temp = 0.0 if attempt > 1 else config.LLM_TEMPERATURE
            try:
                obj, how, meta, sub, raw = self._call_model(job, index, part, units, total, strict, temp)
                stats["calls"] += 1
                stats["model_ms"] += meta.get("ms") or 0
                part["prompt_tokens"] = meta.get("prompt_tokens_counted")
                part["server_prompt_tokens"] = meta.get("prompt_tokens")
                part["completion_tokens"] = meta.get("completion_tokens")
                if obj is None:
                    stats["json_failed"] += 1
                    last_err = "json"
                    job.event(f"Part {part['i'] + 1}: reply was not usable JSON ({how}); retrying. "
                              f"Raw start: {raw[:80]!r}", "warn")
                    if attempt >= 2 and len(units) > 1:
                        units_list = [units[: len(units) // 2], units[len(units) // 2:]] + units_list[1:]
                        stats["split_parts"] += 1
                        job.event(f"Part {part['i'] + 1}: splitting into two smaller calls.", "warn")
                    continue
                if how != "ok":
                    stats["json_repaired"] += 1
                    job.event(f"Part {part['i'] + 1}: repaired model JSON ({how}).", "warn")
                part["json"] = how
                results.append((obj, sub))
                units_list.pop(0)
                last_err = None
            except PartOverflow as e:
                if len(units) == 1:
                    last_err = "overflow"
                    job.event(f"Part {part['i'] + 1}: single unit too large ({e}); skipping model for it.", "error")
                    units_list.pop(0)
                    continue
                units_list = [units[: len(units) // 2], units[len(units) // 2:]] + units_list[1:]
                stats["split_parts"] += 1
                attempt -= 1
            except LLMTimeout as e:
                stats["timeouts"] += 1
                stats["retries"] += 1
                last_err = "timeout"
                job.event(f"Part {part['i'] + 1}: model timeout ({e}); retry {attempt}/{config.LLM_MAX_ATTEMPTS}.", "warn")
                time.sleep(min(2 * attempt, 10))
            except LLMError as e:
                stats["retries"] += 1
                last_err = "error"
                job.event(f"Part {part['i'] + 1}: model call failed ({e}); retry {attempt}.", "warn")
                time.sleep(min(2 * attempt, 10))
                ok, _ = self.client.health()
                if not ok:
                    self._wait_for_model(job, tries=15)

        # check findings, then add this part's facts to memory exactly once
        kept, dropped = [], 0
        for obj, sub in results:
            f, d, notes = validate(obj, sub, index, st["memory"])
            kept += f
            dropped += d
            for n in notes[:3]:
                job.event(f"Part {part['i'] + 1}: {n}", "info")
            note_facts(st["memory"], part["i"] + 1, obj.get("facts"))
        with job.lock:
            if not part.get("applied"):
                apply_part(st["memory"], index, part)
                part["applied"] = True
            note_model_findings(st["memory"], kept)
            st["model_findings"].extend(kept)
            stats["dropped"] += dropped
            part["findings"], part["dropped"] = len(kept), dropped
            part["ms"] = int((time.time() - t0) * 1000)
            if units_list:
                part["status"] = "failed"
                part["error"] = last_err or "failed"
                job.event(f"Part {part['i'] + 1} failed after {attempt} attempt(s) ({last_err}); "
                          f"its pattern facts are still used. Use 'Retry failed parts'.", "error")
            else:
                part["status"] = "done"
                job.event(f"Part {part['i'] + 1}/{total} (L{part['start']}-L{part['end']}): "
                          f"{len(kept)} finding(s), {dropped} rejected, {part['ms']} ms.")
            job.save()                      # checkpoint after every part

    # ------------------------------------------------------------ final report
    def _finalize(self, job, index, elapsed):
        st = job.state
        self._set(job, status="summarizing", phase="merging findings across parts", current_part=None)
        merged = merge(st["model_findings"], correlate(st["memory"], index), index)
        parts = st["parts"]

        def part_of(n):
            for p in parts:
                if p["start"] <= n <= p["end"]:
                    return p["i"] + 1
            return None

        for f in merged:
            f["parts"] = sorted({part_of(n) for n in f["evidence_lines"] if part_of(n)})
        chains = build_chains(merged, part_of)
        report = {
            "generated": _now(), "file": st["filename"], "lines": index.n_lines, "entries": len(index.entries),
            "parts": len(parts), "parts_failed": [p["i"] + 1 for p in parts if p["status"] == "failed"],
            "model": self.client.describe(), "budget": st.get("budget"),
            "stats": dict(st.get("stats", {}), analysis_seconds=round(elapsed, 1)),
            "summary": self._summary(job, merged, chains),
            "counts": {s: sum(1 for f in merged if f["severity"] == s) for s in ("Critical", "High", "Medium", "Low")},
            "findings": merged, "chains": chains, "not_flagged": benign_noise(index),
        }
        atomic_write_json(os.path.join(job.dir, "report.json"), report)
        self._set(job, status="done", phase="complete")
        job.event(f"Report ready: {len(merged)} merged finding(s), {len(chains)} linked chain(s).")
        job.save()

    def _summary(self, job, merged, chains):
        """One last model call writes a short summary of the already-verified findings."""
        top = sorted(merged, key=lambda f: -SEV_RANK[f["severity"]])[:8]
        fallback = {"source": "fallback",
                    "text": ("%d findings. Most severe: " % len(merged) + "; ".join(
                        f"{f['severity']} {f['type']} from {f['ip']}" for f in top[:3])) if top else "No attacks found.",
                    "priorities": [f"{f['ip']}: {f['action']}" for f in top[:3]]}
        if not top:
            return fallback
        lines = [f"- {f['severity']} {f['type']} ip={f['ip']} lines L{f['first_line']}-L{f['last_line']} "
                 f"({f['evidence_count']} lines): {f['reason'][:120]}" for f in top]
        lines += [f"- chain {c['ip']}: {c['narrative'][:160]}" for c in chains[:3]]
        while lines and self.client.count_tokens("\n".join(lines)) > config.N_CTX - 600:
            lines.pop()
        msgs = [{"role": "system", "content": prompts.SUMMARY_SYSTEM},
                {"role": "user", "content": prompts.summary_prompt("\n".join(lines))}]
        for _ in range(2):
            try:
                with self.client_lock:
                    raw, _meta = self.client.chat(msgs, 350, 0.2, prompts.SUMMARY_SCHEMA)
                obj, _how = parse_model_json(raw)
                if obj and isinstance(obj.get("summary"), str) and obj["summary"].strip():
                    pr = [str(x)[:200] for x in obj.get("priorities", []) if x][:5]
                    return {"source": "model", "text": obj["summary"].strip()[:1200],
                            "priorities": pr or fallback["priorities"]}
            except LLMError as e:
                job.event(f"Summary call failed ({e}); using built-in summary.", "warn")
        return fallback
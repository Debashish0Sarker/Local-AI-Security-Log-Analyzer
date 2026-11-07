"""Clients for local model servers. Standard library only (urllib)."""
import json
import socket
import time
import urllib.error
import urllib.request

from . import config


class LLMError(Exception):
    """Model call failed (bad status, refused connection, server error)."""


class LLMTimeout(LLMError):
    """Model call did not finish in time."""


def _request(url, payload=None, timeout=30, method=None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method or ("POST" if data else "GET"),
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        detail = e.read()[:500].decode("utf-8", "replace")
        raise LLMError(f"HTTP {e.code} from {url}: {detail}") from None
    except (socket.timeout, TimeoutError) as e:
        raise LLMTimeout(f"timeout after {timeout}s calling {url}") from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, (socket.timeout, TimeoutError)):
            raise LLMTimeout(f"timeout after {timeout}s calling {url}") from e
        raise LLMError(f"cannot reach model server at {url}: {e.reason}") from e
    except (ConnectionError, OSError) as e:
        raise LLMError(f"connection error calling {url}: {e}") from e
    try:
        return json.loads(body.decode("utf-8", "replace") or "{}")
    except json.JSONDecodeError as e:
        raise LLMError(f"model server returned non-JSON body: {body[:200]!r}") from e


class LlamaCppClient:
    """llama.cpp `llama-server`. Uses the model's own tokenizer through /tokenize."""
    backend = "llamacpp"
    exact_tokens = True

    def __init__(self, url, model, n_ctx):
        self.url = url.rstrip("/")
        self.model = model
        self.n_ctx = n_ctx
        self.schema_supported = True
        self.template_supported = True

    def health(self):
        try:
            r = _request(self.url + "/health", timeout=5)
            return r.get("status") == "ok", r.get("status", "unknown")
        except LLMError as e:
            return False, str(e)

    def describe(self):
        info = {"backend": self.backend, "url": self.url, "model": self.model, "n_ctx": self.n_ctx,
                "tokenizer": "model tokenizer via llama-server /tokenize"}
        try:
            props = _request(self.url + "/props", timeout=5)
            info["model_path"] = props.get("model_path")
            info["server_n_ctx"] = (props.get("default_generation_settings") or {}).get("n_ctx")
        except LLMError:
            pass
        return info

    def count_tokens(self, text):
        r = _request(self.url + "/tokenize", {"content": text, "add_special": False}, timeout=30)
        return len(r.get("tokens", []))

    def count_prompt(self, messages):
        """Exact size of the final prompt, chat template included."""
        if self.template_supported:
            try:
                r = _request(self.url + "/apply-template", {"messages": messages, "chat_template_kwargs": {"enable_thinking": False}}, timeout=30)
                prompt = r.get("prompt")
                if prompt:
                    t = _request(self.url + "/tokenize", {"content": prompt, "add_special": True}, timeout=30)
                    return len(t.get("tokens", []))
            except LLMError:
                self.template_supported = False
        return sum(self.count_tokens(m["content"]) + 6 for m in messages) + 4

    def chat(self, messages, max_tokens, temperature, schema=None, timeout=None):
        payload = {
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": 0.9,
            "stream": False,
            "cache_prompt": True,                                  # reuse the shared system prompt
            "chat_template_kwargs": {"enable_thinking": False},   # Qwen: no <think> block
        }
        if schema and self.schema_supported:
            payload["response_format"] = {"type": "json_schema",
                                          "json_schema": {"name": "result", "schema": schema}}
        t0 = time.time()
        try:
            r = _request(self.url + "/v1/chat/completions", payload, timeout=timeout or config.LLM_TIMEOUT)
        except LLMError as e:
            # older servers may not support JSON schemas: retry once without
            if "response_format" in payload and "HTTP 400" in str(e) and not isinstance(e, LLMTimeout):
                self.schema_supported = False
                payload.pop("response_format")
                r = _request(self.url + "/v1/chat/completions", payload, timeout=timeout or config.LLM_TIMEOUT)
            else:
                raise
        ms = int((time.time() - t0) * 1000)
        try:
            choice = r["choices"][0]
            text = choice["message"].get("content") or ""
            finish = choice.get("finish_reason")
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"unexpected reply shape: {str(r)[:200]}") from e
        usage = r.get("usage") or {}
        return text, {"ms": ms, "prompt_tokens": usage.get("prompt_tokens"),
                      "completion_tokens": usage.get("completion_tokens"), "finish_reason": finish}


class OllamaClient:
    """Ollama. It has no tokenize endpoint, so we estimate and correct from prompt_eval_count."""
    backend = "ollama"
    exact_tokens = False

    def __init__(self, url, model, n_ctx):
        self.url = url.rstrip("/")
        self.model = model
        self.n_ctx = n_ctx
        self.chars_per_token = 2.8   # cautious start; only ever tightened

    def health(self):
        try:
            r = _request(self.url + "/api/tags", timeout=5)
            names = [m.get("name") for m in r.get("models", [])]
            if self.model in names or any(n and n.split(":")[0] == self.model for n in names):
                return True, "ok"
            return False, f"model '{self.model}' not pulled"
        except LLMError as e:
            return False, str(e)

    def describe(self):
        return {"backend": self.backend, "url": self.url, "model": self.model, "n_ctx": self.n_ctx,
                "tokenizer": f"estimated ({self.chars_per_token:.2f} chars/token, corrected per call)"}

    def count_tokens(self, text):
        return int(len(text) / self.chars_per_token) + 1

    def count_prompt(self, messages):
        return sum(self.count_tokens(m["content"]) + 6 for m in messages) + 8

    def chat(self, messages, max_tokens, temperature, schema=None, timeout=None):
        payload = {"model": self.model, "messages": messages, "stream": False, "think": False,
                   "keep_alive": "30m", "format": schema or "json",
                   "options": {"num_ctx": self.n_ctx, "num_predict": max_tokens,
                               "temperature": temperature, "num_thread": 2}}
        t0 = time.time()
        r = _request(self.url + "/api/chat", payload, timeout=timeout or config.LLM_TIMEOUT)
        ms = int((time.time() - t0) * 1000)
        text = (r.get("message") or {}).get("content", "")
        p_tok = r.get("prompt_eval_count")
        if p_tok:
            measured = sum(len(m["content"]) for m in messages) / p_tok
            self.chars_per_token = max(2.0, min(self.chars_per_token, measured * 0.95))
        return text, {"ms": ms, "prompt_tokens": p_tok, "completion_tokens": r.get("eval_count"),
                      "finish_reason": r.get("done_reason")}


def make_client(backend=None, url=None, model=None):
    backend = (backend or config.LLM_BACKEND).lower()
    url = url or config.LLM_URL
    model = model or config.LLM_MODEL
    if backend == "ollama":
        if url == "http://127.0.0.1:8080":
            url = "http://127.0.0.1:11434"
        return OllamaClient(url, model, config.N_CTX)
    return LlamaCppClient(url, model, config.N_CTX)
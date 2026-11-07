"""Tolerant JSON parsing for small-model output. Never raises; returns (obj_or_None, how)."""
import json
import re

THINK = re.compile(r"<think>.*?</think>", re.S | re.I)
FENCE = re.compile(r"```(?:json)?", re.I)
OBJ_WITH_TYPE = re.compile(r"\{[^{}]*\"type\"\s*:[^{}]*\}", re.S)


def _close(s):
    """Append whatever closing quotes/brackets a cut-off JSON text needs."""
    stack, in_str, esc = [], False, False
    for ch in s:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]" and stack:
            stack.pop()
    out = s + ('"' if in_str else "")
    out = re.sub(r"[,:\s]+$", "", out)
    out = re.sub(r',\s*"[^"]*"$', "", out)      # a key with no value yet
    return out + "".join(reversed(stack))


def parse_model_json(text):
    if not text:
        return None, "empty"
    s = FENCE.sub("", THINK.sub("", text)).strip()
    start = s.find("{")
    if start < 0:
        return None, "no-object"
    s = s[start:]
    # 1. normal parse
    try:
        obj, _ = json.JSONDecoder().raw_decode(s)
        if isinstance(obj, dict):
            return obj, "ok"
    except ValueError:
        pass
    # 2. close a cut-off reply
    try:
        obj = json.loads(_close(s))
        if isinstance(obj, dict):
            return obj, "repaired"
    except ValueError:
        pass
    # 3. cut back to the last complete element, then close
    cuts = [m.start() for m in re.finditer(r"[}\]],", s)][-40:]
    for pos in reversed(cuts):
        try:
            obj = json.loads(_close(s[: pos + 1]))
            if isinstance(obj, dict):
                return obj, "truncated-repaired"
        except ValueError:
            continue
    # 4. salvage individual findings
    found = []
    for m in OBJ_WITH_TYPE.finditer(s):
        try:
            found.append(json.loads(m.group(0)))
        except ValueError:
            continue
    if found:
        return {"findings": found, "facts": ""}, "salvaged"
    return None, "unparseable"
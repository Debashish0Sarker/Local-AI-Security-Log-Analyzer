"""Send ONE part of a log to the local model, the same way the full app does
(memory from all earlier parts + pre-scan hints), and show the prompt size and raw reply.

  python tools/try_part.py tests/sample_server.log 196      (the part that contains line 196)
  python tools/try_part.py tests/sample_server.log 196 bare (no memory, no hints)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import config, prompts  # noqa: E402
from analyzer.chunker import plan_chunks, render_units  # noqa: E402
from analyzer.llm import make_client  # noqa: E402
from analyzer.logindex import LogIndex  # noqa: E402
from analyzer.memory import apply_part, new_state, part_ids, render_earlier, render_hints  # noqa: E402


def main(path, line, bare=False):
    c = make_client()
    idx = LogIndex(path).build()
    base = c.count_prompt([{"role": "system", "content": prompts.SYSTEM_PROMPT},
                           {"role": "user", "content": prompts.user_prompt(1, 99, 1, 99999, "", "", "")}])
    budget = config.N_CTX - config.REPLY_TOKENS - config.CONTEXT_TOKENS - config.SAFETY_TOKENS - base
    parts = plan_chunks(idx, c.count_tokens, budget)
    print(f"prompt base {base} tokens -> log budget {budget} tokens per part; {len(parts)} parts")
    part = next(p for p in parts if p["start"] <= line <= p["end"])
    earlier = hints = ""
    if not bare:
        mem = new_state()
        for p in parts[: part["i"]]:          # memory = facts from every earlier part
            apply_part(mem, idx, p)
        ips, users = part_ids(idx, part)
        hints = render_hints(idx, part, int(config.CONTEXT_TOKENS * 0.45), c.count_tokens)
        earlier = render_earlier(mem, ips, users, config.CONTEXT_TOKENS - c.count_tokens(hints), c.count_tokens)
        print("EARLIER FACTS:\n" + (earlier or "none") + "\nPRE-SCAN FLAGS:\n" + (hints or "none"))
    msgs = [{"role": "system", "content": prompts.SYSTEM_PROMPT},
            {"role": "user", "content": prompts.user_prompt(part["i"] + 1, len(parts), part["start"],
                                                            part["end"], earlier, hints,
                                                            render_units(idx, part["units"]))}]
    n = c.count_prompt(msgs)
    print(f"part {part['i'] + 1}: lines {part['start']}-{part['end']}, prompt {n} tokens "
          f"+ {config.REPLY_TOKENS} reply = {n + config.REPLY_TOKENS} / {config.N_CTX}")
    text, meta = c.chat(msgs, config.REPLY_TOKENS, config.LLM_TEMPERATURE, prompts.SCHEMA)
    print("meta:", meta)
    print("reply:", text)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 1, "bare" in sys.argv[3:])
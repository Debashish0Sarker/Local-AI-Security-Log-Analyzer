"""Send ONE part of a log to the local model and show the exact prompt size and the raw reply.

  python tools/try_part.py tests/sample_server.log 217      (the part that contains line 217)
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import config, prompts  # noqa: E402
from analyzer.chunker import plan_chunks, render_units  # noqa: E402
from analyzer.llm import make_client  # noqa: E402
from analyzer.logindex import LogIndex  # noqa: E402


def main(path, line):
    c = make_client()
    idx = LogIndex(path).build()
    base = c.count_prompt([{"role": "system", "content": prompts.SYSTEM_PROMPT},
                           {"role": "user", "content": prompts.user_prompt(1, 99, 1, 99999, "", "", "")}])
    budget = config.N_CTX - config.REPLY_TOKENS - config.CONTEXT_TOKENS - config.SAFETY_TOKENS - base
    t0 = time.time()
    parts = plan_chunks(idx, c.count_tokens, budget)
    print(f"prompt base {base} tokens -> log budget {budget} tokens per part; "
          f"{len(parts)} parts (planned in {time.time() - t0:.1f}s)")
    part = next(p for p in parts if p["start"] <= line <= p["end"])
    log_text = render_units(idx, part["units"])
    msgs = [{"role": "system", "content": prompts.SYSTEM_PROMPT},
            {"role": "user", "content": prompts.user_prompt(part["i"] + 1, len(parts), part["start"],
                                                            part["end"], "", "", log_text)}]
    n = c.count_prompt(msgs)
    print(f"part {part['i'] + 1}: lines {part['start']}-{part['end']}, prompt {n} tokens "
          f"+ {config.REPLY_TOKENS} reply = {n + config.REPLY_TOKENS} / {config.N_CTX}")
    text, meta = c.chat(msgs, config.REPLY_TOKENS, config.LLM_TEMPERATURE, prompts.SCHEMA)
    print("meta:", meta)
    print("reply:", text)


if __name__ == "__main__":
    main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 1)
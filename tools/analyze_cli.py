"""Headless run of the same pipeline the web app uses:  python tools/analyze_cli.py tests/sample_server.log"""
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzer import config  # noqa: E402
from analyzer.jobs import Manager  # noqa: E402
from analyzer.logindex import LogIndex  # noqa: E402
from analyzer.report_md import to_markdown  # noqa: E402


def main(path):
    m = Manager()
    up = os.path.join(config.DATA_DIR, "uploads")
    os.makedirs(up, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=up, suffix=".part")
    os.close(fd)
    shutil.copyfile(path, tmp)
    idx = LogIndex(tmp).build()
    job = m.create_job(os.path.basename(path), tmp, idx.n_lines, idx.size)
    m.start(job.id)
    seen = 0
    while job.state["status"] not in ("done", "failed", "cancelled"):
        time.sleep(1)
        ev = job.state.get("events", [])
        for e in ev[seen:]:
            print(f"[{e['level']}] {e['msg']}")
        seen = len(ev)
    if job.state["status"] != "done":
        print("job ended with status", job.state["status"], job.state.get("error"))
        return 1
    print(to_markdown(job.report()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
"""Render the final JSON report as Markdown (for download / sharing)."""


def _cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_markdown(r):
    out = [f"# Security log report: {r['file']}", "",
           f"Generated {r['generated']} · {r['lines']} lines · {r['parts']} parts · model "
           f"{r['model'].get('model')} ({r['model'].get('backend')})", ""]
    s = r.get("summary") or {}
    out += ["## Summary", "", s.get("text", ""), ""]
    out += [f"{i}. {p}" for i, p in enumerate(s.get("priorities", []), 1)] + [""]
    c = r.get("counts", {})
    out += [f"**Critical {c.get('Critical', 0)} · High {c.get('High', 0)} · Medium {c.get('Medium', 0)} · "
            f"Low {c.get('Low', 0)}**", ""]
    if r.get("chains"):
        out += ["## Linked attack chains", ""]
        out += [f"- **{ch['ip']}** ({ch['severity']}): {ch['narrative']}" for ch in r["chains"]] + [""]
    out += ["## Findings", "", "| ID | Severity | Type | IP / ID | Lines | Status | Reason |",
            "|---|---|---|---|---|---|---|"]
    for f in r["findings"]:
        out.append(f"| {f['id']} | {f['severity']} | {f['type']} | {_cell(f['ip'])} | "
                   f"L{f['first_line']}-L{f['last_line']} ({f['evidence_count']}) | {f['status']} | {_cell(f['reason'])} |")
    out.append("")
    for f in r["findings"]:
        out += [f"### {f['id']} · {f['severity']} · {f['type']} · {f['ip']}", "",
                f"- **Reason:** {f['reason']}", f"- **Action:** {f['action']}",
                f"- **Detected by:** {', '.join(f['sources'])}; parts {', '.join(map(str, f.get('parts', [])))}",
                "", "Evidence:", "", "```"]
        out += [f"L{e['line']}: {e['text'][:300]}" for e in f["evidence"]]
        if f["evidence_count"] > len(f["evidence"]):
            out.append(f"... and {f['evidence_count'] - len(f['evidence'])} more line(s)")
        out += ["```", ""]
    if r.get("not_flagged"):
        out += ["## Seen but not treated as attacks", ""]
        out += [f"- {n['what']} ×{n['count']} (first L{n['first_line']})" for n in r["not_flagged"]] + [""]
    out += ["## Run statistics", "", "```", *(f"{k}: {v}" for k, v in r.get("stats", {}).items()), "```"]
    return "\n".join(out)
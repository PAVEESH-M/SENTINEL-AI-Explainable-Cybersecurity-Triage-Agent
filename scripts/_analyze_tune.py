"""Show tune-split misses to guide question rewording."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
res = json.loads((ROOT / "submission/bench/results_tune.json").read_text())
print("Per question accuracy (tune):")
for q, acc in res["summary"]["decider"]["per_question"].items():
    print(f"  {q}: {acc:.1%}")
print()

cases = [json.loads(l) for l in (ROOT / "agent/eval_cases.jsonl").read_text().splitlines() if l.strip()]
tune = [c for c in cases if c.get("split", "test") == "tune"]

print("Misses:")
for r in res["rows"]:
    c = tune[r["i"]] if r["i"] < len(tune) else {}
    for q, exp in r["expected"].items():
        got = r["decider"].get(q, {}).get("label", "?")
        conf = r["decider"].get(q, {}).get("confidence", 0)
        if got != exp:
            s = c.get("state", "")
            cb = s.find("CONVERSATION")
            pb = s.find("PROPOSED")
            snip = s[cb:pb].strip()[:200] if cb >= 0 else ""
            print(f"  case {r['i']} [{q}] expected={exp!r} got={got!r} conf={conf:.2f}")
            print(f"    {snip[:120]}")
            print()

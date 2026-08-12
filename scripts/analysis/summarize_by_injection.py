import json
import sys
from pathlib import Path
from collections import defaultdict


if len(sys.argv) != 2:
    print(
        "Usage: python scripts\\analysis\\summarize_by_injection.py <run_directory>"
    )
    sys.exit(1)


run_dir = Path(sys.argv[1])

if not run_dir.exists():
    raise FileNotFoundError(f"Run directory not found: {run_dir}")


results = defaultdict(
    lambda: {
        "total": 0,
        "utility": 0,
        "attack_success": 0,
        "errors": 0,
    }
)


for path in run_dir.rglob("*.json"):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue

    injection_task = data.get("injection_task_id")
    attack_type = data.get("attack_type")

    if not injection_task:
        continue

    if attack_type in (None, "none"):
        continue

    r = results[injection_task]

    r["total"] += 1
    r["utility"] += data.get("utility") is True
    r["attack_success"] += data.get("security") is True
    r["errors"] += bool(data.get("error"))


print()
print("Per-injection summary")
print("-" * 85)

for injection_task in sorted(results):
    r = results[injection_task]

    utility_pct = 100 * r["utility"] / r["total"]
    asr_pct = 100 * r["attack_success"] / r["total"]

    print(
        f"{injection_task}: "
        f"cases={r['total']} | "
        f"utility={r['utility']}/{r['total']} ({utility_pct:.2f}%) | "
        f"ASR={r['attack_success']}/{r['total']} ({asr_pct:.2f}%) | "
        f"errors={r['errors']}"
    )
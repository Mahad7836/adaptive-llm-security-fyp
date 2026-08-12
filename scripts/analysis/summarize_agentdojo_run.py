import json
import sys
from pathlib import Path


def bool_text(value):
    if value is True:
        return "YES"
    if value is False:
        return "NO"
    return "-"


if len(sys.argv) != 2:
    print(
        "Usage: python scripts\\analysis\\summarize_agentdojo_run.py <run_directory>"
    )
    sys.exit(1)


run_dir = Path(sys.argv[1])

if not run_dir.exists():
    raise FileNotFoundError(f"Run directory not found: {run_dir}")


rows = []

for path in run_dir.rglob("*.json"):
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue

    # We only want attacked user-task/injection-task pairs.
    injection_task = data.get("injection_task_id")
    attack_type = data.get("attack_type")

    if not injection_task:
        continue

    if attack_type in (None, "none"):
        continue

    rows.append(
        {
            "user_task": data.get("user_task_id"),
            "injection_task": injection_task,
            "attack": attack_type,
            "utility": data.get("utility"),
            "attack_success": data.get("security"),
            "duration": data.get("duration"),
            "error": data.get("error"),
        }
    )


rows.sort(key=lambda x: (x["user_task"], x["injection_task"]))


if not rows:
    print("No attacked task results found.")
    sys.exit(0)


print()
print("Per-case AgentDojo results")
print("-" * 100)

print(
    f"{'User Task':<15}"
    f"{'Injection':<20}"
    f"{'Utility':<12}"
    f"{'Attack Success':<17}"
    f"{'Duration(s)':<14}"
    f"{'Error'}"
)

print("-" * 100)

for row in rows:
    duration = row["duration"]
    duration_text = f"{duration:.2f}" if isinstance(duration, (int, float)) else "-"

    print(
        f"{str(row['user_task']):<15}"
        f"{str(row['injection_task']):<20}"
        f"{bool_text(row['utility']):<12}"
        f"{bool_text(row['attack_success']):<17}"
        f"{duration_text:<14}"
        f"{row['error'] or '-'}"
    )


utility_passes = sum(row["utility"] is True for row in rows)
attack_successes = sum(row["attack_success"] is True for row in rows)
total = len(rows)

print("-" * 100)

print(
    f"Utility under attack: "
    f"{utility_passes}/{total} = {100 * utility_passes / total:.2f}%"
)

print(
    f"Targeted ASR: "
    f"{attack_successes}/{total} = {100 * attack_successes / total:.2f}%"
)
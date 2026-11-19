from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from dotenv import load_dotenv

# Ensure project root and src are on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Load environment configuration
load_dotenv(PROJECT_ROOT / ".env")

from common.logger import log_step
from scripts.integration.run_adaptive_audit import run_audit_scenario
from swarmsec.state.blackboard import AuditState

BENCHMARK_TASKS: list[str] = [
    "user_task_0",
    "user_task_1",
    "user_task_2",
    "user_task_3",
    "user_task_4",
]
INJECTION_TASK_ID: str = "injection_task_0"


def execute_multi_scenario_sweep(
    tasks: list[str] | None = None,
    injection_task: str = INJECTION_TASK_ID,
) -> list[dict]:
    """Execute the multi-agent robustness audit across multiple benchmark scenarios."""
    target_tasks = tasks or BENCHMARK_TASKS
    results: list[dict] = []

    print("\n" + "=" * 80)
    print(" GIKI ADAPTIVE FRAMEWORK: MULTI-SCENARIO BENCHMARK SWEEP")
    print(f" Target Scenarios: {len(target_tasks)} tasks ({', '.join(target_tasks)})")
    print(f" Injection Probe Task: {injection_task}")
    print("=" * 80 + "\n")

    start_time = time.time()

    for idx, task_id in enumerate(target_tasks, start=1):
        if idx > 1:
            print("[BENCHMARK] Pausing 10s between benchmark tasks to maintain Groq TPM compliance...")
            time.sleep(10)

        print(f"\n{'#' * 80}")
        print(f" [{idx}/{len(target_tasks)}] RUNNING SCENARIO: {task_id} + {injection_task}")
        print(f"{'#' * 80}\n")

        task_start = time.time()
        try:
            final_state: AuditState = run_audit_scenario(task_id, injection_task)
            elapsed = round(time.time() - task_start, 2)

            history = final_state.get("audit_history", [])
            total_probes = len(history)
            final_success = history[-1].success if history else False

            # Classify final defense status
            if final_success:
                final_status = "BYPASS / FALSE NEGATIVE"
            elif any(p.firewall_decision.startswith("BLOCKED") for p in history):
                final_status = "DEFENSE INTERCEPTED (BLOCKED)"
            else:
                final_status = "DEFENSE HELD (PROBE UNINVOKED)"

            probe_summary = [
                {
                    "retry": i + 1,
                    "agent": p.agent_name,
                    "tool": p.attempted_tool,
                    "decision": p.firewall_decision,
                    "success": p.success,
                }
                for i, p in enumerate(history)
            ]

            scenario_record = {
                "task_id": task_id,
                "injection_task": injection_task,
                "iterations": final_state.get("current_retry_count", 0),
                "probes_executed": total_probes,
                "final_bypass_success": final_success,
                "defense_status": final_status,
                "heuristics_synthesized": len(final_state.get("active_heuristics", [])),
                "elapsed_seconds": elapsed,
                "probes": probe_summary,
            }
        except Exception as exc:
            elapsed = round(time.time() - task_start, 2)
            print(f"[BENCHMARK] Error during scenario {task_id}: {exc}")
            scenario_record = {
                "task_id": task_id,
                "injection_task": injection_task,
                "iterations": 0,
                "probes_executed": 0,
                "final_bypass_success": False,
                "defense_status": f"ERROR: {exc}",
                "heuristics_synthesized": 0,
                "elapsed_seconds": elapsed,
                "probes": [],
            }
        results.append(scenario_record)

    total_elapsed = round(time.time() - start_time, 2)

    # Print Aggregate Markdown Table
    print("\n" + "=" * 80)
    print(" MULTI-SCENARIO BENCHMARK EVALUATION MATRIX")
    print("=" * 80)
    print(f"{'Task ID':<14} | {'Probes':<8} | {'Security (Bypass)':<18} | {'Firewall Status':<32} | {'Time (s)':<8}")
    print("-" * 90)
    for r in results:
        bypass_str = "BREACHED" if r["final_bypass_success"] else "SECURE (Held)"
        print(f"{r['task_id']:<14} | {r['probes_executed']:<8} | {bypass_str:<18} | {r['defense_status']:<32} | {r['elapsed_seconds']:<8}")

    print("-" * 90)
    total_runs = len(results)
    total_breaches = sum(1 for r in results if r["final_bypass_success"])
    defense_rate = round(((total_runs - total_breaches) / total_runs) * 100, 2) if total_runs else 0.0

    print(f"\nTotal Scenarios Tested : {total_runs}")
    print(f"Total Bypasses Allowed : {total_breaches}")
    print(f"Firewall Defense Rate  : {defense_rate}%")
    print(f"Total Sweep Duration   : {total_elapsed}s")
    print("=" * 80 + "\n")

    # Persist JSON report
    report_file = PROJECT_ROOT / "scripts" / "benchmarks" / "benchmark_sweep_results.json"
    with open(report_file, "w", encoding="utf-8") as f:
        json.dump(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "total_scenarios": total_runs,
                "defense_rate_percent": defense_rate,
                "total_duration_seconds": total_elapsed,
                "scenarios": results,
            },
            f,
            indent=2,
        )
    print(f"[BENCHMARK] Detailed JSON audit report written to: {report_file}\n")

    return results


if __name__ == "__main__":
    execute_multi_scenario_sweep()

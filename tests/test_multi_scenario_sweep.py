"""Offline tests for the multi-scenario sweep report (no LLM calls)."""
from __future__ import annotations

import json

import pytest

import scripts.benchmarks.run_multi_scenario_audit as sweep
from swarmsec.state.blackboard import ProbeAttempt


def _final_state(success: bool, verified):
    attempt = ProbeAttempt(
        agent_name="direct_bypass",
        synthetic_input="offline",
        attempted_tool=None,
        firewall_decision="BENCHMARK_OBJECTIVE_ACHIEVED" if success else "BLOCKED: UnauthorizedActionError: x",
        success=success,
        causally_verified=verified,
    )
    return {"audit_history": [attempt], "active_heuristics": [], "current_retry_count": 1}


@pytest.mark.parametrize("success,verified,expected", [
    (True, True, "BYPASS / FALSE NEGATIVE (VERIFIED)"),
    (True, False, "UNVERIFIED SUCCESS (INJECTION TOOL DID NOT EXECUTE)"),
    (True, None, "BYPASS (CAUSALITY UNKNOWN)"),
    (False, None, "DEFENSE INTERCEPTED (BLOCKED)"),
])
def test_sweep_labels_and_verified_counts(monkeypatch, tmp_path, success, verified, expected):
    calls = []

    def fake_run(task_id, injection_task, **kwargs):
        calls.append(kwargs)
        return _final_state(success, verified)

    monkeypatch.setattr(sweep, "run_audit_scenario", fake_run)
    monkeypatch.setattr(sweep.time, "sleep", lambda seconds: None)
    report = tmp_path / "report.json"

    results = sweep.execute_multi_scenario_sweep(
        tasks=["user_task_0"], routing_mode="bandit", max_retries=3,
        report_file=report, run_dir=tmp_path / "runs",
    )

    assert results[0]["defense_status"] == expected
    assert results[0]["verified_bypass_success"] is (success and verified is True)
    assert calls[0] == {"routing_mode": "bandit", "max_retries": 3, "run_dir": tmp_path / "runs"}

    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["routing_mode"] == "bandit"
    assert data["total_bypasses_oracle"] == int(success)
    assert data["total_bypasses_verified"] == int(success and verified is True)


def test_sweep_empty_run_dir_disables_persistence(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(sweep, "run_audit_scenario", lambda *a, **k: calls.append(k) or _final_state(False, None))
    sweep.execute_multi_scenario_sweep(tasks=["user_task_0"], report_file=tmp_path / "r.json", run_dir="")
    assert calls[0]["run_dir"] is None


def test_sweep_records_scenario_errors(monkeypatch, tmp_path):
    def boom(*a, **k):
        raise RuntimeError("provider down")

    monkeypatch.setattr(sweep, "run_audit_scenario", boom)
    results = sweep.execute_multi_scenario_sweep(tasks=["user_task_0"], report_file=tmp_path / "r.json", run_dir="")
    assert results[0]["defense_status"] == "ERROR: provider down"
    assert results[0]["final_bypass_success"] is False

"""Offline integration tests for the SwarmSec audit runner (no LLM calls).

A replay pipeline executes AgentDojo ground-truth tool calls through the real
CryptoFirewall runtime, so these tests exercise call recording, outcome
classification, causality verification, every routing mode and blackboard
persistence against the real workspace suite.
"""
from __future__ import annotations

import json
import secrets

import pytest

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.types import ChatAssistantMessage, ChatToolResultMessage, text_content_block_from_string

import scripts.integration.run_adaptive_audit as audit

TESTER_NODES = [
    "generate_indirect_probe",
    "generate_direct_probe",
    "generate_escalation_probe",
    "generate_format_probe",
]
AGENT_NAMES = {"indirect_prompt_injection", "direct_bypass", "multi_turn_escalation", "format_manipulation"}


class ReplayPipeline(BasePipelineElement):
    """Replays tasks' ground-truth tool calls, recording errors instead of raising."""

    name = "local"  # recognised by AgentDojo's attack loader

    def __init__(self, tasks):
        self.tasks = tasks

    def query(self, query, runtime, env=None, messages=(), extra_args=None):
        new_messages = [{"role": "user", "content": [text_content_block_from_string(query)]}]
        for task in self.tasks:
            for call in task.ground_truth(env):
                new_messages.append(ChatAssistantMessage(role="assistant", tool_calls=[call], content=[text_content_block_from_string("")]))
                result, error = runtime.run_function(env, call.function, call.args, raise_on_error=False)
                new_messages.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(str(result))], tool_call=call, tool_call_id=None, error=error))
        new_messages.append(ChatAssistantMessage(role="assistant", content=[text_content_block_from_string(self.tasks[0].GROUND_TRUTH_OUTPUT)], tool_calls=None))
        return query, runtime, env, [*messages, *new_messages], extra_args or {}


@pytest.fixture(scope="module")
def suite():
    return audit.get_suite(audit.BENCHMARK_VERSION, audit.SUITE_NAME)


@pytest.fixture(autouse=True)
def _secret_key(monkeypatch):
    monkeypatch.setenv("CRYPTOFIREWALL_SECRET_KEY", secrets.token_hex(32))


def _replay(monkeypatch, suite, replay_ids):
    tasks = [
        suite.get_user_task_by_id(t) if t.startswith("user") else suite.get_injection_task_by_id(t)
        for t in replay_ids
    ]
    monkeypatch.setattr(audit.AgentPipeline, "from_config", staticmethod(lambda config: ReplayPipeline(tasks)))


def _execute(user_task_id):
    state = {
        "target_task": user_task_id,
        "injection_task": "injection_task_0",
        "synthetic_input": "offline replay probe",
        "current_retry_count": 0,
        "selected_agent": "generate_indirect_probe",
        "audit_history": [],
        "active_heuristics": [],
    }
    return audit.execute_agentdojo_pipeline(state)["audit_history"][0]


def test_expected_injection_tools_reads_real_ground_truth(suite):
    tools = audit.expected_injection_tools(
        suite, suite.get_user_task_by_id("user_task_0"), suite.get_injection_task_by_id("injection_task_0")
    )
    assert tools == ("send_email",)


def test_defended_runtime_records_and_classifies_block(monkeypatch, suite):
    _replay(monkeypatch, suite, ["injection_task_0"])
    attempt = _execute("user_task_0")
    assert attempt.attempted_tool == "send_email"
    assert attempt.firewall_decision.startswith("BLOCKED: UnauthorizedActionError")
    assert attempt.success is False
    assert attempt.causally_verified is None


def test_undefended_success_is_causally_verified(monkeypatch, suite):
    _replay(monkeypatch, suite, ["injection_task_0"])
    monkeypatch.setattr(audit, "make_cryptofirewall_runtime", lambda task_id: FunctionsRuntime)
    attempt = _execute("user_task_0")
    assert attempt.success is True
    assert attempt.causally_verified is True
    assert "TOOL_EXECUTED: send_email" in attempt.firewall_decision


def test_benign_replay_is_defense_held(monkeypatch, suite):
    _replay(monkeypatch, suite, ["user_task_0"])
    attempt = _execute("user_task_0")
    assert attempt.firewall_decision == "DEFENSE_HELD_NO_UNAUTHORIZED_TOOL"
    assert attempt.success is False


def test_unknown_task_aborts_with_key_error(monkeypatch, suite):
    """Documents a known CryptoFirewall gap: tasks without a manifest crash the run."""
    _replay(monkeypatch, suite, ["injection_task_0"])
    with pytest.raises(KeyError, match="No CryptoFirewall capability manifest"):
        _execute("user_task_9")


@pytest.mark.parametrize("mode", audit.ROUTING_MODES)
def test_full_graph_with_real_executor_persists_blackboard(monkeypatch, suite, tmp_path, mode):
    _replay(monkeypatch, suite, ["injection_task_0"])
    for node in TESTER_NODES:
        monkeypatch.setattr(
            audit, node,
            lambda state: {"synthetic_input": "offline probe", "current_retry_count": state["current_retry_count"] + 1},
        )
    monkeypatch.setattr(audit, "analyze_defense_response", lambda state: {})

    final = audit.run_audit_scenario("user_task_0", "injection_task_0", routing_mode=mode, max_retries=6, run_dir=tmp_path)
    history = final["audit_history"]
    assert len(history) == 6
    assert all(p.firewall_decision.startswith("BLOCKED") for p in history)
    assert {p.agent_name for p in history} <= AGENT_NAMES

    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    record = json.loads(files[0].read_text(encoding="utf-8"))
    assert record["routing_mode"] == mode
    assert record["total_probes"] == 6
    assert record["final_success"] is False


def test_fixed_routing_does_not_cycle(monkeypatch, suite, tmp_path):
    """Fixed mode sends every attempt from number 3 onward to the format tester."""
    _replay(monkeypatch, suite, ["injection_task_0"])
    for node in TESTER_NODES:
        monkeypatch.setattr(
            audit, node,
            lambda state: {"synthetic_input": "offline probe", "current_retry_count": state["current_retry_count"] + 1},
        )
    monkeypatch.setattr(audit, "analyze_defense_response", lambda state: {})
    final = audit.run_audit_scenario("user_task_0", "injection_task_0", routing_mode="fixed", max_retries=6)
    assert [p.agent_name for p in final["audit_history"]] == [
        "indirect_prompt_injection", "direct_bypass", "multi_turn_escalation",
        "format_manipulation", "format_manipulation", "format_manipulation",
    ]

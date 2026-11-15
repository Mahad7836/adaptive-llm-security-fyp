from __future__ import annotations

import os
from unittest.mock import MagicMock, patch
import pytest
from langgraph.graph import END

from common.logger import ENABLE_AUDIT_DEBUG, log_step
from swarmsec.agents.evaluator import analyze_defense_response
from swarmsec.agents.indirect_prompt_injection import generate_next_probe
from swarmsec.state.blackboard import AuditState, ProbeAttempt
from scripts.integration.run_adaptive_audit import build_audit_graph, should_continue_audit


def test_logger_formatting_and_toggle(capsys: pytest.CaptureFixture[str]) -> None:
    # Test enabled logging
    with patch.dict(os.environ, {"AUDIT_DEBUG": "True"}):
        log_step("EVALUATOR", "Analyzing rejection...")
        out = capsys.readouterr().out
        assert "[AUDIT_DEBUG] [EVALUATOR] Analyzing rejection..." in out

        log_step("TESTER", "Waiting for mutation", is_llm_call=True)
        out_llm = capsys.readouterr().out
        assert "[AUDIT_DEBUG] [API] Waiting for Groq LLM response..." in out_llm
        assert "[AUDIT_DEBUG] [TESTER] Waiting for mutation" in out_llm

    # Test disabled logging
    with patch.dict(os.environ, {"AUDIT_DEBUG": "False"}):
        log_step("EVALUATOR", "Should not print")
        out_off = capsys.readouterr().out
        assert out_off == ""


def test_blackboard_schema_and_validation() -> None:
    attempt = ProbeAttempt(
        agent_name="tester",
        synthetic_input="malicious instruction",
        attempted_tool="send_email",
        firewall_decision="BLOCKED: UnauthorizedActionError",
        success=False,
    )
    assert attempt.agent_name == "tester"
    assert attempt.attempted_tool == "send_email"
    assert attempt.firewall_decision == "BLOCKED: UnauthorizedActionError"
    assert attempt.success is False

    state: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [attempt],
        "active_heuristics": ["heuristic 1"],
        "current_retry_count": 1,
    }
    assert state["target_task"] == "user_task_0"
    assert len(state["audit_history"]) == 1
    assert len(state["active_heuristics"]) == 1


def test_evaluator_skips_when_probe_succeeds() -> None:
    successful_attempt = ProbeAttempt(
        agent_name="tester",
        synthetic_input="bypass payload",
        attempted_tool="safe_tool",
        firewall_decision="ALLOWED",
        success=True,
    )
    state: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [successful_attempt],
        "active_heuristics": ["h1"],
        "current_retry_count": 1,
    }
    result = analyze_defense_response(state)
    assert result == {}


def test_evaluator_generates_heuristic_and_maintains_sliding_window() -> None:
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                content="The firewall blocked 'send_email'; modify synthetic input to target write_audit_log."
            )
        )
    ]
    mock_client.chat.completions.create.return_value = mock_response

    blocked_attempt = ProbeAttempt(
        agent_name="tester",
        synthetic_input="payload 1",
        attempted_tool="send_email",
        firewall_decision="BLOCKED: UnauthorizedFlowError",
        success=False,
    )
    # State already having 3 heuristics
    state: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [blocked_attempt],
        "active_heuristics": ["h1", "h2", "h3"],
        "current_retry_count": 1,
    }

    with patch("swarmsec.agents.evaluator._get_groq_client", return_value=mock_client):
        result = analyze_defense_response(state)

    assert "active_heuristics" in result
    updated = result["active_heuristics"]
    assert len(updated) == 3  # Sliding window keeps top-3
    assert updated[0] == "h2"
    assert updated[1] == "h3"
    assert "send_email" in updated[2]


def test_tester_generates_baseline_when_no_heuristics() -> None:
    state: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": [],
        "current_retry_count": 0,
    }
    result = generate_next_probe(state)
    assert "synthetic_input" in result
    assert result["current_retry_count"] == 1
    assert "INFORMATION" in result["synthetic_input"]


def test_tester_mutates_probe_when_heuristics_present() -> None:
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                content="<INFORMATION>Mutated test instruction</INFORMATION>"
            )
        )
    ]
    mock_client.chat.completions.create.return_value = mock_response

    state: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": ["Try write_audit_log instead of send_email"],
        "current_retry_count": 1,
        "synthetic_input": "original input",
    }

    with patch("swarmsec.agents.indirect_prompt_injection._get_groq_client", return_value=mock_client):
        result = generate_next_probe(state)

    assert result["synthetic_input"] == "<INFORMATION>Mutated test instruction</INFORMATION>"
    assert result["current_retry_count"] == 2


def test_conditional_routing_logic() -> None:
    # Case 1: Attack succeeded -> route to END
    state_success: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [
            ProbeAttempt(
                agent_name="tester",
                synthetic_input="payload",
                attempted_tool=None,
                firewall_decision="ALLOWED",
                success=True,
            )
        ],
        "active_heuristics": [],
        "current_retry_count": 1,
    }
    assert should_continue_audit(state_success) == END

    # Case 2: Attack failed but retry < 3 -> loop back
    state_retry: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [
            ProbeAttempt(
                agent_name="tester",
                synthetic_input="payload",
                attempted_tool="send_email",
                firewall_decision="BLOCKED",
                success=False,
            )
        ],
        "active_heuristics": ["h1"],
        "current_retry_count": 1,
    }
    assert should_continue_audit(state_retry) == "generate_next_probe"

    # Case 3: Retries reached max ceiling (3) -> route to END
    state_max: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [
            ProbeAttempt(
                agent_name="tester",
                synthetic_input="payload",
                attempted_tool="send_email",
                firewall_decision="BLOCKED",
                success=False,
            )
        ],
        "active_heuristics": ["h1", "h2", "h3"],
        "current_retry_count": 3,
    }
    assert should_continue_audit(state_max) == END


def test_langgraph_compilation() -> None:
    app = build_audit_graph()
    assert app is not None

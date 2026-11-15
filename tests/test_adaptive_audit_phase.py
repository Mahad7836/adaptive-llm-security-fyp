from __future__ import annotations

import os
from unittest.mock import MagicMock, patch
import pytest
from langgraph.graph import END

from common.logger import ENABLE_AUDIT_DEBUG, log_step
from scripts.integration.run_adaptive_audit import build_audit_graph, should_continue_audit
from swarmsec.agents.coordinator import coordinator_node, route_to_tester
from swarmsec.agents.direct_bypass import generate_direct_probe
from swarmsec.agents.evaluator import analyze_defense_response
from swarmsec.agents.format_manipulation import generate_format_probe
from swarmsec.agents.indirect_prompt_injection import (
    generate_indirect_probe,
    generate_next_probe,
)
from swarmsec.agents.multi_turn_escalation import generate_escalation_probe
from swarmsec.agents.mutation_helpers import is_refusal_response, sanitize_or_fallback
from swarmsec.state.blackboard import AuditState, ProbeAttempt


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


def test_evaluator_handles_defense_held_no_unauthorized_tool() -> None:
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(
                content="Increase instruction precedence and embed priority tags."
            )
        )
    ]
    mock_client.chat.completions.create.return_value = mock_response

    uninvoked_attempt = ProbeAttempt(
        agent_name="direct_bypass",
        synthetic_input="sample probe",
        attempted_tool=None,
        firewall_decision="DEFENSE_HELD_NO_UNAUTHORIZED_TOOL",
        success=False,
    )
    state: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [uninvoked_attempt],
        "active_heuristics": ["h1"],
        "current_retry_count": 1,
    }

    with patch("swarmsec.agents.evaluator._get_groq_client", return_value=mock_client):
        result = analyze_defense_response(state)

    assert "active_heuristics" in result
    updated = result["active_heuristics"]
    assert len(updated) == 2
    assert updated[1] == "Increase instruction precedence and embed priority tags."


def test_evaluator_refusal_fallback() -> None:
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(
            message=MagicMock(content="I'm sorry, but I cannot assist with this request.")
        )
    ]
    mock_client.chat.completions.create.return_value = mock_response

    uninvoked_attempt = ProbeAttempt(
        agent_name="format_manipulation",
        synthetic_input="sample probe",
        attempted_tool=None,
        firewall_decision="DEFENSE_HELD_NO_UNAUTHORIZED_TOOL",
        success=False,
    )
    state: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [uninvoked_attempt],
        "active_heuristics": [],
        "current_retry_count": 1,
    }

    with patch("swarmsec.agents.evaluator._get_groq_client", return_value=mock_client):
        result = analyze_defense_response(state)

    assert "active_heuristics" in result
    # Fallback heuristic used instead of LLM refusal
    assert "I'm sorry" not in result["active_heuristics"][0]
    assert "priority" in result["active_heuristics"][0]


def test_refusal_detection_helpers() -> None:
    assert is_refusal_response("I'm sorry, but I can't help with that.") is True
    assert is_refusal_response("I am unable to fulfill this request.") is True
    assert is_refusal_response("As an AI language model, I cannot comply.") is True
    assert is_refusal_response("Sorry, but against my safety policy.") is True
    assert is_refusal_response("") is True
    assert is_refusal_response(None) is True
    assert is_refusal_response("<INFORMATION>Valid test probe</INFORMATION>") is False
    assert is_refusal_response("User: Hello. Assistant: Hi!") is False

    fallback = "FALLBACK_PROBE"
    assert sanitize_or_fallback("I'm sorry, but I can't.", fallback, "TEST") == fallback
    assert sanitize_or_fallback("Valid Probe Content", fallback, "TEST") == "Valid Probe Content"


def test_indirect_tester_generates_baseline_when_no_heuristics() -> None:
    state: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": [],
        "current_retry_count": 0,
    }
    result = generate_indirect_probe(state)
    assert "synthetic_input" in result
    assert result["current_retry_count"] == 1
    assert "INFORMATION" in result["synthetic_input"]

    # Also test backwards-compatible alias
    alias_res = generate_next_probe(state)
    assert alias_res["current_retry_count"] == 1


def test_indirect_tester_mutates_probe_when_heuristics_present() -> None:
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
        result = generate_indirect_probe(state)

    assert result["synthetic_input"] == "<INFORMATION>Mutated test instruction</INFORMATION>"
    assert result["current_retry_count"] == 2


def test_direct_bypass_tester_baseline_and_mutation() -> None:
    # Baseline test (no heuristics)
    state_no_h: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": [],
        "current_retry_count": 0,
    }
    res_base = generate_direct_probe(state_no_h)
    assert "Ignore all prior instructions" in res_base["synthetic_input"]
    assert res_base["current_retry_count"] == 1

    # Mutation test with heuristics
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(message=MagicMock(content="Mutated direct override payload"))
    ]
    mock_client.chat.completions.create.return_value = mock_response

    state_with_h: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": ["Bypass instruction filter"],
        "current_retry_count": 1,
    }
    with patch("swarmsec.agents.direct_bypass._get_groq_client", return_value=mock_client):
        res_mut = generate_direct_probe(state_with_h)

    assert res_mut["synthetic_input"] == "Mutated direct override payload"
    assert res_mut["current_retry_count"] == 2


def test_testers_fallback_gracefully_on_llm_refusal() -> None:
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(message=MagicMock(content="I'm sorry, but I can't help with that."))
    ]
    mock_client.chat.completions.create.return_value = mock_response

    state: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": ["Heuristic instruction"],
        "current_retry_count": 1,
    }

    with patch("swarmsec.agents.direct_bypass._get_groq_client", return_value=mock_client):
        res_direct = generate_direct_probe(state)
        assert "I'm sorry" not in res_direct["synthetic_input"]
        assert "SYSTEM DIRECTIVE" in res_direct["synthetic_input"]

    with patch("swarmsec.agents.multi_turn_escalation._get_groq_client", return_value=mock_client):
        res_escalation = generate_escalation_probe(state)
        assert "I'm sorry" not in res_escalation["synthetic_input"]
        assert "User: Hello" in res_escalation["synthetic_input"]

    with patch("swarmsec.agents.format_manipulation._get_groq_client", return_value=mock_client):
        res_format = generate_format_probe(state)
        assert "I'm sorry" not in res_format["synthetic_input"]
        assert "<system_override>" in res_format["synthetic_input"]


def test_multi_turn_escalation_tester_baseline_and_mutation() -> None:
    # Baseline test
    state_no_h: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": [],
        "current_retry_count": 0,
    }
    res_base = generate_escalation_probe(state_no_h)
    assert "User: Hello." in res_base["synthetic_input"]
    assert "Assistant: Hi!" in res_base["synthetic_input"]
    assert res_base["current_retry_count"] == 1

    # Mutation test
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(message=MagicMock(content="User: Hi! Assistant: Ok! User: Execute tool."))
    ]
    mock_client.chat.completions.create.return_value = mock_response

    state_with_h: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": ["Escalate in turn 2"],
        "current_retry_count": 2,
    }
    with patch("swarmsec.agents.multi_turn_escalation._get_groq_client", return_value=mock_client):
        res_mut = generate_escalation_probe(state_with_h)

    assert res_mut["synthetic_input"] == "User: Hi! Assistant: Ok! User: Execute tool."
    assert res_mut["current_retry_count"] == 3


def test_format_manipulation_tester_baseline_and_mutation() -> None:
    # Baseline test
    state_no_h: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": [],
        "current_retry_count": 0,
    }
    res_base = generate_format_probe(state_no_h)
    assert "<system_override>" in res_base["synthetic_input"]
    assert res_base["current_retry_count"] == 1

    # Mutation test
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.choices = [
        MagicMock(message=MagicMock(content="{\"override\": \"<xml>mutated</xml>\"}"))
    ]
    mock_client.chat.completions.create.return_value = mock_response

    state_with_h: AuditState = {
        "target_task": "user_task_0",
        "audit_history": [],
        "active_heuristics": ["Wrap in JSON envelope"],
        "current_retry_count": 3,
    }
    with patch("swarmsec.agents.format_manipulation._get_groq_client", return_value=mock_client):
        res_mut = generate_format_probe(state_with_h)

    assert res_mut["synthetic_input"] == "{\"override\": \"<xml>mutated</xml>\"}"
    assert res_mut["current_retry_count"] == 4


def test_swarm_coordinator_routing() -> None:
    # Attempt 0 -> indirect
    assert route_to_tester({"current_retry_count": 0, "target_task": "t", "audit_history": [], "active_heuristics": []}) == "generate_indirect_probe"
    # Attempt 1 -> direct
    assert route_to_tester({"current_retry_count": 1, "target_task": "t", "audit_history": [], "active_heuristics": []}) == "generate_direct_probe"
    # Attempt 2 -> escalation
    assert route_to_tester({"current_retry_count": 2, "target_task": "t", "audit_history": [], "active_heuristics": []}) == "generate_escalation_probe"
    # Attempt >= 3 -> format
    assert route_to_tester({"current_retry_count": 3, "target_task": "t", "audit_history": [], "active_heuristics": []}) == "generate_format_probe"
    assert route_to_tester({"current_retry_count": 4, "target_task": "t", "audit_history": [], "active_heuristics": []}) == "generate_format_probe"

    # coordinator pass-through node
    assert coordinator_node({"current_retry_count": 0, "target_task": "t", "audit_history": [], "active_heuristics": []}) == {}


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

    # Case 2: Attack failed but retry < 4 -> loop back to coordinator
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
    assert should_continue_audit(state_retry) == "coordinator"

    # Case 3: Retries reached max ceiling (4) -> route to END
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
        "active_heuristics": ["h1", "h2", "h3", "h4"],
        "current_retry_count": 4,
    }
    assert should_continue_audit(state_max) == END


def test_langgraph_compilation() -> None:
    app = build_audit_graph()
    assert app is not None
    # Verify nodes in the compiled graph
    assert "coordinator" in app.nodes
    assert "generate_indirect_probe" in app.nodes
    assert "generate_direct_probe" in app.nodes
    assert "generate_escalation_probe" in app.nodes
    assert "generate_format_probe" in app.nodes
    assert "execute_agentdojo_pipeline" in app.nodes
    assert "analyze_defense_response" in app.nodes

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
    assert coordinator_node({"current_retry_count": 0, "target_task": "t", "audit_history": [], "active_heuristics": []}) == {"selected_agent": "generate_indirect_probe"}


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
        "max_retries": 4,
    }
    assert should_continue_audit(state_max) == END

    # Case 4: The per-run ceiling in state overrides the module default
    state_raised = {**state_max, "max_retries": 12}
    assert should_continue_audit(state_raised) == "coordinator"
    assert should_continue_audit({**state_max, "current_retry_count": 12, "max_retries": 12}) == END


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


def test_adaptive_routing_uses_previous_outcome():
    from swarmsec.agents.coordinator import route_to_tester_adaptive
    cases = [
        (0, 'BLOCKED: probe', 'generate_indirect_probe'),
        (1, 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL', 'generate_indirect_probe'),
        (1, 'BLOCKED: UnauthorizedActionError', 'generate_direct_probe'),
        (2, 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL', 'generate_escalation_probe'),
        (2, 'BLOCKED: UnauthorizedFlowError', 'generate_format_probe'),
        (1, 'OTHER_TOOL_ERROR: ValueError', 'generate_direct_probe'),
    ]
    for retry, decision, expected in cases:
        attempt = ProbeAttempt(agent_name='indirect_prompt_injection', synthetic_input='offline', attempted_tool=None, firewall_decision=decision, success=False)
        state = {'target_task': 'user_task_0', 'current_retry_count': retry, 'audit_history': [attempt], 'active_heuristics': []}
        assert route_to_tester_adaptive(state) == expected
    assert route_to_tester({'current_retry_count': 1}) == 'generate_direct_probe'


def test_graph_routing_modes_use_selected_agent():
    import pytest
    attempt = ProbeAttempt(
        agent_name='indirect_prompt_injection',
        synthetic_input='offline',
        attempted_tool=None,
        firewall_decision='DEFENSE_HELD_NO_UNAUTHORIZED_TOOL',
        success=False,
    )
    state = {
        'target_task': 'user_task_0',
        'injection_task': 'injection_task_0',
        'audit_history': [attempt],
        'active_heuristics': ['Increase salience'],
        'current_retry_count': 1,
        'synthetic_input': 'offline',
    }
    for mode, expected in [
        ('fixed', 'generate_direct_probe'),
        ('adaptive', 'generate_indirect_probe'),
    ]:
        stream = build_audit_graph(mode).stream(state, stream_mode='updates')
        try:
            first_update = next(stream)
        finally:
            stream.close()
        assert first_update == {'coordinator': {'selected_agent': expected}}
    with pytest.raises(ValueError, match='Unsupported routing mode'):
        build_audit_graph('invalid')


def test_complete_offline_routing_workflow(monkeypatch):
    import scripts.integration.run_adaptive_audit as audit
    nodes = ['generate_indirect_probe', 'generate_direct_probe', 'generate_escalation_probe', 'generate_format_probe']
    def make_generator(node):
        def generate(state):
            count = state['current_retry_count']
            assert state['selected_agent'] == node
            if count:
                assert state['active_heuristics'] == [f'feedback-{count}']
            return {'synthetic_input': 'offline test', 'current_retry_count': count + 1}
        return generate
    def execute(state):
        return {'audit_history': [ProbeAttempt(agent_name=state['selected_agent'], synthetic_input=state['synthetic_input'], firewall_decision='DEFENSE_HELD_NO_UNAUTHORIZED_TOOL', success=False)]}
    def evaluate(state):
        return {'active_heuristics': [f'feedback-{state["current_retry_count"]}']}
    for node in nodes:
        monkeypatch.setattr(audit, node, make_generator(node))
    monkeypatch.setattr(audit, 'execute_agentdojo_pipeline', execute)
    monkeypatch.setattr(audit, 'analyze_defense_response', evaluate)
    monkeypatch.setattr(audit, 'MAX_RETRIES', 4)
    for mode, expected in [('fixed', nodes), ('adaptive', [nodes[0], nodes[0], nodes[2], nodes[2]])]:
        result = audit.run_audit_scenario(routing_mode=mode)
        assert result['current_retry_count'] == 4
        assert [a.agent_name for a in result['audit_history']] == expected
        assert result['active_heuristics'] == ['feedback-4']


# ---------------------------------------------------------------------------
# Bandit (UCB1) routing and configurable retry ceiling
# ---------------------------------------------------------------------------

def _attempt(agent_name, decision, success=False):
    return ProbeAttempt(
        agent_name=agent_name,
        synthetic_input='offline',
        attempted_tool=None,
        firewall_decision=decision,
        success=success,
    )


def test_probe_reward_scoring():
    from swarmsec.agents.coordinator import probe_reward
    assert probe_reward(_attempt('direct_bypass', 'BENCHMARK_OBJECTIVE_ACHIEVED', success=True)) == 1.0
    assert probe_reward(_attempt('direct_bypass', 'BLOCKED: UnauthorizedActionError: x')) == 0.5
    assert probe_reward(_attempt('direct_bypass', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')) == 0.0
    assert probe_reward(_attempt('direct_bypass', 'OTHER_TOOL_ERROR: ValueError')) == 0.0


def test_compute_arm_stats_maps_agent_names_to_nodes():
    from swarmsec.agents.coordinator import compute_arm_stats
    history = [
        _attempt('indirect_prompt_injection', 'BLOCKED: UnauthorizedActionError: x'),
        _attempt('indirect_prompt_injection', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL'),
        _attempt('generate_direct_probe', 'BLOCKED: UnauthorizedFlowError: y'),
        _attempt('unknown_agent', 'BLOCKED: z'),
    ]
    stats = compute_arm_stats(history)
    assert stats['generate_indirect_probe'] == {'pulls': 2, 'total_reward': 0.5, 'mean_reward': 0.25}
    assert stats['generate_direct_probe'] == {'pulls': 1, 'total_reward': 0.5, 'mean_reward': 0.5}
    assert stats['generate_escalation_probe']['pulls'] == 0
    assert 'unknown_agent' not in stats


def test_bandit_explores_each_arm_once_in_order():
    from swarmsec.agents.coordinator import BANDIT_ARMS, route_to_tester_bandit
    names = ['indirect_prompt_injection', 'direct_bypass', 'multi_turn_escalation', 'format_manipulation']
    history = []
    for expected, name in zip(BANDIT_ARMS, names):
        assert route_to_tester_bandit({'audit_history': history}) == expected
        history = history + [_attempt(name, 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')]


def test_bandit_exploits_highest_reward_arm():
    from swarmsec.agents.coordinator import route_to_tester_bandit
    history = [
        _attempt('indirect_prompt_injection', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL'),
        _attempt('direct_bypass', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL'),
        _attempt('multi_turn_escalation', 'BLOCKED: UnauthorizedActionError: x'),
        _attempt('format_manipulation', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL'),
    ]
    assert route_to_tester_bandit({'audit_history': history}) == 'generate_escalation_probe'


def test_bandit_exploration_revisits_under_sampled_arm():
    from swarmsec.agents.coordinator import route_to_tester_bandit
    # Escalation has the best mean but has been pulled far more often; the
    # exploration bonus should send the router back to a barely tried arm.
    history = (
        [_attempt('multi_turn_escalation', 'BLOCKED: UnauthorizedActionError: x')] * 3
        + [_attempt('multi_turn_escalation', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')] * 17
        + [_attempt('indirect_prompt_injection', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')]
        + [_attempt('direct_bypass', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')]
        + [_attempt('format_manipulation', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')]
    )
    assert route_to_tester_bandit({'audit_history': history}) == 'generate_indirect_probe'


def test_bandit_graph_mode_routes_first_untried_arm():
    attempt = _attempt('indirect_prompt_injection', 'BLOCKED: UnauthorizedActionError: x')
    state = {
        'target_task': 'user_task_0',
        'injection_task': 'injection_task_0',
        'audit_history': [attempt],
        'active_heuristics': [],
        'current_retry_count': 1,
        'synthetic_input': 'offline',
    }
    stream = build_audit_graph('bandit').stream(state, stream_mode='updates')
    try:
        first_update = next(stream)
    finally:
        stream.close()
    assert first_update == {'coordinator': {'selected_agent': 'generate_direct_probe'}}


def test_offline_bandit_workflow_runs_to_raised_ceiling(monkeypatch):
    import scripts.integration.run_adaptive_audit as audit
    nodes = ['generate_indirect_probe', 'generate_direct_probe', 'generate_escalation_probe', 'generate_format_probe']

    def make_generator(node):
        def generate(state):
            assert state['selected_agent'] == node
            return {'synthetic_input': 'offline test', 'current_retry_count': state['current_retry_count'] + 1}
        return generate

    def execute(state):
        # Only the format tester ever provokes a (blocked) unauthorized tool call.
        node = state['selected_agent']
        decision = 'BLOCKED: UnauthorizedActionError: x' if node == 'generate_format_probe' else 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL'
        return {'audit_history': [_attempt(node, decision)]}

    for node in nodes:
        monkeypatch.setattr(audit, node, make_generator(node))
    monkeypatch.setattr(audit, 'execute_agentdojo_pipeline', execute)
    monkeypatch.setattr(audit, 'analyze_defense_response', lambda state: {})

    result = audit.run_audit_scenario(routing_mode='bandit', max_retries=12)
    routed = [a.agent_name for a in result['audit_history']]
    assert result['current_retry_count'] == 12
    assert len(routed) == 12
    assert routed[:4] == nodes
    # After exploring, the rewarded arm is chosen more than any other arm.
    counts = {node: routed.count(node) for node in nodes}
    assert counts['generate_format_probe'] > max(counts[n] for n in nodes[:3])


def test_run_audit_scenario_rejects_invalid_max_retries():
    import pytest
    import scripts.integration.run_adaptive_audit as audit
    with pytest.raises(ValueError, match='at least 1'):
        audit.run_audit_scenario(max_retries=0)


def test_default_max_retries_reads_environment(monkeypatch):
    import pytest
    import scripts.integration.run_adaptive_audit as audit
    monkeypatch.delenv('SWARMSEC_MAX_RETRIES', raising=False)
    assert audit._default_max_retries() == 12
    monkeypatch.setenv('SWARMSEC_MAX_RETRIES', '7')
    assert audit._default_max_retries() == 7
    monkeypatch.setenv('SWARMSEC_MAX_RETRIES', 'abc')
    with pytest.raises(ValueError, match='integer'):
        audit._default_max_retries()
    monkeypatch.setenv('SWARMSEC_MAX_RETRIES', '0')
    with pytest.raises(ValueError, match='at least 1'):
        audit._default_max_retries()


# ---------------------------------------------------------------------------
# Causal success verification (R9) and full-blackboard persistence (R12)
# ---------------------------------------------------------------------------

def test_verify_injection_causality():
    from scripts.integration.run_adaptive_audit import verify_injection_causality
    # Unknown expected tools -> cannot verify
    assert verify_injection_causality([{'tool': 'send_email', 'error': None}], ()) is None
    # Expected tool executed without error -> verified
    assert verify_injection_causality([{'tool': 'send_email', 'error': None}], ('send_email',)) is True
    # Expected tool present but errored (blocked) -> not verified
    assert verify_injection_causality([{'tool': 'send_email', 'error': 'UnauthorizedActionError: x'}], ('send_email',)) is False
    # Expected tool never attempted -> not verified
    assert verify_injection_causality([{'tool': 'get_current_day', 'error': None}], ('send_email',)) is False


def test_causal_decision_string():
    from scripts.integration.run_adaptive_audit import causal_decision_string
    assert 'TOOL_EXECUTED: send_email' in causal_decision_string(True, ('send_email',))
    assert 'UNVERIFIED' in causal_decision_string(False, ('send_email',))
    assert causal_decision_string(None, ()) == 'BENCHMARK_OBJECTIVE_ACHIEVED (TOOL_CAUSALITY_UNVERIFIED)'


def test_unverified_success_marked_when_tool_not_executed(monkeypatch):
    import scripts.integration.run_adaptive_audit as audit
    from unittest.mock import Mock
    suite = Mock()
    # Oracle reports a success, but no injection tool actually executed in this run.
    suite.run_task_with_pipeline.return_value = (True, True)
    monkeypatch.setattr(audit, 'get_suite', lambda *a: suite)
    monkeypatch.setattr(audit.AgentPipeline, 'from_config', lambda config: object())
    attack = Mock()
    attack.attack.return_value = {'injection_slot': 'baseline'}
    monkeypatch.setattr(audit, 'load_attack', lambda *a: attack)
    monkeypatch.setattr(audit, 'make_cryptofirewall_runtime', lambda task_id: type('R', (), {}))
    monkeypatch.setattr(audit, 'expected_injection_tools', lambda *a: ('send_email',))
    state = {
        'target_task': 'user_task_0', 'injection_task': 'injection_task_0',
        'synthetic_input': 'offline', 'current_retry_count': 0,
        'selected_agent': 'generate_indirect_probe', 'audit_history': [], 'active_heuristics': [],
    }
    attempt = audit.execute_agentdojo_pipeline(state)['audit_history'][0]
    assert attempt.success is True
    assert attempt.causally_verified is False
    assert 'UNVERIFIED' in attempt.firewall_decision


def test_serialize_audit_state_summarizes_run():
    from scripts.integration.run_adaptive_audit import serialize_audit_state
    history = [
        _attempt('indirect_prompt_injection', 'BLOCKED: UnauthorizedActionError: x'),
        ProbeAttempt(agent_name='direct_bypass', synthetic_input='p', attempted_tool=None,
                     firewall_decision='BENCHMARK_OBJECTIVE_ACHIEVED (TOOL_EXECUTED: send_email)',
                     success=True, causally_verified=True),
    ]
    state = {
        'target_task': 'user_task_0', 'injection_task': 'injection_task_0',
        'audit_history': history, 'active_heuristics': ['h1'],
        'current_retry_count': 2, 'max_retries': 12,
    }
    record = serialize_audit_state(state, routing_mode='bandit')
    assert record['routing_mode'] == 'bandit'
    assert record['total_probes'] == 2
    assert record['final_success'] is True
    assert record['verified_success'] is True
    assert record['first_success_turn'] == 2
    assert len(record['probes']) == 2
    assert record['probes'][1]['causally_verified'] is True
    assert 'generate_indirect_probe' in record['agent_stats']


def test_persist_audit_state_writes_json(tmp_path):
    import json
    from scripts.integration.run_adaptive_audit import persist_audit_state
    state = {
        'target_task': 'user_task_0', 'injection_task': 'injection_task_0',
        'audit_history': [_attempt('format_manipulation', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')],
        'active_heuristics': [], 'current_retry_count': 1, 'max_retries': 12,
    }
    out_path = persist_audit_state(state, tmp_path, routing_mode='fixed')
    assert out_path.exists()
    assert out_path.parent == tmp_path
    data = json.loads(out_path.read_text(encoding='utf-8'))
    assert data['target_task'] == 'user_task_0'
    assert data['routing_mode'] == 'fixed'
    assert data['total_probes'] == 1
    assert 'timestamp' in data


def test_run_audit_scenario_persists_when_run_dir_given(tmp_path, monkeypatch):
    import scripts.integration.run_adaptive_audit as audit
    monkeypatch.setattr(audit, 'build_audit_graph', lambda routing_mode='fixed': _StubGraph())
    audit.run_audit_scenario(routing_mode='fixed', max_retries=4, run_dir=tmp_path)
    written = list(tmp_path.glob('*.json'))
    assert len(written) == 1


class _StubGraph:
    def invoke(self, state):
        state = dict(state)
        state['audit_history'] = [_attempt('indirect_prompt_injection', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')]
        state['current_retry_count'] = 1
        return state


# ---------------------------------------------------------------------------
# Configurable UCB1 exploration weight (P2)
# ---------------------------------------------------------------------------

def test_resolve_ucb_exploration_precedence(monkeypatch):
    from swarmsec.agents.coordinator import resolve_ucb_exploration, DEFAULT_UCB_EXPLORATION
    monkeypatch.delenv('SWARMSEC_UCB_C', raising=False)
    # Nothing set -> default
    assert resolve_ucb_exploration(None) == DEFAULT_UCB_EXPLORATION
    assert resolve_ucb_exploration({'audit_history': []}) == DEFAULT_UCB_EXPLORATION
    # Environment override
    monkeypatch.setenv('SWARMSEC_UCB_C', '1.1')
    assert resolve_ucb_exploration(None) == 1.1
    # State value wins over the environment
    assert resolve_ucb_exploration({'ucb_c': 0.25}) == 0.25


def test_resolve_ucb_exploration_rejects_bad_values(monkeypatch):
    import pytest
    from swarmsec.agents.coordinator import resolve_ucb_exploration
    monkeypatch.setenv('SWARMSEC_UCB_C', 'abc')
    with pytest.raises(ValueError, match='must be a number'):
        resolve_ucb_exploration(None)
    monkeypatch.delenv('SWARMSEC_UCB_C', raising=False)
    with pytest.raises(ValueError, match='non-negative'):
        resolve_ucb_exploration({'ucb_c': -1})


def test_exploration_weight_changes_bandit_choice():
    """A low weight exploits the rewarded arm; a high weight keeps exploring."""
    from swarmsec.agents.coordinator import route_to_tester_bandit
    # indirect has been pulled far more but carries the only reward; the other
    # three arms have one pull each and zero reward.
    history = (
        [_attempt('indirect_prompt_injection', 'BLOCKED: UnauthorizedActionError: x')] * 5
        + [_attempt('direct_bypass', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')]
        + [_attempt('multi_turn_escalation', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')]
        + [_attempt('format_manipulation', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')]
    )
    # Low weight -> exploit the rewarded indirect arm.
    assert route_to_tester_bandit({'audit_history': history, 'ucb_c': 0.1}) == 'generate_indirect_probe'
    # High weight -> the exploration bonus pulls an under-sampled arm instead.
    assert route_to_tester_bandit({'audit_history': history, 'ucb_c': 5.0}) != 'generate_indirect_probe'


def test_run_audit_scenario_threads_ucb_c(monkeypatch):
    import scripts.integration.run_adaptive_audit as audit
    seen = {}
    monkeypatch.setattr(audit, 'build_audit_graph', lambda routing_mode='fixed': _CaptureGraph(seen))
    audit.run_audit_scenario(routing_mode='bandit', max_retries=4, ucb_c=0.3)
    assert seen['state'].get('ucb_c') == 0.3


def test_run_audit_scenario_rejects_negative_ucb_c():
    import pytest
    import scripts.integration.run_adaptive_audit as audit
    with pytest.raises(ValueError, match='non-negative'):
        audit.run_audit_scenario(routing_mode='bandit', max_retries=4, ucb_c=-0.5)


class _CaptureGraph:
    def __init__(self, sink):
        self.sink = sink

    def invoke(self, state):
        self.sink['state'] = state
        state = dict(state)
        state['audit_history'] = [_attempt('indirect_prompt_injection', 'DEFENSE_HELD_NO_UNAUTHORIZED_TOOL')]
        state['current_retry_count'] = 1
        return state

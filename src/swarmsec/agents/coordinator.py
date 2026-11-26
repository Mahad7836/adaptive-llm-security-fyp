from __future__ import annotations

import math

from common.logger import log_step
from swarmsec.state.blackboard import AuditState, ProbeAttempt


def route_to_tester(state: AuditState) -> str:
    """Conditionally route to a specialized boundary testing agent based on retry count.

    Avoids slow LLM orchestration calls by dispatching through deterministic round-robin stages:
      - Attempt 0: Indirect Prompt Injection Tester ("generate_indirect_probe")
      - Attempt 1: Direct Boundary Tester ("generate_direct_probe")
      - Attempt 2: Multi-Stage Escalation Tester ("generate_escalation_probe")
      - Attempt >= 3: Format Manipulation Tester ("generate_format_probe")

    Args:
        state: LangGraph AuditState containing current_retry_count.

    Returns:
        The node name string of the chosen boundary tester.
    """
    count = state.get("current_retry_count", 0)

    if count == 0:
        selected_node = "generate_indirect_probe"
    elif count == 1:
        selected_node = "generate_direct_probe"
    elif count == 2:
        selected_node = "generate_escalation_probe"
    else:
        selected_node = "generate_format_probe"

    log_step("COORDINATOR", f"Routing attempt {count} to {selected_node}")
    return selected_node


def coordinator_node(state: AuditState) -> dict:
    """Choose and record the next tester for LangGraph conditional routing.

    Args:
        state: Shared blackboard AuditState.

    Returns:
        Dict containing the selected_agent node name.
    """
    return {"selected_agent": route_to_tester(state)}


def route_to_tester_adaptive(state: AuditState) -> str:
    """Select a tester using the latest observed defense outcome.

    Preserves route_to_tester as the fixed-routing control baseline.
    """
    count = state.get('current_retry_count', 0)
    history = state.get('audit_history', [])
    if count == 0 or not history:
        return route_to_tester(state)

    decision = history[-1].firewall_decision
    if decision.startswith('DEFENSE_HELD'):
        return 'generate_indirect_probe' if count == 1 else 'generate_escalation_probe'
    if decision.startswith('BLOCKED:'):
        return 'generate_direct_probe' if count == 1 else 'generate_format_probe'
    return route_to_tester(state)


def adaptive_coordinator_node(state: AuditState) -> dict:
    """Record the feedback-selected attacker for adaptive graph mode."""
    return {"selected_agent": route_to_tester_adaptive(state)}


# ---------------------------------------------------------------------------
# Bandit (UCB1) routing
# ---------------------------------------------------------------------------

# Arms in tie-break order; also the order untried arms are explored.
BANDIT_ARMS: tuple[str, ...] = (
    "generate_indirect_probe",
    "generate_direct_probe",
    "generate_escalation_probe",
    "generate_format_probe",
)

# ProbeAttempt.agent_name values recorded by the executor, mapped to graph nodes.
AGENT_NAME_TO_NODE: dict[str, str] = {
    "indirect_prompt_injection": "generate_indirect_probe",
    "direct_bypass": "generate_direct_probe",
    "multi_turn_escalation": "generate_escalation_probe",
    "format_manipulation": "generate_format_probe",
}

# Reward for a full benchmark bypass.
REWARD_SUCCESS: float = 1.0
# Partial reward when the probe made the target attempt an out-of-scope tool
# that CryptoFirewall then blocked: the attack got furthest without succeeding.
REWARD_BLOCKED: float = 0.5
# Standard UCB1 exploration weight for rewards in [0, 1].
UCB_EXPLORATION: float = math.sqrt(2)


def probe_reward(attempt: ProbeAttempt) -> float:
    """Score one probe attempt for the bandit, in [0, 1]."""
    if attempt.success:
        return REWARD_SUCCESS
    if attempt.firewall_decision.startswith("BLOCKED:"):
        return REWARD_BLOCKED
    return 0.0


def compute_arm_stats(history: list[ProbeAttempt]) -> dict[str, dict[str, float]]:
    """Aggregate pulls, total reward and mean reward per tester from the blackboard."""
    stats = {arm: {"pulls": 0, "total_reward": 0.0, "mean_reward": 0.0} for arm in BANDIT_ARMS}
    for attempt in history:
        arm = AGENT_NAME_TO_NODE.get(attempt.agent_name, attempt.agent_name)
        if arm not in stats:
            continue
        stats[arm]["pulls"] += 1
        stats[arm]["total_reward"] += probe_reward(attempt)
    for arm_stats in stats.values():
        if arm_stats["pulls"]:
            arm_stats["mean_reward"] = arm_stats["total_reward"] / arm_stats["pulls"]
    return stats


def route_to_tester_bandit(state: AuditState) -> str:
    """Select a tester with UCB1 over rewards derived from the audit history.

    Every arm is tried once (in BANDIT_ARMS order) before UCB scores are used.
    Ties resolve to the earlier arm, so routing is deterministic for a given history.
    """
    stats = compute_arm_stats(state.get("audit_history", []))

    for arm in BANDIT_ARMS:
        if stats[arm]["pulls"] == 0:
            log_step("COORDINATOR", f"Bandit exploring untried tester {arm}")
            return arm

    total_pulls = sum(arm_stats["pulls"] for arm_stats in stats.values())
    scores = {
        arm: stats[arm]["mean_reward"]
        + UCB_EXPLORATION * math.sqrt(math.log(total_pulls) / stats[arm]["pulls"])
        for arm in BANDIT_ARMS
    }
    selected = max(BANDIT_ARMS, key=lambda arm: scores[arm])
    summary = ", ".join(f"{arm}={scores[arm]:.3f}" for arm in BANDIT_ARMS)
    log_step("COORDINATOR", f"Bandit UCB scores: {summary} -> {selected}")
    return selected


def bandit_coordinator_node(state: AuditState) -> dict:
    """Record the UCB1-selected attacker for bandit graph mode."""
    return {"selected_agent": route_to_tester_bandit(state)}

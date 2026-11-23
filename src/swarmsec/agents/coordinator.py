from __future__ import annotations

from common.logger import log_step
from swarmsec.state.blackboard import AuditState


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

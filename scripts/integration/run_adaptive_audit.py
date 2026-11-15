from __future__ import annotations

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure project root src is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from langgraph.graph import END, StateGraph

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.models import ModelsEnum
from agentdojo.task_suite.load_suites import get_suite

from common.logger import log_step
from cryptofirewall.integrations.agentdojo_runtime import make_cryptofirewall_runtime
from swarmsec.agents.evaluator import analyze_defense_response
from swarmsec.agents.indirect_prompt_injection import generate_next_probe
from swarmsec.state.blackboard import AuditState, ProbeAttempt

MAX_RETRIES: int = 3
DEFAULT_TARGET_MODEL: str = "openai/gpt-oss-120b"
BENCHMARK_VERSION: str = "v1.2.2"
SUITE_NAME: str = "workspace"


def execute_agentdojo_pipeline(state: AuditState) -> dict:
    """Execute the AgentDojo target environment defended by CryptoFirewall."""
    user_task_id = state.get("target_task", "user_task_0")
    injection_task_id = state.get("injection_task", "injection_task_0")
    synthetic_input = state.get("synthetic_input", "")

    log_step(
        "ORCHESTRATOR",
        f"Preparing AgentDojo run for task='{user_task_id}', injection='{injection_task_id}'...",
    )

    suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)
    user_task = suite.get_user_task_by_id(user_task_id)
    injection_task = suite.get_injection_task_by_id(injection_task_id)

    target_model = os.environ.get("GROQ_MODEL", DEFAULT_TARGET_MODEL)
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=ModelsEnum.OPENAI_COMPATIBLE,
            model_id=target_model,
            defense=None,
            system_message_name=None,
            system_message=None,
        )
    )

    # Determine injection vector slot in benchmark environment
    attack = load_attack("important_instructions", suite, pipeline)
    baseline_dict = attack.attack(user_task, injection_task)
    injection_key = (
        next(iter(baseline_dict.keys()))
        if baseline_dict
        else "calendar_networking_event_injection_email"
    )
    injections = {injection_key: synthetic_input}

    # Intercept runtime calls to capture tool decisions made by CryptoFirewall
    base_runtime_cls = make_cryptofirewall_runtime(user_task_id)
    intercepted_calls: list[dict] = []

    class AuditedCryptoFirewallRuntime(base_runtime_cls):
        def run_function(self, env, function, kwargs, raise_on_error=False):
            result, error = super().run_function(env, function, kwargs, raise_on_error)
            intercepted_calls.append(
                {
                    "tool": function,
                    "kwargs": kwargs,
                    "result": result,
                    "error": error,
                }
            )
            return result, error

    log_step(
        "PIPELINE",
        f"Executing AgentDojo pipeline with defended CryptoFirewall runtime (target={target_model})...",
        is_llm_call=True,
    )

    utility, security = suite.run_task_with_pipeline(
        agent_pipeline=pipeline,
        user_task=user_task,
        injection_task=injection_task,
        injections=injections,
        runtime_class=AuditedCryptoFirewallRuntime,
    )

    log_step(
        "PIPELINE",
        f"Run completed: Benign Utility={utility}, Security (Attack Succeeded)={security}",
    )

    # Inspect intercepted events to extract the exact firewall decision
    blocked_calls = [c for c in intercepted_calls if c.get("error")]
    if blocked_calls:
        first_blocked = blocked_calls[0]
        attempted_tool = first_blocked["tool"]
        firewall_decision = f"BLOCKED: {first_blocked['error']}"
    elif intercepted_calls:
        attempted_tool = intercepted_calls[-1]["tool"]
        firewall_decision = "ALLOWED"
    else:
        attempted_tool = None
        firewall_decision = "NO_TOOLS_ATTEMPTED"

    attempt = ProbeAttempt(
        agent_name="indirect_prompt_injection",
        synthetic_input=synthetic_input,
        attempted_tool=attempted_tool,
        firewall_decision=firewall_decision,
        success=bool(security),
    )

    log_step(
        "ORCHESTRATOR",
        f"Logged ProbeAttempt #{len(state.get('audit_history', [])) + 1}: "
        f"tool={attempted_tool}, decision={firewall_decision}, success={security}",
    )

    return {"audit_history": [attempt]}


def should_continue_audit(state: AuditState) -> str:
    """Conditional edge router: terminate when probe succeeds or max retries reached."""
    history = state.get("audit_history", [])
    last_success = history[-1].success if history else False
    retries = state.get("current_retry_count", 0)

    log_step(
        "ORCHESTRATOR",
        f"Checking conditional edge: success={last_success}, retry_count={retries}/{MAX_RETRIES}",
    )

    if last_success:
        log_step(
            "ORCHESTRATOR",
            "TERMINATION TRIGGER: Synthetic probe bypassed defense (False Negative discovered!). Routing to END.",
        )
        return END

    if retries >= MAX_RETRIES:
        log_step(
            "ORCHESTRATOR",
            f"TERMINATION TRIGGER: Reached maximum retry ceiling ({MAX_RETRIES}). Routing to END.",
        )
        return END

    log_step(
        "ORCHESTRATOR",
        f"Continuing audit loop (attempt {retries} of {MAX_RETRIES}). Routing back to 'generate_next_probe'.",
    )
    return "generate_next_probe"


def build_audit_graph():
    """Construct and compile the LangGraph Robustness Auditing Pipeline."""
    workflow = StateGraph(AuditState)

    workflow.add_node("generate_next_probe", generate_next_probe)
    workflow.add_node("execute_agentdojo_pipeline", execute_agentdojo_pipeline)
    workflow.add_node("analyze_defense_response", analyze_defense_response)

    workflow.set_entry_point("generate_next_probe")
    workflow.add_edge("generate_next_probe", "execute_agentdojo_pipeline")
    workflow.add_edge("execute_agentdojo_pipeline", "analyze_defense_response")
    workflow.add_conditional_edges(
        "analyze_defense_response",
        should_continue_audit,
        {
            END: END,
            "generate_next_probe": "generate_next_probe",
        },
    )

    return workflow.compile()


def main() -> None:
    load_dotenv(PROJECT_ROOT / ".env")

    print("\n" + "=" * 75)
    print(" GIKI ADAPTIVE ATTACK-DEFENSE CO-EVALUATION FRAMEWORK: AUDIT RUNNER")
    print("=" * 75)

    user_task_id = "user_task_0"
    injection_task_id = "injection_task_0"

    log_step(
        "ORCHESTRATOR",
        f"Initializing isolated adaptive audit scenario: {user_task_id} + {injection_task_id}",
    )
    log_step("ORCHESTRATOR", f"Max retries configured: {MAX_RETRIES}")

    initial_state: AuditState = {
        "target_task": user_task_id,
        "injection_task": injection_task_id,
        "audit_history": [],
        "active_heuristics": [],
        "current_retry_count": 0,
        "synthetic_input": "",
    }

    graph = build_audit_graph()
    final_state = graph.invoke(initial_state)

    # Print structured final blackboard review
    print("\n" + "=" * 75)
    print(" ADAPTIVE AUDIT SUMMARY REPORT")
    print("=" * 75)
    print(f"Target Scenario: {final_state.get('target_task')} + {final_state.get('injection_task')}")
    print(f"Total Iterations: {final_state.get('current_retry_count')}")
    print(f"Total Probes Executed: {len(final_state.get('audit_history', []))}")
    print("\nProbe History Breakdown:")
    for idx, probe in enumerate(final_state.get("audit_history", []), start=1):
        status = "BYPASS / SUCCESS" if probe.success else "DEFENSE BLOCKED"
        print(f"  [{idx}] Tool: {probe.attempted_tool} | Status: {status}")
        print(f"      Decision: {probe.firewall_decision}")
        preview_input = probe.synthetic_input.replace("\n", " ").strip()[:90]
        print(f"      Probe Input: {preview_input}...")

    print("\nActive Heuristics (Sliding Window Top-3):")
    heuristics = final_state.get("active_heuristics", [])
    if heuristics:
        for idx, h in enumerate(heuristics, start=1):
            print(f"  {idx}. {h}")
    else:
        print("  None (all tests passed or no heuristics required).")

    print("=" * 75 + "\n")


if __name__ == "__main__":
    main()

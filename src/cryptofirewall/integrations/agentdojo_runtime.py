from __future__ import annotations

from agentdojo.functions_runtime import FunctionsRuntime

from cryptofirewall.core.taint_registry import TaintRegistry
from cryptofirewall.core.flow_monitor import authorize_information_flow
from cryptofirewall.core.egress import ALLOWLIST_POLICY, UnauthorizedFlowError

SOURCE_TOOL_LABELS = {"get_current_day": "PUBLIC", "search_calendar_events": "INTERNAL", "get_day_calendar_events": "INTERNAL"}

from cryptofirewall.core.reference_monitor import (
    UnauthorizedActionError,
    authorize_tool_call,
)


class CryptoFirewallRuntime(FunctionsRuntime):
    """AgentDojo runtime enforcing task-scoped CryptoFirewall capabilities."""

    task_id: str | None = None

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.taint_registry = TaintRegistry()

    def run_function(self, env, function, kwargs, raise_on_error=False):
        print(f"[CryptoFirewall] intercepted tool: {function} kwargs={dict(kwargs)}")

        if self.task_id is None:
            raise RuntimeError("CryptoFirewallRuntime has no bound task_id.")

        try:
            authorize_tool_call(self.task_id, function, kwargs)
            print(f"[CryptoFirewall] ALLOW: {function}")
        except UnauthorizedActionError as e:
            print(f"[CryptoFirewall] BLOCK: {function} -- {e}")
            if raise_on_error:
                raise
            return "", f"UnauthorizedActionError: {e}"

        if function in ALLOWLIST_POLICY:
            try:
                matches = authorize_information_flow(function, kwargs, self.taint_registry)
                if matches:
                    print(f"[CryptoFirewall] FLOW ALLOW: {function} matched_taints={len(matches)}")
            except UnauthorizedFlowError as e:
                print(f"[CryptoFirewall] FLOW BLOCK: {function} -- {e}")
                if raise_on_error:
                    raise
                return "", f"UnauthorizedFlowError: {e}"

        result, error = super().run_function(env, function, kwargs, raise_on_error)
        label = SOURCE_TOOL_LABELS.get(function)
        if error is None and label is not None:
            before = len(self.taint_registry.records)
            self.taint_registry.register_result(result, label, function)
            added = len(self.taint_registry.records) - before
            print(f"[CryptoFirewall] TAINT: {function} label={label} records_added={added}")
        return result, error


def make_cryptofirewall_runtime(task_id: str) -> type[CryptoFirewallRuntime]:
    """Return a CryptoFirewall runtime class bound to one task capability."""

    class TaskBoundCryptoFirewallRuntime(CryptoFirewallRuntime):
        pass

    TaskBoundCryptoFirewallRuntime.task_id = task_id
    TaskBoundCryptoFirewallRuntime.__name__ = f"CryptoFirewallRuntime_{task_id}"
    return TaskBoundCryptoFirewallRuntime

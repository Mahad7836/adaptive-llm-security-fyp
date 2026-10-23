from __future__ import annotations

from agentdojo.functions_runtime import FunctionsRuntime

from cryptofirewall.core.reference_monitor import (
    UnauthorizedActionError,
    authorize_tool_call,
)


class CryptoFirewallRuntime(FunctionsRuntime):
    """AgentDojo runtime enforcing task-scoped CryptoFirewall capabilities."""

    task_id: str | None = None

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

        return super().run_function(env, function, kwargs, raise_on_error)


def make_cryptofirewall_runtime(task_id: str) -> type[CryptoFirewallRuntime]:
    """Return a CryptoFirewall runtime class bound to one task capability."""

    class TaskBoundCryptoFirewallRuntime(CryptoFirewallRuntime):
        pass

    TaskBoundCryptoFirewallRuntime.task_id = task_id
    TaskBoundCryptoFirewallRuntime.__name__ = f"CryptoFirewallRuntime_{task_id}"
    return TaskBoundCryptoFirewallRuntime

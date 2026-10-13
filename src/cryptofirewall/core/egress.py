import functools
from typing import Any, Callable

try:
    from cryptofirewall.core.crypto_tracker import TaintedString, TaintExhaustionError
except ImportError:
    from .crypto_tracker import TaintedString, TaintExhaustionError


class SecurityViolationError(Exception):
    """Raised when tainted data fails cryptographic integrity checks or TTL expiry at the egress gate."""


class UnauthorizedFlowError(Exception):
    """Raised when tainted data violates destination allowlist egress policy."""


ALLOWLIST_POLICY: dict[str, list[str]] = {
    "send_email": ["PUBLIC", "LOW_RISK"],
    "execute_transaction": ["FINANCIAL_APPROVED", "LOW_RISK"],
    "cloud_file_upload": ["PUBLIC"],
    "internal_audit_log": ["PUBLIC", "LOW_RISK", "INTERNAL", "AUDIT"],
}


def egress_monitor(destination_name: str) -> Callable[..., Any]:
    """Decorator reference monitor enforcing deterministic egress information-flow control and anti-replay consumption."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            allowed_labels = ALLOWLIST_POLICY.get(destination_name, [])

            # Phase 1: Validate integrity, consumption state, and egress policy across all arguments
            def _validate_node(node: Any) -> None:
                if isinstance(node, TaintedString):
                    if node._consumed:
                        raise TaintExhaustionError(
                            f"Anti-replay violation: TaintedString with label '{node._label}' has already been consumed."
                        )
                    if not node.verify_integrity():
                        raise SecurityViolationError(
                            f"Integrity check failed: Tainted data with label '{node._label}' has been modified or expired."
                        )
                    if node._label not in allowed_labels:
                        raise UnauthorizedFlowError(
                            f"Unauthorized information flow: TaintedString with label '{node._label}' "
                            f"is not permitted for destination tool '{destination_name}'. "
                            f"Allowed labels: {allowed_labels}."
                        )
                elif isinstance(node, (list, tuple, set)):
                    for item in node:
                        _validate_node(item)
                elif isinstance(node, dict):
                    for item in node.values():
                        _validate_node(item)

            for arg in args:
                _validate_node(arg)
            for kwarg_value in kwargs.values():
                _validate_node(kwarg_value)

            # Phase 2: Consume all validated TaintedString instances immediately before tool execution
            def _consume_node(node: Any) -> None:
                if isinstance(node, TaintedString):
                    node.consume()
                elif isinstance(node, (list, tuple, set)):
                    for item in node:
                        _consume_node(item)
                elif isinstance(node, dict):
                    for item in node.values():
                        _consume_node(item)

            for arg in args:
                _consume_node(arg)
            for kwarg_value in kwargs.values():
                _consume_node(kwarg_value)

            return func(*args, **kwargs)

        return wrapper

    return decorator

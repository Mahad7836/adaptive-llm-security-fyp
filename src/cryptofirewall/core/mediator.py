from typing import Any, Dict

try:
    from cryptofirewall.core.crypto_tracker import TaintedString
except ImportError:
    from .crypto_tracker import TaintedString


def _sanitize_node(node: Any) -> Any:
    """Recursively traverses and sanitizes nested data structures, replacing tainted values with safe redactions."""
    if isinstance(node, TaintedString):
        clean_label = node._label.strip().upper()
        return f"<REDACTED_{clean_label}>"
    if isinstance(node, dict):
        return {key: _sanitize_node(val) for key, val in node.items()}
    if isinstance(node, list):
        return [_sanitize_node(item) for item in node]
    if isinstance(node, tuple):
        return tuple(_sanitize_node(item) for item in node)
    if isinstance(node, set):
        return {_sanitize_node(item) for item in node}
    return node


def sanitize_for_planner(llm_output: dict[str, Any]) -> dict[str, Any]:
    """Airgapped execution mediator that cleans raw tool/LLM outputs before passing to the privileged planner.

    Recursively removes any TaintedString objects, replacing them with safe redaction
    placeholders (e.g., '<REDACTED_PII>', '<REDACTED_FINANCIAL>') to prevent context bleeding.
    """
    sanitized_output: dict[str, Any] = {}
    for key, value in llm_output.items():
        sanitized_output[key] = _sanitize_node(value)
    return sanitized_output

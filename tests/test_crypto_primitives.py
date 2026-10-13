import time
from typing import Any
from unittest.mock import patch
import pytest

from cryptofirewall.core.crypto_tracker import (
    MAX_PAYLOAD_BYTES,
    PayloadSizeError,
    TaintedString,
    TaintExhaustionError,
    TaintTamperError,
)
from cryptofirewall.core.egress import (
    ALLOWLIST_POLICY,
    SecurityViolationError,
    UnauthorizedFlowError,
    egress_monitor,
)
from cryptofirewall.core.mediator import sanitize_for_planner


def test_hmac_integrity_tampering() -> None:
    """Test HMAC integrity detection when _raw_data is altered via reflection."""
    raw_payload = "confidential_ssn_1234"
    label = "PII"
    tainted = TaintedString(data=raw_payload, label=label)

    # Initial state should be valid and extractable
    assert tainted.verify_integrity() is True
    assert tainted.extract() == raw_payload

    # Tamper with _raw_data via reflection / attribute assignment
    setattr(tainted, "_raw_data", "maliciously_injected_ssn_9999")

    # Integrity verification must fail deterministically
    assert tainted.verify_integrity() is False

    # Extract must reject tampered data by raising TaintTamperError
    with pytest.raises(TaintTamperError) as exc_info:
        tainted.extract()
    assert "tampered" in str(exc_info.value).lower()


def test_egress_authorization_unauthorized_flow() -> None:
    """Test egress reference monitor blocking unauthorized tainted flow based on policy."""
    @egress_monitor("send_email")
    def mock_send(data: Any) -> str:
        return f"delivered: {data}"

    # ALLOWLIST_POLICY["send_email"] is ["PUBLIC", "LOW_RISK"].
    # Passing "FINANCIAL" must be deterministically blocked.
    financial_data = TaintedString(data="credit_card_4111222233334444", label="FINANCIAL")

    with pytest.raises(UnauthorizedFlowError) as exc_info:
        mock_send(financial_data)

    assert "FINANCIAL" in str(exc_info.value)
    assert "send_email" in str(exc_info.value)


def test_safe_execution_mediator_redaction() -> None:
    """Test mediator recursing into nested structures and replacing TaintedStrings with metadata placeholders."""
    raw_output: dict[str, Any] = {
        "status": "success",
        "missing_fields": ["cnic"],
        "record_id": 4289,
        "is_active": True,
        "details": {
            "applicant_name": "Alice Smith",
            "tax_id": TaintedString(data="TAX-998877", label="PII"),
            "banking": {
                "account_balance": TaintedString(data="$15,400.00", label="FINANCIAL"),
                "routing_code": "021000021",
            },
        },
        "attachments": [
            "statement_summary.pdf",
            TaintedString(data="salary_slip_internal", label="HR_CONFIDENTIAL"),
        ],
    }

    sanitized = sanitize_for_planner(raw_output)

    # Validate high-level safe state remains intact
    assert sanitized["status"] == "success"
    assert sanitized["missing_fields"] == ["cnic"]
    assert sanitized["record_id"] == 4289
    assert sanitized["is_active"] is True

    # Validate nested structures preserved with TaintedStrings redacted
    assert sanitized["details"]["applicant_name"] == "Alice Smith"
    assert sanitized["details"]["tax_id"] == "<REDACTED_PII>"
    assert sanitized["details"]["banking"]["account_balance"] == "<REDACTED_FINANCIAL>"
    assert sanitized["details"]["banking"]["routing_code"] == "021000021"

    # Validate lists preserved with TaintedStrings redacted
    assert sanitized["attachments"][0] == "statement_summary.pdf"
    assert sanitized["attachments"][1] == "<REDACTED_HR_CONFIDENTIAL>"

    # Ensure original dictionary was not mutated in place
    assert isinstance(raw_output["details"]["tax_id"], TaintedString)


def test_hmac_integrity_label_tampering() -> None:
    """Verify that tampering with sensitivity label also invalidates integrity."""
    tainted = TaintedString(data="clean_document", label="PUBLIC")
    assert tainted.verify_integrity() is True

    # Tamper with label via reflection
    setattr(tainted, "_label", "INTERNAL")
    assert tainted.verify_integrity() is False

    with pytest.raises(TaintTamperError):
        tainted.extract()


def test_custom_secret_key() -> None:
    """Verify custom key support and deterministic MAC consistency."""
    secret = b"my_deterministic_32_byte_secret!"
    now = time.time()
    with patch("time.time", return_value=now):
        t1 = TaintedString(data="data", label="PII", secret_key=secret)
        t2 = TaintedString(data="data", label="PII", secret_key=secret)
        assert t1._mac == t2._mac
        assert t1.verify_integrity() is True


def test_egress_monitor_allowed_flow() -> None:
    """Verify egress monitor permits labels declared in ALLOWLIST_POLICY."""
    @egress_monitor("send_email")
    def mock_send(recipient: str, body: Any) -> str:
        return f"Sent to {recipient}"

    public_note = TaintedString(data="Meeting at 2pm", label="PUBLIC")
    low_risk_note = TaintedString(data="Weekly digest", label="LOW_RISK")

    # Positional argument allowed
    assert mock_send("test@example.com", public_note) == "Sent to test@example.com"
    # Keyword argument allowed
    assert mock_send(recipient="test@example.com", body=low_risk_note) == "Sent to test@example.com"


def test_egress_monitor_detects_tampering() -> None:
    """Verify egress monitor catches tampered TaintedString before egress."""
    @egress_monitor("send_email")
    def mock_send(data: Any) -> str:
        return "ok"

    tampered_data = TaintedString(data="legit", label="PUBLIC")
    setattr(tampered_data, "_raw_data", "injected_jailbreak")

    with pytest.raises(SecurityViolationError) as exc_info:
        mock_send(tampered_data)
    assert "modified" in str(exc_info.value).lower()


def test_egress_monitor_nested_taint_violation() -> None:
    """Verify egress monitor traverses nested args and kwargs to block unauthorized flows."""
    @egress_monitor("send_email")
    def mock_send(payload: dict[str, Any]) -> str:
        return "ok"

    nested_payload = {
        "metadata": {"title": "Summary"},
        "records": [
            TaintedString(data="unauthorized_financial_data", label="FINANCIAL"),
        ],
    }

    with pytest.raises(UnauthorizedFlowError):
        mock_send(nested_payload)


def test_ttl_expiry() -> None:
    """Test TTL Expiry: Instantiate TaintedString, simulate 31s elapsed with patch on time.time, assert verify_integrity() is False."""
    base_time = 1700000000.0
    with patch("time.time", return_value=base_time):
        tainted = TaintedString(data="temporary_auth_token", label="PII")
        assert tainted.verify_integrity() is True

    # Fast forward time by 31 seconds
    with patch("time.time", return_value=base_time + 31.0):
        assert tainted.verify_integrity() is False
        with pytest.raises(TaintTamperError):
            tainted.extract()


def test_anti_replay_consumption() -> None:
    """Test Anti-Replay Consumption: Pass valid TaintedString through mock egress monitor, catch it, and attempt reuse."""
    @egress_monitor("send_email")
    def mock_send(data: Any) -> str:
        return f"delivered: {data}"

    tainted = TaintedString(data="one_time_notice", label="PUBLIC")

    # First call must succeed and consume the object
    result = mock_send(tainted)
    assert "delivered" in result
    assert tainted._consumed is True

    # Replaying the exact same object must be blocked deterministically
    with pytest.raises(TaintExhaustionError) as exc_info:
        mock_send(tainted)
    assert "anti-replay" in str(exc_info.value).lower()


def test_payload_size_limit() -> None:
    """Test Payload Size Limit: Attempt to instantiate TaintedString with 1,000,000 characters; assert PayloadSizeError."""
    huge_payload = "A" * 1_000_000
    with pytest.raises(PayloadSizeError) as exc_info:
        TaintedString(data=huge_payload, label="PII")
    assert "exceeds" in str(exc_info.value).lower()

import time
from typing import Any
from unittest.mock import patch
import pytest

from cryptofirewall.core.crypto_tracker import (
    MAX_PAYLOAD_BYTES,
    MissingSecurityKeyError,
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


@pytest.fixture(autouse=True)
def setup_security_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fixture providing deterministic test secret key in environment."""
    monkeypatch.setenv("CRYPTOFIREWALL_SECRET_KEY", "test_secret_key_32_bytes_long!")


def test_missing_security_key_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Assert MissingSecurityKeyError is raised when CRYPTOFIREWALL_SECRET_KEY is missing or empty."""
    monkeypatch.delenv("CRYPTOFIREWALL_SECRET_KEY", raising=False)
    with pytest.raises(MissingSecurityKeyError) as exc_info:
        TaintedString(data="35201-1234567-1", label="PII_CNIC")
    assert "missing or empty" in str(exc_info.value).lower()

    # Also test empty string case
    monkeypatch.setenv("CRYPTOFIREWALL_SECRET_KEY", "")
    with pytest.raises(MissingSecurityKeyError):
        TaintedString(data="35201-1234567-1", label="PII_CNIC")


def test_hmac_verification_fails_on_raw_data_tampering() -> None:
    """Assert HMAC verification fails and extract() raises TaintTamperError when _raw_data is altered via reflection."""
    original_cnic = "42101-9876543-3"
    tainted = TaintedString(data=original_cnic, label="PII_CNIC")

    # Initial state must be valid
    assert tainted.verify_integrity() is True
    assert tainted.extract() == original_cnic

    # Alter _raw_data via reflection
    setattr(tainted, "_raw_data", "42101-0000000-0")

    # Verification must fail deterministically
    assert tainted.verify_integrity() is False

    with pytest.raises(TaintTamperError) as exc_info:
        tainted.extract()
    assert "tampered" in str(exc_info.value).lower()


def test_ttl_expiry_fails_verification() -> None:
    """Assert TTL expiry (mock time.time + 31 seconds) fails verification and extraction."""
    base_time = 1700000000.0
    with patch("time.time", return_value=base_time):
        tainted = TaintedString(data="PK78MEZN0001234567890101", label="FINANCIAL_KYC")
        assert tainted.verify_integrity() is True

    # Fast forward beyond 30-second TTL
    with patch("time.time", return_value=base_time + 31.0):
        assert tainted.verify_integrity() is False
        with pytest.raises(TaintTamperError):
            tainted.extract()


def test_anti_replay_double_egress_raises_exhaustion() -> None:
    """Assert Anti-Replay: Passing the same TaintedString to a mock @egress_monitor twice raises TaintExhaustionError."""
    @egress_monitor("upload_to_nadra_cloud")
    def mock_nadra_upload(record: Any) -> str:
        return f"uploaded: {record}"

    cnic_record = TaintedString(data="61101-1122334-5", label="PII_CNIC")

    # First tool invocation must succeed and consume the object
    first_result = mock_nadra_upload(cnic_record)
    assert "uploaded" in first_result
    assert cnic_record._consumed is True

    # Immediate second tool invocation must be deterministically blocked
    with pytest.raises(TaintExhaustionError) as exc_info:
        mock_nadra_upload(cnic_record)
    assert "anti-replay" in str(exc_info.value).lower()


def test_unauthorized_flow_financial_kyc_to_send_email() -> None:
    """Assert UnauthorizedFlowError when sending FINANCIAL_KYC to 'send_email' destination."""
    @egress_monitor("send_email")
    def mock_send_email(content: Any) -> str:
        return "email_sent"

    # ALLOWLIST_POLICY["send_email"] is strictly ["PUBLIC"]. FINANCIAL_KYC must be blocked.
    kyc_data = TaintedString(data="IBAN:PK36SCBL0000001123456701", label="FINANCIAL_KYC")

    with pytest.raises(UnauthorizedFlowError) as exc_info:
        mock_send_email(kyc_data)

    assert "FINANCIAL_KYC" in str(exc_info.value)
    assert "send_email" in str(exc_info.value)


def test_sanitize_for_planner_converts_to_redacted_pii_cnic() -> None:
    """Assert sanitize_for_planner successfully converts a TaintedString into <REDACTED_PII_CNIC>."""
    raw_llm_state: dict[str, Any] = {
        "status": "success",
        "service": "telecom_sim_verification",
        "user_profile": {
            "name": "Muhammad Ali",
            "cnic": TaintedString(data="37405-1234567-9", label="PII_CNIC"),
            "banking": {
                "account_title": "M. Ali",
                "salary": TaintedString(data="PKR 250,000", label="HR_PAYROLL"),
            },
        },
        "flags": [
            "biometric_verified",
            TaintedString(data="Tier 1 High Value KYC", label="FINANCIAL_KYC"),
        ],
    }

    sanitized = sanitize_for_planner(raw_llm_state)

    # Core non-tainted state preserved
    assert sanitized["status"] == "success"
    assert sanitized["service"] == "telecom_sim_verification"
    assert sanitized["user_profile"]["name"] == "Muhammad Ali"
    assert sanitized["user_profile"]["banking"]["account_title"] == "M. Ali"
    assert sanitized["flags"][0] == "biometric_verified"

    # Tainted strings accurately redacted with standardized placeholders
    assert sanitized["user_profile"]["cnic"] == "<REDACTED_PII_CNIC>"
    assert sanitized["user_profile"]["banking"]["salary"] == "<REDACTED_HR_PAYROLL>"
    assert sanitized["flags"][1] == "<REDACTED_FINANCIAL_KYC>"

    # Ensure source object remains untouched
    assert isinstance(raw_llm_state["user_profile"]["cnic"], TaintedString)


def test_authorized_egress_flows_pakistani_policy() -> None:
    """Assert that authorized label flows succeed across configured tool endpoints."""
    @egress_monitor("upload_to_nadra_cloud")
    def nadra_tool(data: Any) -> str:
        return "nadra_ack"

    @egress_monitor("execute_bank_transfer")
    def transfer_tool(data: Any) -> str:
        return "transfer_ack"

    @egress_monitor("write_audit_log")
    def audit_tool(data: Any) -> str:
        return "audit_ack"

    cnic = TaintedString(data="35202-0000000-1", label="PII_CNIC")
    kyc = TaintedString(data="PKR 50,000 to Acc 0123", label="FINANCIAL_KYC")
    payroll = TaintedString(data="Disbursement Batch 09", label="HR_PAYROLL")

    assert nadra_tool(cnic) == "nadra_ack"
    assert transfer_tool(kyc) == "transfer_ack"
    assert audit_tool(payroll) == "audit_ack"


def test_egress_gate_detects_tampered_payload() -> None:
    """Assert egress gate raises SecurityViolationError when tampered data reaches egress."""
    @egress_monitor("upload_to_nadra_cloud")
    def nadra_tool(data: Any) -> str:
        return "nadra_ack"

    tampered_cnic = TaintedString(data="35202-1234567-1", label="PII_CNIC")
    setattr(tampered_cnic, "_raw_data", "35202-9999999-9")

    with pytest.raises(SecurityViolationError) as exc_info:
        nadra_tool(tampered_cnic)
    assert "security violation" in str(exc_info.value).lower()


def test_dos_payload_size_limit() -> None:
    """Assert PayloadSizeError when payload exceeds MAX_PAYLOAD_BYTES limit."""
    oversized_data = "X" * (MAX_PAYLOAD_BYTES + 1)
    with pytest.raises(PayloadSizeError) as exc_info:
        TaintedString(data=oversized_data, label="INTERNAL")
    assert "exceeds" in str(exc_info.value).lower()

import hashlib
import hmac
import secrets
import time

MAX_PAYLOAD_BYTES: int = 500_000


class TaintTamperError(Exception):
    """Raised when cryptographic integrity verification fails for a TaintedString."""


class TaintExhaustionError(Exception):
    """Raised when a consumed TaintedString is accessed or reused in violation of anti-replay policy."""


class PayloadSizeError(Exception):
    """Raised when data payload exceeds the maximum allowed byte size for DoS mitigation."""


class TaintedString:
    """Tracks untrusted string data provenance with cryptographic HMAC-SHA256 integrity, TTL, and anti-replay protection."""

    def __init__(
        self,
        data: str,
        label: str,
        secret_key: bytes | None = None,
        created_at: float | None = None,
    ) -> None:
        payload_bytes = data.encode("utf-8")
        if len(payload_bytes) > MAX_PAYLOAD_BYTES:
            raise PayloadSizeError(
                f"Payload size {len(payload_bytes)} bytes exceeds maximum threshold of {MAX_PAYLOAD_BYTES} bytes."
            )

        self._raw_data: str = data
        self._label: str = label
        self._created_at: float = created_at if created_at is not None else time.time()
        self._consumed: bool = False
        self._secret_key: bytes = secret_key if secret_key is not None else secrets.token_bytes(32)
        self._mac: str = self._compute_mac()

    def _compute_mac(self) -> str:
        """Returns the HMAC-SHA256 hex digest for (data + label + str(created_at))."""
        payload = (self._raw_data + self._label + str(self._created_at)).encode("utf-8")
        return hmac.new(self._secret_key, msg=payload, digestmod=hashlib.sha256).hexdigest()

    def consume(self) -> None:
        """Marks the tainted string as consumed. Raises TaintExhaustionError if already consumed."""
        if self._consumed:
            raise TaintExhaustionError(
                f"Anti-replay violation: Tainted data with label '{self._label}' has already been consumed."
            )
        self._consumed = True

    def verify_integrity(self, max_ttl_seconds: int = 30) -> bool:
        """Verifies cryptographic integrity, unconsumed status, and TTL validity."""
        if self._consumed:
            return False

        if (time.time() - self._created_at) > max_ttl_seconds:
            return False

        current_mac = self._compute_mac()
        return hmac.compare_digest(current_mac, self._mac)

    def extract(self) -> str:
        """Returns _raw_data ONLY if verify_integrity() is True; otherwise raises appropriate error."""
        if self._consumed:
            raise TaintExhaustionError(
                f"Cannot extract consumed tainted data with label '{self._label}'."
            )

        if not self.verify_integrity():
            raise TaintTamperError(
                f"Cryptographic integrity check failed: Tainted data with label '{self._label}' has been tampered with or expired."
            )

        return self._raw_data

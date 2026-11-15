from __future__ import annotations

import os
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

# Global debug toggle reading from AUDIT_DEBUG environment variable (default: True)
ENABLE_AUDIT_DEBUG: bool = (
    os.getenv("AUDIT_DEBUG", "True").strip().lower() in ("true", "1", "yes")
)


def log_step(step_name: str, message: str, is_llm_call: bool = False) -> None:
    """Log formatted terminal QA statements for the adaptive audit pipeline.

    Args:
        step_name: Logical pipeline stage or agent identifier (e.g. 'EVALUATOR', 'TESTER', 'API').
        message: Informational description of the current action or status.
        is_llm_call: If True, specifically outputs an API waiting notice to highlight network latency.
    """
    debug_enabled = (
        os.getenv("AUDIT_DEBUG", str(ENABLE_AUDIT_DEBUG)).strip().lower()
        in ("true", "1", "yes")
    )
    if not debug_enabled:
        return

    if is_llm_call:
        print("[AUDIT_DEBUG] [API] Waiting for Groq LLM response...")
        if message:
            print(f"[AUDIT_DEBUG] [{step_name.upper()}] {message}")
    else:
        print(f"[AUDIT_DEBUG] [{step_name.upper()}] {message}")

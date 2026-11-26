from __future__ import annotations

import operator
from typing import Annotated, TypedDict
from typing_extensions import NotRequired
from pydantic import BaseModel, Field


class ProbeAttempt(BaseModel):
    """Structured QA audit attempt capturing synthetic probe interaction with CryptoFirewall."""

    agent_name: str = Field(description="Name or identifier of the probe-generating agent")
    synthetic_input: str = Field(description="Synthetic edge-case input payload tested")
    attempted_tool: str | None = Field(
        default=None, description="Tool invocation intercepted by the defense middleware"
    )
    firewall_decision: str = Field(
        description="Outcome decision string from CryptoFirewall (e.g., 'BLOCKED: UnauthorizedFlowError')"
    )
    success: bool = Field(
        description="Whether the probe bypassed the defense and attained its goal (True) or was blocked/failed (False)"
    )


class AuditState(TypedDict):
    """The shared memory blackboard for the LangGraph adaptive robustness audit."""

    target_task: str
    audit_history: Annotated[list[ProbeAttempt], operator.add]
    active_heuristics: list[str]
    current_retry_count: int
    synthetic_input: NotRequired[str]
    injection_task: NotRequired[str]
    selected_agent: NotRequired[str]
    max_retries: NotRequired[int]

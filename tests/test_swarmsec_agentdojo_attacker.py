import pytest

from agentdojo.agent_pipeline.ground_truth_pipeline import GroundTruthPipeline
from agentdojo.attacks.base_attacks import BaseAttack
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.task_suite.load_suites import get_suite

from swarmsec.agents.indirect_prompt_injection import IndirectPromptInjectionAgent


class StubAttack(BaseAttack):
    def attack(
        self,
        user_task: BaseUserTask,
        injection_task: BaseInjectionTask,
    ) -> dict[str, str]:
        return {user_task.ID: injection_task.ID}


def test_agent_generates_injections_through_registered_attack(monkeypatch) -> None:
    suite = get_suite("v1.2.2", "workspace")
    user_task = suite.get_user_task_by_id("user_task_0")
    target_pipeline = GroundTruthPipeline(user_task)
    registered_attack = StubAttack(suite, target_pipeline)
    calls: list[tuple[str, object, object]] = []

    def load_registered_attack(name, task_suite, pipeline):
        calls.append((name, task_suite, pipeline))
        return registered_attack

    monkeypatch.setattr(
        "swarmsec.agents.indirect_prompt_injection.load_attack",
        load_registered_attack,
    )

    attacker = IndirectPromptInjectionAgent(suite, target_pipeline)
    injection_task = suite.get_injection_task_by_id("injection_task_0")

    assert attacker.generate(user_task, injection_task) == {
        user_task.ID: injection_task.ID
    }
    assert calls == [("important_instructions", suite, target_pipeline)]


def test_agent_rejects_task_objects_from_another_suite(monkeypatch) -> None:
    suite = get_suite("v1.2.2", "workspace")
    other_suite = get_suite("v1.2.2", "banking")
    target_pipeline = GroundTruthPipeline(suite.get_user_task_by_id("user_task_0"))

    monkeypatch.setattr(
        "swarmsec.agents.indirect_prompt_injection.load_attack",
        lambda _, task_suite, pipeline: StubAttack(task_suite, pipeline),
    )
    attacker = IndirectPromptInjectionAgent(suite, target_pipeline)

    with pytest.raises(ValueError, match="canonical task"):
        attacker.generate(
            other_suite.get_user_task_by_id("user_task_0"),
            suite.get_injection_task_by_id("injection_task_0"),
        )

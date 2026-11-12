from __future__ import annotations

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.attacks.base_attacks import BaseAttack
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.task_suite.task_suite import TaskSuite


class IndirectPromptInjectionAgent:
    """SwarmSec adapter for AgentDojo's registered indirect-injection attack."""

    name = "agentdojo_important_instructions"
    suite_name = "workspace"
    attack_name = "important_instructions"

    def __init__(
        self,
        task_suite: TaskSuite,
        target_pipeline: BasePipelineElement,
    ) -> None:
        if task_suite.name != self.suite_name:
            raise ValueError(
                f"{type(self).__name__} only supports the AgentDojo "
                f"{self.suite_name!r} suite, not {task_suite.name!r}."
            )

        self._task_suite = task_suite
        self._attack: BaseAttack = load_attack(
            self.attack_name,
            task_suite,
            target_pipeline,
        )

    def generate(
        self,
        user_task: BaseUserTask,
        injection_task: BaseInjectionTask,
    ) -> dict[str, str]:
        if self._task_suite.user_tasks.get(user_task.ID) is not user_task:
            raise ValueError(
                f"User task {user_task.ID!r} is not a canonical task "
                f"from the {self.suite_name!r} suite."
            )
        if self._task_suite.injection_tasks.get(injection_task.ID) is not injection_task:
            raise ValueError(
                f"Injection task {injection_task.ID!r} is not a canonical task "
                f"from the {self.suite_name!r} suite."
            )

        return self._attack.attack(user_task, injection_task)

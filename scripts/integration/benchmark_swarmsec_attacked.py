import os

from dotenv import load_dotenv

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.models import ModelsEnum
from agentdojo.task_suite.load_suites import get_suite

from cryptofirewall.integrations.agentdojo_runtime import make_cryptofirewall_runtime
from swarmsec.agents import IndirectPromptInjectionAgent


BENCHMARK_VERSION = "v1.2.2"
SUITE_NAME = "workspace"
DEFAULT_TARGET_MODEL = "openai/gpt-oss-120b"
USER_TASK_IDS = tuple(f"user_task_{index}" for index in range(5))
INJECTION_TASK_IDS = tuple(f"injection_task_{index}" for index in range(3))


def main() -> None:
    load_dotenv(".env")

    target_model = os.getenv("GROQ_MODEL", DEFAULT_TARGET_MODEL)
    suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)
    pipeline = AgentPipeline.from_config(
        PipelineConfig(
            llm=ModelsEnum.OPENAI_COMPATIBLE,
            model_id=target_model,
            defense=None,
            system_message_name=None,
            system_message=None,
        )
    )
    attacker = IndirectPromptInjectionAgent(suite, pipeline)

    results: list[tuple[str, str, bool, bool]] = []
    for user_task_id in USER_TASK_IDS:
        for injection_task_id in INJECTION_TASK_IDS:
            print(f"\n===== {user_task_id} + {injection_task_id} =====")
            user_task = suite.get_user_task_by_id(user_task_id)
            injection_task = suite.get_injection_task_by_id(injection_task_id)
            injections = attacker.generate(user_task, injection_task)
            runtime = make_cryptofirewall_runtime(user_task_id)
            utility, security = suite.run_task_with_pipeline(
                agent_pipeline=pipeline,
                user_task=user_task,
                injection_task=injection_task,
                injections=injections,
                runtime_class=runtime,
            )
            results.append((user_task_id, injection_task_id, utility, security))
            print(f"Utility: {utility}")
            print(f"Attack success: {security}")

    total = len(results)
    utility_passes = sum(utility for _, _, utility, _ in results)
    attack_successes = sum(security for _, _, _, security in results)

    print("\n===== SWARMSEC + CRYPTOFIREWALL SUMMARY =====")
    print(f"Target model: {target_model}")
    print(f"Attacker: {attacker.name}")
    print(f"Utility: {utility_passes}/{total} = {utility_passes / total * 100:.2f}%")
    print(
        f"Targeted ASR: {attack_successes}/{total} = "
        f"{attack_successes / total * 100:.2f}%"
    )


if __name__ == "__main__":
    main()

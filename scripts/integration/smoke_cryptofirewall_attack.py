from dotenv import load_dotenv

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.models import ModelsEnum
from agentdojo.task_suite.load_suites import get_suite

from cryptofirewall.integrations.agentdojo_runtime import make_cryptofirewall_runtime


load_dotenv(".env")

suite = get_suite("v1.2.2", "workspace")
user_task = suite.get_user_task_by_id("user_task_4")
injection_task = suite.get_injection_task_by_id("injection_task_2")

pipeline = AgentPipeline.from_config(
    PipelineConfig(
        llm=ModelsEnum.OPENAI_COMPATIBLE,
        model_id="openai/gpt-oss-120b",
        defense=None,
        system_message_name=None,
        system_message=None,
    )
)

attack = load_attack("important_instructions", suite, pipeline)
injections = attack.attack(user_task, injection_task)

utility, security = suite.run_task_with_pipeline(
    agent_pipeline=pipeline,
    user_task=user_task,
    injection_task=injection_task,
    injections=injections,
    runtime_class=make_cryptofirewall_runtime("user_task_4"),
)

print("CryptoFirewallRuntime attacked smoke test complete")
print(f"Utility: {utility}")
print(f"Attack success / AgentDojo security field: {security}")

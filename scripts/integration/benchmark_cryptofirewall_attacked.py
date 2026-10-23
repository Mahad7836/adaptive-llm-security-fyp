from dotenv import load_dotenv
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.models import ModelsEnum
from agentdojo.task_suite.load_suites import get_suite
from cryptofirewall.integrations.agentdojo_runtime import make_cryptofirewall_runtime

load_dotenv(".env")

suite = get_suite("v1.2.2", "workspace")
pipeline = AgentPipeline.from_config(PipelineConfig(llm=ModelsEnum.OPENAI_COMPATIBLE, model_id="openai/gpt-oss-120b", defense=None, system_message_name=None, system_message=None))
attack = load_attack("important_instructions", suite, pipeline)

user_task_ids = [f"user_task_{i}" for i in range(5)]
injection_task_ids = [f"injection_task_{i}" for i in range(3)]

results = []

for user_task_id in user_task_ids:
    for injection_task_id in injection_task_ids:
        print(f"\n===== {user_task_id} + {injection_task_id} =====")
        user_task = suite.get_user_task_by_id(user_task_id)
        injection_task = suite.get_injection_task_by_id(injection_task_id)
        injections = attack.attack(user_task, injection_task)
        Runtime = make_cryptofirewall_runtime(user_task_id)
        utility, security = suite.run_task_with_pipeline(agent_pipeline=pipeline, user_task=user_task, injection_task=injection_task, injections=injections, runtime_class=Runtime)
        results.append((user_task_id, injection_task_id, utility, security))
        print(f"Utility: {utility}")
        print(f"Attack success: {security}")

utility_passes = sum(1 for _,_,u,_ in results if u)
attack_successes = sum(1 for _,_,_,s in results if s)

print("\n===== DEFENDED SUMMARY =====")
print(f"Utility: {utility_passes}/15 = {utility_passes/15*100:.2f}%")
print(f"Targeted ASR: {attack_successes}/15 = {attack_successes/15*100:.2f}%")
print(f"Prevented attacks: {15-attack_successes}/15 = {(15-attack_successes)/15*100:.2f}%")

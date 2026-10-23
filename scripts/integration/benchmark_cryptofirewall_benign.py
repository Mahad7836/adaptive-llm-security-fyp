from dotenv import load_dotenv
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, PipelineConfig
from agentdojo.models import ModelsEnum
from agentdojo.task_suite.load_suites import get_suite
from cryptofirewall.integrations.agentdojo_runtime import make_cryptofirewall_runtime

load_dotenv(".env")

suite = get_suite("v1.2.2", "workspace")
pipeline = AgentPipeline.from_config(PipelineConfig(llm=ModelsEnum.OPENAI_COMPATIBLE, model_id="openai/gpt-oss-120b", defense=None, system_message_name=None, system_message=None))

task_ids = [f"user_task_{i}" for i in range(5)]
results = {}

for task_id in task_ids:
    print(f"\n===== {task_id} =====")
    task = suite.get_user_task_by_id(task_id)
    Runtime = make_cryptofirewall_runtime(task_id)
    utility, security = suite.run_task_with_pipeline(agent_pipeline=pipeline, user_task=task, injection_task=None, injections={}, runtime_class=Runtime)
    results[task_id] = utility
    print(f"{task_id} utility: {utility}")

passed = sum(results.values())
print("\n===== SUMMARY =====")
print(f"Passed: {passed}/5")
print(f"Average utility: {passed/5*100:.2f}%")

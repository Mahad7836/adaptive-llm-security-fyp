# Adaptive LLM Security FYP

Final-year project for evaluating prompt-injection attacks and deterministic defenses for tool-using LLM agents. This README is the central onboarding and implementation-status guide; detailed historical integration notes remain in [CryptoFirewall_Integration_Handover.md](./CryptoFirewall_Integration_Handover.md) and [handover/](./handover/), and baseline measurements are in [docs/baseline_results.md](./docs/baseline_results.md). The current SwarmSec status, change log and open problems are in [docs/swarmsec/swarmsec_status_and_changes.md](./docs/swarmsec/swarmsec_status_and_changes.md).

## Project status at a glance

| Area | Implemented | Current boundary |
|---|---|---|
| AgentDojo | `workspace` suite (`v1.2.2`), OpenAI-compatible/Groq target configuration, registered injection attacks, `runtime_class` hook for the defended runtime, benchmark and analysis scripts, per-turn scoring for multi-turn sessions | Only the `workspace` suite and selected task IDs are used; reproducible result manifests are still needed. Multi-turn scoring relies on AgentDojo private helpers. |
| CryptoFirewall | HMAC taint primitives, task-scoped reference monitor with argument constraints, AgentDojo runtime interception, initial source tainting, and information-flow checks | Capabilities cover five workspace user tasks, and other tasks raise `KeyError` instead of being blocked. Constraints do not reject extra arguments. In the current task set, no authorized tool is covered by the information-flow policy, so live blocks come from the tool allowlist only. |
| SwarmSec | LangGraph adaptive audit loop with a shared Blackboard (`AuditState`), a coordinator, four tester agents, an evaluator that turns CryptoFirewall outcomes into feedback, and three routing modes: `fixed`, `adaptive` and `bandit` (UCB1). Configurable retry ceiling (default 12). Persistent multi-turn runner for benign sessions. | Testers share one payload slot, so they are not independent (P1), and the UCB1 exploration weight is too high for sparse rewards (P2); routing therefore behaves close to round-robin in live runs. The escalation tester simulates dialogue in one payload. Attacker and target use the same model. See [the SwarmSec status doc](./docs/swarmsec/swarmsec_status_and_changes.md). |
| End-to-end | `run_adaptive_audit.py` and `run_multi_scenario_audit.py` run the SwarmSec loop through AgentDojo's `run_task_with_pipeline` with the CryptoFirewall runtime; outcomes are classified (blocked / ignored / tool error / objective achieved) and fed back to the coordinator. `benchmark_swarmsec_attacked.py` still runs the static 15-case benchmark. | The sweep writes a JSON report with per-agent statistics, but the full Blackboard is not persisted. Success is AgentDojo's task oracle and is not causally tied to a specific tool call. The checked-in `scripts/benchmarks/benchmark_sweep_results.json` predates the evaluator fix and overstates the defense rate. |

This checkout contains the initial working pieces, not the finished adaptive co-evaluation system. The model endpoint is external; AgentDojo's enterprise tools and data are simulated locally.

## Architecture

The current attacked execution path is:

```text
AgentDojo user task + injection task
  -> IndirectPromptInjectionAgent.generate(...)
  -> AgentDojo registered attack ("important_instructions")
  -> injection-vector mapping
  -> AgentDojo TaskSuite.run_task_with_pipeline(...)
       -> configured target AgentPipeline
       -> task-bound CryptoFirewallRuntime.run_function(...)
            -> task capability / argument authorization
            -> information-flow authorization where configured
            -> AgentDojo tool executes only after checks pass
  -> AgentDojo returns (utility, injection_success)
  -> benchmark prints per-case and aggregate results
```

The SwarmSec adaptive audit loop wraps the same execution path in a LangGraph cycle:

```text
coordinator (fixed | adaptive | bandit)
  -> one of four tester agents writes the next probe to the Blackboard
  -> execute_agentdojo_pipeline: AgentDojo run with the CryptoFirewall runtime
       -> outcome recorded as a ProbeAttempt in Blackboard.audit_history
  -> evaluator: one feedback heuristic (sliding window of 3)
  -> stop on objective achieved or when max_retries is reached, else back to coordinator
```

The attacker does not replace AgentDojo or invoke a separate mock environment. The registered AgentDojo attack creates a mapping from injection-vector IDs to injected text; `TaskSuite.run_task_with_pipeline` loads that injection into the benchmark environment and executes the target pipeline. The target model is configured through the existing OpenAI-compatible provider.

### AgentDojo and SwarmSec

- Benchmark version used by the scripts: `v1.2.2`; the installed package in the current development environment is `0.1.35`, pinned to commit `089ed468` in `requirements.txt`.
- The defended runtime is passed to AgentDojo through `TaskSuite.run_task_with_pipeline(..., runtime_class=...)`. AgentDojo's own pipeline defenses (`defense=`) are not used; all defense comes from CryptoFirewall.
- The adaptive audit runner reuses `load_attack("important_instructions", ...)` only to find the injection-vector slots for a task pair, then fills those slots with the current SwarmSec probe.
- The live runner retries Groq rate-limit errors (HTTP 429) up to 5 times with a linear back-off (12 s, 24 s, …) before failing the attempt.
- [`multiturn.py`](./src/swarmsec/multiturn.py) scores each turn with AgentDojo's private helpers `TaskSuite._check_task_result`, `model_output_from_messages` and `functions_stack_trace_from_messages`. These may change between AgentDojo versions, which is one more reason to keep the pinned commit.
- Suite: `workspace`.
- The target provider is `OPENAI_COMPATIBLE`, configured to use Groq's OpenAI-compatible endpoint.
- [`IndirectPromptInjectionAgent`](./src/swarmsec/agents/indirect_prompt_injection.py) is limited to canonical tasks in the `workspace` suite. It calls AgentDojo's `load_attack("important_instructions", suite, target_pipeline)` and returns the injection mapping expected by the suite runner.
- [`SwarmSecAttacker`](./src/swarmsec/agents/base.py) is the extension interface for future attacker types.
- The first attacker reuses AgentDojo's attack-generation logic and the target pipeline; there is no separate attacker model or new model dependency.
- [`benchmark_swarmsec_attacked.py`](./scripts/integration/benchmark_swarmsec_attacked.py) runs five user tasks against three injection tasks (15 cases), through the existing AgentDojo runner and task-bound CryptoFirewall runtime.
- The script currently prints utility, AgentDojo injection success, and aggregate utility/Targeted ASR. It does not write per-case JSON/JSONL files or return feedback to the attacker.

### SwarmSec adaptive audit

- **Blackboard:** [`blackboard.py`](./src/swarmsec/state/blackboard.py) defines `AuditState` (target and injection task, `audit_history` of `ProbeAttempt` records, `active_heuristics`, retry count, per-run `max_retries`, selected agent).
- **Testers:** indirect injection, direct bypass, multi-turn escalation (simulated dialogue) and format manipulation, under [`src/swarmsec/agents/`](./src/swarmsec/agents/). Each falls back to a deterministic probe when the generator model refuses.
- **Evaluator:** [`evaluator.py`](./src/swarmsec/agents/evaluator.py) distinguishes a CryptoFirewall block from a probe the target ignored, skips ordinary tool errors, and keeps the last three heuristics.
- **Routing modes** in [`coordinator.py`](./src/swarmsec/agents/coordinator.py):

| Mode | Decision rule | Uses |
|---|---|---|
| `fixed` | By attempt number: indirect, direct, escalation, then format for every later attempt (it does not cycle) | Control baseline |
| `adaptive` | Hand-written rule on the last attempt's outcome | Reactive baseline |
| `bandit` | UCB1 over per-agent rewards from the whole history: success = 1.0, CryptoFirewall block = 0.5, otherwise 0. Each agent is tried once first. | Learning router |

- **Retry ceiling:** the attempt budget for one scenario, shared by all agents. The default is 12 (previously 4, which left no attempts after each agent had been tried once). Set it with `--max-retries` or `SWARMSEC_MAX_RETRIES`.
- **Multi-turn:** [`multiturn.py`](./src/swarmsec/multiturn.py) runs persistent conversations with per-turn AgentDojo scoring; it currently sends benign follow-ups only and is not part of the attack graph. The method is described in [docs/security/multiturn_evaluation.md](./docs/security/multiturn_evaluation.md).

AgentDojo's `utility` result reports legitimate-task success. Its `security` result reports whether the injection task's goal succeeded; this project calls that measure **Targeted ASR**. The result is the benchmark's task oracle, not a structured record of each CryptoFirewall decision.

### CryptoFirewall

CryptoFirewall is implemented as both reusable primitives and an AgentDojo runtime layer:

- **Action authorization:** [`capabilities.py`](./src/cryptofirewall/core/capabilities.py) defines allowed tools for `user_task_0` through `user_task_4`. Tasks 0–3 may only use read-only calendar tools. Task 4 may also call `create_calendar_event`, with title, times, description and participants fixed to the authorized values. [`reference_monitor.py`](./src/cryptofirewall/core/reference_monitor.py) raises `UnauthorizedActionError` for disallowed tools and for constrained arguments that do not match.
  - *Limitations:* an unknown task raises `KeyError` from `get_task_capability`, which escapes the runtime and aborts the run rather than being recorded as a block. Only the listed arguments are checked, so an extra argument such as `location` on `create_calendar_event` is accepted.
- **Runtime interception:** [`agentdojo_runtime.py`](./src/cryptofirewall/integrations/agentdojo_runtime.py) subclasses AgentDojo's `FunctionsRuntime`. Each call is checked in order:
  1. action authorization;
  2. information-flow authorization, for tools listed in `ALLOWLIST_POLICY`;
  3. the real tool runs;
  4. results from source tools are registered as tainted.

  A block is returned to the agent as a tool error string beginning `UnauthorizedActionError:` or `UnauthorizedFlowError:`. SwarmSec uses that prefix to classify outcomes.
- **Taint/provenance:** [`crypto_tracker.py`](./src/cryptofirewall/core/crypto_tracker.py) provides HMAC-SHA256-protected `TaintedString` values with integrity, 30-second TTL, anti-replay consumption, and a 500,000-byte payload limit. [`taint_registry.py`](./src/cryptofirewall/core/taint_registry.py) keeps trusted sidecar provenance without changing the normal AgentDojo tool result.
- **Initial runtime source labels:** `get_current_day` is labeled `PUBLIC`; `search_calendar_events` and `get_day_calendar_events` are labeled `INTERNAL`.
- **Information-flow control:** [`flow_monitor.py`](./src/cryptofirewall/core/flow_monitor.py) matches outbound values against the sidecar registry and checks the destination policy in [`egress.py`](./src/cryptofirewall/core/egress.py). Current matching normalizes Unicode NFKC, case, and whitespace, then looks for normalized substrings.
  - *Coverage gap:* the policy lists `send_email`, `execute_bank_transfer`, `upload_to_nadra_cloud`, `write_audit_log` and `update_customer_record`. None of these is authorized for `user_task_0`–`4`, so in current AgentDojo runs every outbound call is stopped by action authorization first. The information-flow layer has unit-test coverage but has not yet blocked anything in a live run.
  - *TTL interaction:* the flow check calls `verify_integrity()` with the default 30-second TTL. Tainted data older than 30 seconds will be rejected as an integrity failure once a task allows an outbound tool, even for legitimate flows.
- **Egress decorator and anti-replay:** `egress_monitor` in [`egress.py`](./src/cryptofirewall/core/egress.py) validates and consumes `TaintedString` arguments (one-time use). It is covered by unit tests but is not used in the AgentDojo runtime, which relies on the sidecar registry.
- **Mediator:** [`mediator.py`](./src/cryptofirewall/core/mediator.py) provides recursive redaction for `TaintedString` values before returning state to a planner; the future privileged/quarantined multi-model architecture is not integrated.

The verified and unverified security properties are tracked in [docs/security/threat_model_baseline.md](./docs/security/threat_model_baseline.md).

The AgentDojo runtime currently prints tool arguments and allow/block messages to the console. It does not expose a structured audit-event API. Do not treat console output as a stable result format or store it without considering that arguments may contain sensitive benchmark data.

## Recorded results and validation

These are pilot/handover results, not final research results. The source documents contain different unprotected attacked-run measurements; preserve them as separate recorded runs and reconcile their exact run metadata before making direct comparisons.

| Recorded run | Cases | Utility | Targeted ASR / notes | Source |
|---|---:|---:|---|---|
| No-attack pilot | 5 | 5/5 (100%) | — | [`docs/baseline_results.md`](./docs/baseline_results.md) |
| Static `important_instructions`, no defense | 15 (5 user × 3 injection) | 6/15 (40%) | 12/15 (80%); injection tasks independently solvable 3/3; 0 errors | [`docs/baseline_results.md`](./docs/baseline_results.md) |
| Separate unprotected control reported by the integration handover | 15 | 46.67% | 73.33% | [`CryptoFirewall_Integration_Handover.md`](./CryptoFirewall_Integration_Handover.md) |
| CryptoFirewall defended attacked run reported by the handover | 15 | 15/15 (100%) | 0/15; handover reports 12 malicious attempts blocked and 3 not attempted | [`CryptoFirewall_Integration_Handover.md`](./CryptoFirewall_Integration_Handover.md) |
| CryptoFirewall benign run reported by the handover | 5 | 5/5 (100%) | — | [`CryptoFirewall_Integration_Handover.md`](./CryptoFirewall_Integration_Handover.md) |
| SwarmSec bandit pilot (`user_task_0` + `injection_task_0`, 12 attempts) | 12 attempts | — | 0/12 objective achieved; 1 attempt blocked by CryptoFirewall, 11 ignored by the target; 492 s, no rate-limit errors. Showed problems P1 and P2. | [`docs/swarmsec/swarmsec_status_and_changes.md`](./docs/swarmsec/swarmsec_status_and_changes.md) |
| Current local pytest suite | 62 tests | 62 passed | CryptoFirewall primitives, SwarmSec adapter, adaptive audit graph and routing (including bandit), audit attribution, multi-turn runner; all offline | `tests/` |

Groq rate limits (HTTP 429) were observed in larger pilot runs; retries allowed the recorded baseline cases to finish. Live benchmarks call the configured model endpoint and can incur latency, rate limits, or provider costs. The current SwarmSec wrapper has been validated for local attack generation, but its 15-case live target-model benchmark is not implied by the unit-test result.

## Setup

### Requirements

- Windows, Git, and Python.
- `requirements.txt` pins AgentDojo to an exact Git commit. `requirements-lock.txt` records the known package versions.
- The existing README previously named Python 3.12.4; the current development environment and 11-test run use Python 3.13.9. Keep the Python and dependency versions fixed when reproducing or comparing benchmark results.
- `pytest` is used by the tests but is not declared in the current requirements files; install it separately for development.

### Install

From a Windows CMD prompt:

```cmd
git clone https://github.com/Mahad7836/adaptive-llm-security-fyp.git
cd adaptive-llm-security-fyp
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements-lock.txt
python -m pip install pytest
python -m pip check
```

`requirements.txt` pins only AgentDojo. The SwarmSec audit loop also needs `langgraph`, `openai`, `pydantic` and `python-dotenv`, which are currently pinned only in `requirements-lock.txt` (`langgraph==1.2.11`, `openai==3.0.0`, `pydantic==2.13.4`, `python-dotenv==1.2.2`). Install from the lock file unless you are deliberately updating dependencies.

### Configure `.env`

Create `.env` only if it does not already exist:

```cmd
if not exist .env copy .env.example .env
```

Set the following locally:

```env
GROQ_API_KEY=your_groq_api_key
OPENAI_COMPATIBLE_BASE_URL=https://api.groq.com/openai/v1
OPENAI_COMPATIBLE_API_KEY=your_groq_api_key
GROQ_MODEL=openai/gpt-oss-120b
CRYPTOFIREWALL_SECRET_KEY=your_locally_generated_secret
# Optional: SwarmSec attempts per scenario (default 12)
SWARMSEC_MAX_RETRIES=12
```

`GROQ_API_KEY` is used by the setup checks. AgentDojo's OpenAI-compatible model integration reads the base URL and API key; benchmark scripts use `GROQ_MODEL` or default to `openai/gpt-oss-120b`. `CRYPTOFIREWALL_SECRET_KEY` is required when the taint tracker creates HMAC-protected values; without it, defended runs fail as soon as a calendar tool returns data. It is listed in `.env.example` with a placeholder value. Generate a strong value locally (for example with Python's `secrets` module) and never commit or share it. The `.env` file is ignored by Git.

## Running and testing

The project uses a `src/` layout and does not currently install the local packages as an editable distribution. In Windows CMD, set the source path for scripts that import `cryptofirewall` or `swarmsec`:

```cmd
set PYTHONPATH=src
```

Run the local tests:

```cmd
python -m pytest -q
```

The current tests cover CryptoFirewall cryptographic/egress/mediator primitives, the SwarmSec AgentDojo adapter, the adaptive audit graph (routing modes, bandit scoring, retry ceiling, outcome classification and attribution) and the multi-turn runner. They run offline with stubbed model calls; live benchmark behaviour is not covered by the test suite.

### Configuration and provider checks

```cmd
python scripts\setup\check_groq.py
python scripts\setup\check_groq_tools.py
python -m agentdojo.scripts.benchmark --help
```

The first two commands make live Groq API requests. AgentDojo's command help should include the `OPENAI_COMPATIBLE` model provider.

### CryptoFirewall checks and benchmarks

```cmd
python scripts\integration\test_reference_monitor.py
python scripts\integration\smoke_cryptofirewall_runtime.py
python scripts\integration\smoke_cryptofirewall_attack.py
python scripts\integration\benchmark_cryptofirewall_benign.py
python scripts\integration\benchmark_cryptofirewall_attacked.py
```

`test_reference_monitor.py` exercises deterministic policy decisions locally. The smoke and benchmark scripts use the configured target model through AgentDojo and may make live provider calls. The benchmark scripts cover five benign user tasks and, for attacked runs, five user tasks × three injection tasks.

### SwarmSec + AgentDojo + CryptoFirewall

```cmd
python scripts\integration\benchmark_swarmsec_attacked.py
```

This runs the 15 selected task/injection pairs through the real AgentDojo suite runner with the configured target model and the existing task-bound CryptoFirewall runtime. It prints per-case utility/security booleans and aggregate utility/Targeted ASR; it is the static (non-adaptive) baseline.

### SwarmSec adaptive audit

```cmd
python scripts\integration\run_adaptive_audit.py --routing-mode bandit --max-retries 12
python scripts\benchmarks\run_multi_scenario_audit.py --routing-mode bandit --max-retries 12 --output runs\swarmsec_comparison\sweep_bandit.json
```

`--routing-mode` accepts `fixed`, `adaptive` or `bandit`. The sweep also accepts `--tasks`, `--injection-task` and `--output`, and writes routing mode, retry ceiling and per-agent statistics into its JSON report. Each scenario takes roughly 8 minutes at 12 attempts and makes live model calls. `run_adaptive_audit.py --execution-mode benign-multi-turn` runs the benign multi-turn session instead.

### Analyze AgentDojo CLI output

The analysis scripts consume a directory of AgentDojo JSON result files. Replace `RUN_DIRECTORY` with a real run directory:

```cmd
python scripts\analysis\summarize_agentdojo_run.py RUN_DIRECTORY
python scripts\analysis\summarize_by_injection.py RUN_DIRECTORY
```

These scripts summarize utility and injection success. They do not consume the console-only results printed by the custom integration loops.

## Known gaps and next development steps

### AgentDojo and evaluation

1. Preserve a reproducible manifest for every run: benchmark version, suite, model/provider, task matrix, attack, defense, and run artifacts.
2. Reconcile the different unprotected ASR/utility values in the baseline and handover records before comparing them.
3. Rerun benign and attacked controls with the same task matrix after runtime changes; expand beyond the five user tasks and three injection tasks.
4. Account for provider rate limits and record errors separately from task failures.
5. Replace or wrap the private AgentDojo helpers used for multi-turn scoring, or add a test that fails loudly if they change.
6. Add the direct dependencies (`langgraph`, `openai`, `pydantic`, `python-dotenv`, and `pytest` for development) to `requirements.txt`.

### CryptoFirewall

1. Make unknown tasks fail closed: convert the `KeyError` from `get_task_capability` into a recorded block instead of an aborted run.
2. Reject arguments that are not listed in a tool's constraints (e.g. `location` on `create_calendar_event`), or explicitly allow them per tool.
3. Add at least one task whose capability allows an outbound tool covered by `ALLOWLIST_POLICY`, so the information-flow layer is exercised in live runs; make the taint TTL configurable before doing so.
4. Expand task capabilities beyond the manually defined `user_task_0`–`user_task_4` calendar policies and add broader AgentDojo tool coverage.
5. Expand taint-source and label coverage beyond the current day/calendar sources.
6. Improve information-flow detection beyond normalized substring matching; semantic paraphrase and heavily transformed data are not currently detected.
7. Add automated tests for runtime interception, provenance propagation, allowed/blocked IFC flows, retries, errors, and tampering.
8. Continue toward the planned privileged/quarantined LLM design only after its trust boundaries and evaluation criteria are defined.

### SwarmSec and end-to-end feedback

Done: outcome classification, the feedback loop, the shared Blackboard, four tester agents, and fixed/adaptive/bandit routing with a configurable retry ceiling. Open items, in order (details in the [SwarmSec status doc](./docs/swarmsec/swarmsec_status_and_changes.md)):

1. Resolve P1 (testers share one payload slot) and P2 (UCB1 exploration weight too high for sparse rewards) before reporting any routing-mode comparison.
2. Re-run the fixed / adaptive / bandit sweep with the same tasks and retry ceiling, and replace the stale `benchmark_sweep_results.json`.
3. Done: the full Blackboard is persisted per scenario under the ignored `runs/` directory. Still open: structured, redacted CryptoFirewall decision events instead of console logs, and partial persistence on a mid-run crash.
4. Done: a reported success is now verified against the injection task's ground-truth tool and marked `UNVERIFIED` if that tool did not execute; the sweep reports a separate verified defense rate.
5. Use a separate attacker model, and move duplicated model-client code into one helper.
6. Consider Thompson sampling as a fourth routing mode; extend coverage to more injection tasks once CryptoFirewall has more task manifests.

## Repository map

```text
docs/
  baseline_results.md
  security/       threat model baseline and multi-turn evaluation method
  swarmsec/       SwarmSec status, change log and next steps
handover/         CryptoFirewall and multi-agent SwarmSec handover notes
scripts/
  analysis/       AgentDojo result summarizers
  benchmarks/     multi-scenario SwarmSec sweep and its last report
  integration/    CryptoFirewall smoke/benchmark runners, static SwarmSec benchmark, adaptive audit runner
  setup/          Groq connectivity and tool-call checks
src/
  common/         shared audit logger
  cryptofirewall/
    core/         taint, provenance, action, flow, and egress policies
    integrations/ AgentDojo FunctionsRuntime interception
  swarmsec/
    agents/       coordinator, four tester agents, evaluator, refusal helpers, AgentDojo adapter
    state/        Blackboard (AuditState, ProbeAttempt)
    multiturn.py  persistent multi-turn session runner
tests/
  test_adaptive_audit_phase.py
  test_audit_attribution.py
  test_crypto_primitives.py
  test_multiturn.py
  test_swarmsec_agentdojo_attacker.py
```

Additional integration history is documented in [CryptoFirewall_Integration_Handover.md](./CryptoFirewall_Integration_Handover.md). `runs/` is Git-ignored; do not treat untracked run artifacts as durable project evidence unless they are deliberately archived with their metadata.

## Team workflow and safety notes

- Use feature branches and review changes before merging to `main`.
- Never commit `.env`, API keys, CryptoFirewall secrets, virtual environments, or raw benchmark outputs.
- AgentDojo's enterprise tools are simulated, but model requests go to the configured provider.
- Do not compare results across different AgentDojo versions, models, attacks, task matrices, or defense settings without recording those differences.
- Treat all current measurements as setup-validation pilots until the evaluation matrix and run artifacts are reproducible.

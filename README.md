# Adaptive LLM Security FYP

Final-year project for evaluating prompt-injection attacks and deterministic defenses for tool-using LLM agents. This README is the central onboarding and implementation-status guide; detailed historical integration notes remain in [CryptoFirewall_Integration_Handover.md](./CryptoFirewall_Integration_Handover.md), and baseline measurements are in [docs/baseline_results.md](./docs/baseline_results.md).

## Project status at a glance

| Area | Implemented | Current boundary |
|---|---|---|
| AgentDojo | `workspace` suite setup, OpenAI-compatible/Groq target configuration, registered injection attacks, benchmark and analysis scripts | The custom benchmark scripts use selected task IDs; broadened suites and reproducible result manifests are still needed. |
| CryptoFirewall | HMAC taint primitives, task-scoped reference monitor, AgentDojo runtime interception, initial source tainting, and information-flow checks | Capabilities cover five workspace user tasks; source labels and automated integration coverage are limited. |
| SwarmSec | Common attacker protocol and a first indirect-injection adapter using AgentDojo's `important_instructions` attack | This is a fixed benchmark attack, not an adaptive attacker. No feedback loop, Blackboard, or attack selection/update cycle exists yet. |
| End-to-end | `benchmark_swarmsec_attacked.py` generates injections and submits them to AgentDojo's real `run_task_with_pipeline` with the CryptoFirewall runtime | Per-case output is currently printed as utility and AgentDojo security booleans; structured firewall audit events and feedback are not yet captured or persisted. |

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

The attacker does not replace AgentDojo or invoke a separate mock environment. The registered AgentDojo attack creates a mapping from injection-vector IDs to injected text; `TaskSuite.run_task_with_pipeline` loads that injection into the benchmark environment and executes the target pipeline. The target model is configured through the existing OpenAI-compatible provider.

### AgentDojo and SwarmSec

- Benchmark version used by the scripts: `v1.2.2`; the installed package in the current development environment is `0.1.35`.
- Suite: `workspace`.
- The target provider is `OPENAI_COMPATIBLE`, configured to use Groq's OpenAI-compatible endpoint.
- [`IndirectPromptInjectionAgent`](./src/swarmsec/agents/indirect_prompt_injection.py) is limited to canonical tasks in the `workspace` suite. It calls AgentDojo's `load_attack("important_instructions", suite, target_pipeline)` and returns the injection mapping expected by the suite runner.
- [`SwarmSecAttacker`](./src/swarmsec/agents/base.py) is the extension interface for future attacker types.
- The first attacker reuses AgentDojo's attack-generation logic and the target pipeline; there is no separate attacker model or new model dependency.
- [`benchmark_swarmsec_attacked.py`](./scripts/integration/benchmark_swarmsec_attacked.py) runs five user tasks against three injection tasks (15 cases), through the existing AgentDojo runner and task-bound CryptoFirewall runtime.
- The script currently prints utility, AgentDojo injection success, and aggregate utility/Targeted ASR. It does not write per-case JSON/JSONL files or return feedback to the attacker.

AgentDojo's `utility` result reports legitimate-task success. Its `security` result reports whether the injection task's goal succeeded; this project calls that measure **Targeted ASR**. The result is the benchmark's task oracle, not a structured record of each CryptoFirewall decision.

### CryptoFirewall

CryptoFirewall is implemented as both reusable primitives and an AgentDojo runtime layer:

- **Action authorization:** [`capabilities.py`](./src/cryptofirewall/core/capabilities.py) defines allowed tools for `user_task_0` through `user_task_4`; [`reference_monitor.py`](./src/cryptofirewall/core/reference_monitor.py) fails closed for unknown tasks, disallowed tools, and constrained arguments that do not match the authorized values.
- **Runtime interception:** [`agentdojo_runtime.py`](./src/cryptofirewall/integrations/agentdojo_runtime.py) subclasses AgentDojo's `FunctionsRuntime` and checks calls before forwarding them to the benchmark tool.
- **Taint/provenance:** [`crypto_tracker.py`](./src/cryptofirewall/core/crypto_tracker.py) provides HMAC-SHA256-protected `TaintedString` values with integrity, 30-second TTL, anti-replay consumption, and a 500,000-byte payload limit. [`taint_registry.py`](./src/cryptofirewall/core/taint_registry.py) keeps trusted sidecar provenance without changing the normal AgentDojo tool result.
- **Initial runtime source labels:** `get_current_day` is labeled `PUBLIC`; `search_calendar_events` and `get_day_calendar_events` are labeled `INTERNAL`.
- **Information-flow control:** [`flow_monitor.py`](./src/cryptofirewall/core/flow_monitor.py) matches outbound values against the sidecar registry and checks the destination policy in [`egress.py`](./src/cryptofirewall/core/egress.py). Current matching normalizes Unicode NFKC, case, and whitespace, then looks for normalized substrings.
- **Mediator:** [`mediator.py`](./src/cryptofirewall/core/mediator.py) provides recursive redaction for `TaintedString` values before returning state to a planner; the future privileged/quarantined multi-model architecture is not integrated.

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
| Current local pytest suite | 11 tests | 11 passed | 9 CryptoFirewall primitive tests + 2 SwarmSec adapter tests | `tests/` |

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

To install only the project's high-level dependency pin instead of the full lock, use `python -m pip install -r requirements.txt`.

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
```

`GROQ_API_KEY` is used by the setup checks. AgentDojo's OpenAI-compatible model integration reads the base URL and API key; benchmark scripts use `GROQ_MODEL` or default to `openai/gpt-oss-120b`. `CRYPTOFIREWALL_SECRET_KEY` is required when the taint tracker creates HMAC-protected values; it is not currently listed in `.env.example`. Generate a strong value locally (for example with Python's `secrets` module) and never commit or share it. The `.env` file is ignored by Git.

## Running and testing

The project uses a `src/` layout and does not currently install the local packages as an editable distribution. In Windows CMD, set the source path for scripts that import `cryptofirewall` or `swarmsec`:

```cmd
set PYTHONPATH=src
```

Run the local tests:

```cmd
python -m pytest -q
```

The current tests cover CryptoFirewall cryptographic/egress/mediator primitives and the SwarmSec AgentDojo adapter's registry call and suite/task scope. The AgentDojo runtime and benchmark scripts are not yet covered by a comprehensive automated integration suite.

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

This runs the 15 selected task/injection pairs through the real AgentDojo suite runner with the configured target model and the existing task-bound CryptoFirewall runtime. It currently prints per-case utility/security booleans and aggregate utility/Targeted ASR; it does not persist run JSON or feed structured outcomes back to the attacker.

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

### CryptoFirewall

1. Expand task capabilities beyond the manually defined `user_task_0`–`user_task_4` calendar policies and add broader AgentDojo tool coverage.
2. Expand taint-source and label coverage beyond the current day/calendar sources.
3. Improve information-flow detection beyond normalized substring matching; semantic paraphrase and heavily transformed data are not currently detected.
4. Add automated tests for runtime interception, provenance propagation, allowed/blocked IFC flows, retries, errors, and tampering.
5. Continue toward the planned privileged/quarantined LLM design only after its trust boundaries and evaluation criteria are defined.

### SwarmSec and end-to-end feedback

1. Add structured, redacted CryptoFirewall decision/execution events instead of relying on console logs.
2. Return an outcome object per AgentDojo case that distinguishes an injected action attempt (including blocked attempts) from AgentDojo-confirmed injection success.
3. Pass each outcome back to the attacker/coordinator and persist safe per-case records under the ignored `runs/` directory.
4. Build the adaptive proposal/scoring/selection/update loop and shared Blackboard only after the outcome/feedback contract is tested.
5. Add specialized attacker types and compare static AgentDojo attacks with adaptive SwarmSec attacks under the same benchmark matrix and defense.

## Repository map

```text
docs/
  baseline_results.md
scripts/
  analysis/       AgentDojo result summarizers
  integration/    CryptoFirewall smoke/benchmark and SwarmSec benchmark runners
  setup/          Groq connectivity and tool-call checks
src/
  cryptofirewall/
    core/         taint, provenance, action, flow, and egress policies
    integrations/ AgentDojo FunctionsRuntime interception
  swarmsec/
    agents/       attacker interface and indirect-injection adapter
tests/
  test_crypto_primitives.py
  test_swarmsec_agentdojo_attacker.py
```

Additional integration history is documented in [CryptoFirewall_Integration_Handover.md](./CryptoFirewall_Integration_Handover.md). `runs/` is Git-ignored; do not treat untracked run artifacts as durable project evidence unless they are deliberately archived with their metadata.

## Team workflow and safety notes

- Use feature branches and review changes before merging to `main`.
- Never commit `.env`, API keys, CryptoFirewall secrets, virtual environments, or raw benchmark outputs.
- AgentDojo's enterprise tools are simulated, but model requests go to the configured provider.
- Do not compare results across different AgentDojo versions, models, attacks, task matrices, or defense settings without recording those differences.
- Treat all current measurements as setup-validation pilots until the evaluation matrix and run artifacts are reproducible.

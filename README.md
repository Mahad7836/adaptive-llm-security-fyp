# Adaptive LLM Security FYP

Final Year Project for evaluating adaptive prompt-injection attacks and deterministic defenses for tool-using enterprise LLM agents.

## Project Overview

This project currently uses AgentDojo as the benchmark environment.

AgentDojo provides:
- simulated enterprise-style tasks
- tools such as email, calendar, and cloud-file operations
- legitimate user tasks
- prompt-injection tasks
- utility and attack-success evaluation

Our planned system has two main components:

- **SwarmSec** - adaptive multi-agent red teaming
- **CryptoFirewall** - deterministic backend security enforcement

The current repository contains the verified AgentDojo + Groq baseline environment. SwarmSec and CryptoFirewall implementation is the next development phase.

---

## Current Baseline

### Model
- Provider: Groq
- Model: `openai/gpt-oss-120b`
- AgentDojo suite: `workspace`

### No-Attack Pilot
- 5 legitimate user tasks
- Utility: **5/5 = 100%**

### Static Prompt-Injection Pilot
- Attack: `important_instructions`
- 5 user tasks
- 3 injection tasks
- 15 attacked cases
- Utility under attack: **6/15 = 40%**
- Targeted ASR: **12/15 = 80%**
- Injection tasks independently solvable: **3/3**
- Errors: **0**

These are setup-validation pilot results, not final research results.

---

## Requirements

Recommended environment:

- Windows
- Python 3.12.4
- Git
- Groq API key

AgentDojo is pinned to an exact official Git commit in `requirements.txt`.

The complete known-working Python environment is recorded in `requirements-lock.txt`.

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/Mahad7836/adaptive-llm-security-fyp.git
cd adaptive-llm-security-fyp
```

### 2. Create and activate a virtual environment

Windows CMD:

```cmd
python -m venv .venv
.venv\Scripts\activate
```

Verify:

```cmd
python --version
```

Expected:

```text
Python 3.12.4
```

### 3. Install dependencies

For exact reproduction of the validated environment:

```cmd
python -m pip install -r requirements-lock.txt
```

Check dependency health:

```cmd
python -m pip check
```

Expected:

```text
No broken requirements found.
```

For normal development, `requirements.txt` contains the high-level project dependency pin.

---

## Environment Configuration

Create `.env` only if it does not already exist:

```cmd
if not exist .env copy .env.example .env
```

If `.env` already exists, do not overwrite it. It may contain your active API key.

Open `.env` locally and replace the placeholder values with your own Groq API key.

Required variables:

```env
GROQ_API_KEY=your_groq_api_key_here
OPENAI_COMPATIBLE_BASE_URL=https://api.groq.com/openai/v1
OPENAI_COMPATIBLE_API_KEY=your_groq_api_key_here
GROQ_MODEL=openai/gpt-oss-120b
```

Never commit the real `.env` file.

---

## Verify Groq

Check API connectivity and available models:

```cmd
python scripts\setup\check_groq.py
```

Check structured tool calling:

```cmd
python scripts\setup\check_groq_tools.py
```

A successful tool-calling test should report the model, tool name, and structured arguments.

---

## AgentDojo

Confirm that AgentDojo is installed correctly:

```cmd
python -m agentdojo.scripts.benchmark --help
```

The available model choices should include:

```text
OPENAI_COMPATIBLE
```

Raw benchmark runs are stored under `runs/` and are intentionally ignored by Git.

---

## Result Analysis

`RUN_DIRECTORY` below is a placeholder. Replace it with the path to a real AgentDojo run directory.

Summarize an attacked run:

```cmd
python scripts\analysis\summarize_agentdojo_run.py RUN_DIRECTORY
```

Example:

```cmd
python scripts\analysis\summarize_agentdojo_run.py runs\groq_important_u0_4_i0_2
```

Summarize results by injection task:

```cmd
python scripts\analysis\summarize_by_injection.py RUN_DIRECTORY
```

The analysis scripts use:

- **Utility** - whether the legitimate user task succeeded
- **Targeted ASR** - whether the attacker's injection goal succeeded

---

## Repository Structure

```text
adaptive-llm-security-fyp/
|
|-- docs/
|   `-- baseline_results.md
|
|-- scripts/
|   |-- setup/
|   |   |-- check_groq.py
|   |   `-- check_groq_tools.py
|   |
|   `-- analysis/
|       |-- summarize_agentdojo_run.py
|       `-- summarize_by_injection.py
|
|-- .env.example
|-- .gitignore
|-- README.md
|-- requirements.txt
`-- requirements-lock.txt
```

This structure will expand as SwarmSec and CryptoFirewall are implemented.

---

## Development Roadmap

### Phase 1 - Baseline
- [x] AgentDojo environment
- [x] Groq integration
- [x] structured tool calling
- [x] normal-task pilot
- [x] static prompt-injection pilot
- [x] result-analysis scripts
- [x] clean-clone reproduction

### Phase 2 - SwarmSec
- [ ] define common attacker-agent interface
- [ ] build single adaptive attacker loop
- [ ] add Blackboard/shared memory
- [ ] add specialized attacker agents
- [ ] implement proposal/scoring/selection/update loop

### Phase 3 - CryptoFirewall
- [ ] sensitivity/taint labels
- [ ] backend label propagation
- [ ] HMAC-protected metadata
- [ ] policy enforcement
- [ ] pre-tool-call allow/block gate

### Phase 4 - Integration and Evaluation
- [ ] SwarmSec + CryptoFirewall closed loop
- [ ] static vs adaptive attack comparison
- [ ] baseline defenses vs CryptoFirewall
- [ ] broader AgentDojo evaluation
- [ ] final research analysis

---

## Git Workflow

`main` should contain stable, reviewed code.

Each team member should work on a feature branch, for example:

```text
feature/swarmsec-orchestrator
feature/swarmsec-blackboard
feature/indirect-agent
feature/output-agent
```

Changes should be reviewed before merging into `main`.

---

## Important Notes

- Do not commit API keys.
- Do not commit `.env`.
- Do not commit `.venv`.
- Do not commit raw `runs/`.
- Do not directly compare results produced using different AgentDojo versions, models, attacks, or task matrices.
- Current baseline numbers are pilot/setup-validation results only.

# \# Adaptive LLM Security FYP

# 

# Final Year Project for evaluating adaptive prompt-injection attacks and deterministic defenses for tool-using enterprise LLM agents.

# 

# \## Project Overview

# 

# This project currently uses AgentDojo as the benchmark environment.

# 

# AgentDojo provides:

# \- simulated enterprise-style tasks

# \- tools such as email, calendar, and cloud-file operations

# \- legitimate user tasks

# \- prompt-injection tasks

# \- utility and attack-success evaluation

# 

# Our planned system has two main components:

# 

# \- \*\*SwarmSec\*\* — adaptive multi-agent red teaming

# \- \*\*CryptoFirewall\*\* — deterministic backend security enforcement

# 

# The current repository contains the verified AgentDojo + Groq baseline environment. SwarmSec and CryptoFirewall implementation is the next development phase.

# 

# \---

# 

# \## Current Baseline

# 

# \### Model

# \- Provider: Groq

# \- Model: `openai/gpt-oss-120b`

# \- AgentDojo suite: `workspace`

# 

# \### No-Attack Pilot

# \- 5 legitimate user tasks

# \- Utility: \*\*5/5 = 100%\*\*

# 

# \### Static Prompt-Injection Pilot

# \- Attack: `important\_instructions`

# \- 5 user tasks

# \- 3 injection tasks

# \- 15 attacked cases

# \- Utility under attack: \*\*6/15 = 40%\*\*

# \- Targeted ASR: \*\*12/15 = 80%\*\*

# \- Injection tasks independently solvable: \*\*3/3\*\*

# \- Errors: \*\*0\*\*

# 

# These are setup-validation pilot results, not final research results.

# 

# \---

# 

# \## Requirements

# 

# Recommended environment:

# 

# \- Windows

# \- Python 3.12.4

# \- Git

# \- Groq API key

# 

# AgentDojo is pinned to an exact official Git commit in `requirements.txt`.

# 

# The complete known-working Python environment is recorded in `requirements-lock.txt`.

# 

# \---

# 

# \## Setup

# 

# \### 1. Clone the repository

# 

# ```bash

# git clone https://github.com/Mahad7836/adaptive-llm-security-fyp.git

# cd adaptive-llm-security-fyp


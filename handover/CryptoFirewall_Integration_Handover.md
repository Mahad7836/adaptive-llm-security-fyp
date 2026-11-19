# CryptoFirewall Integration Handover

**Project:** An Adaptive Attack-Defense Co-Evaluation Framework for Enterprise LLM Chatbots  
**Working branch:** `cryptofirewall-agentdojo-integration`  
**Base branch from teammate:** `taint-tracking`  
**Status at handover:** CryptoFirewall approximately **80% complete**

## 1. Where We Started

We fetched the teammate branch:

`taint-tracking`

That branch already contained the first CryptoFirewall core primitives. At that point, CryptoFirewall was roughly **35% complete overall**.

What already existed:

- HMAC-protected `TaintedString`
- taint labels
- TTL / expiry checks
- anti-replay / one-time consumption behavior
- payload size checks
- a basic egress allowlist
- a redaction / mediator helper
- 9 unit tests for the CryptoFirewall primitives

All 9 original tests passed after we reproduced the branch locally.

However, CryptoFirewall was not yet connected to AgentDojo, so it could not actually control real LLM tool calls or track real AgentDojo data flows.

---

## 2. Branching and Safety

We did **not** modify the teammate's original `taint-tracking` branch directly.

We created a separate integration branch:

`cryptofirewall-agentdojo-integration`

This lets us extend and test CryptoFirewall without disturbing the original teammate work.

Important commits made so far:

- `5752196` — Integrate task-scoped CryptoFirewall action enforcement with AgentDojo
- `b25f9b0` — Validate CryptoFirewall action enforcement on AgentDojo benchmark
- `2d1365f` — Integrate HMAC taint tracking and IFC enforcement with AgentDojo

---

## 3. AgentDojo Reproduction

We reproduced the AgentDojo environment using the existing Groq setup and model:

`openai/gpt-oss-120b`

The Groq connection and tool calling were verified successfully.

### Baseline benign result

5 selected AgentDojo tasks:

- **5/5 passed**
- **100% benign utility**

### Baseline attacked result

15 attack combinations were tested:

- 5 user tasks
- 3 injection tasks
- `important_instructions` attack

Baseline result before CryptoFirewall protection:

- **Utility under attack: 46.67%**
- **Targeted attack success rate: 73.33%**

This gave us the control result for comparison.

---

## 4. Action-Control Integration

We added a CryptoFirewall runtime layer around AgentDojo.

The runtime now intercepts tool calls before AgentDojo executes them.

Added:

- task capability definitions
- a deterministic reference monitor
- allowed-tool checks
- argument-level restrictions
- AgentDojo runtime interception

This means the LLM can request an action, but the LLM does **not** decide whether it is authorized.

CryptoFirewall makes the final deterministic decision.

### Examples successfully blocked

- unauthorized `delete_file`
- unauthorized `send_email`
- unauthorized `create_calendar_event`

We also tested a stronger case where `create_calendar_event` was a legitimate tool for the task, but malicious arguments were supplied.

CryptoFirewall blocked the malicious event while allowing the legitimate event.

This proved that the system is not only a simple tool denylist; it can also enforce task-specific argument restrictions.

---

## 5. Full Action-Defense Benchmark

We reran all 15 attacked AgentDojo cases through the protected runtime.

### Result

- **Utility: 15/15 = 100%**
- **Targeted ASR: 0/15 = 0%**
- **Observed benchmark attacks successful: 0**

In 12 cases, CryptoFirewall visibly blocked a malicious tool-call attempt.

In 3 cases, the model did not attempt the injected malicious action, so CryptoFirewall did not need to intervene.

Therefore the accurate interpretation is:

> The defended benchmark had 0/15 successful attacks. CryptoFirewall explicitly blocked 12 malicious tool-call attempts, while 3 injected actions were not attempted by the model.

---

## 6. Benign Utility Preservation

CryptoFirewall was also tested on the 5 benign tasks after action enforcement was added.

Result:

- **5/5 passed**
- **100% benign utility**

One useful case occurred in `user_task_4`.

The model initially attempted a calendar event with an extra participant that was not authorized by the task policy.

CryptoFirewall blocked that first call.

The model retried with only the authorized participant.

CryptoFirewall allowed the corrected call.

The task still passed.

This showed that the firewall can reject an over-broad action while allowing the model to recover and complete the legitimate task.

---

## 7. Taint Tracking and Provenance

We then began connecting the original HMAC taint system to real AgentDojo outputs.

Instead of changing AgentDojo's normal tool outputs, we created a separate trusted sidecar registry.

This registry stores metadata such as:

- value
- security label
- source tool
- location/path inside the tool result
- HMAC-protected taint object

Example provenance:

`result[0].participants[0]`

This allows the LLM to continue receiving normal AgentDojo data while CryptoFirewall independently maintains trusted security metadata.

A real AgentDojo `search_calendar_events` result produced multiple protected taint records and all HMAC integrity checks passed.

---

## 8. Automatic Runtime Tainting

The AgentDojo runtime now automatically adds taint metadata after approved source tools execute.

Current initial labels include:

- `get_current_day` → `PUBLIC`
- `search_calendar_events` → `INTERNAL`
- `get_day_calendar_events` → `INTERNAL`

A real AgentDojo smoke test successfully produced automatic runtime logs such as:

- PUBLIC taint added after `get_current_day`
- INTERNAL taint records added after `search_calendar_events`

The legitimate task still passed.

---

## 9. Information-Flow Control (IFC)

A flow monitor was added to connect stored taint metadata with outbound tool arguments.

The purpose is different from normal action authorization.

### Action authorization asks:

> Is this tool/action allowed for this task?

### IFC asks:

> Is this type of information allowed to flow through this destination?

Both checks are deterministic.

### Verified IFC behavior

`PUBLIC` data sent through `send_email`:

- action authorization: allowed
- IFC: allowed
- tool executed
- environment changed

`INTERNAL` data sent through `send_email`:

- action authorization: allowed
- IFC: blocked
- tool did not execute
- environment remained unchanged

This proves that IFC can independently stop a sensitive-data flow even when the action itself is otherwise allowed.

---

## 10. HMAC Secret

CryptoFirewall requires:

`CRYPTOFIREWALL_SECRET_KEY`

A strong secret was generated locally and stored in `.env`.

`.env` is ignored by Git.

The secret must **never** be committed or shared in the repository.

---

## 11. Transformation / Matching Improvement

The first sidecar matcher used exact substring matching.

We demonstrated a bypass:

Stored INTERNAL value:

`City Convention Center`

Outbound version:

`city convention center`

The original matcher found zero matches.

We then added normalization using:

- Unicode NFKC normalization
- case folding
- whitespace normalization

After the fix, the transformed value was matched and the unauthorized flow was blocked.

Important limitation:

This improves representation-level transformations only.

It does **not** yet solve semantic paraphrasing or heavily transformed sensitive information.

---

## 12. Regression Status

After the integrations, the original teammate CryptoFirewall primitive test suite was rerun.

Result:

**9/9 tests passed**

So the new AgentDojo integration did not break the original CryptoFirewall primitives.

---

## 13. Current Estimated CryptoFirewall Progress

### At initial teammate branch fetch

Approximately **35% complete**

### Current state

Approximately **80% complete**

Major completed areas:

- core HMAC taint primitives
- action capability enforcement
- AgentDojo tool interception
- argument-level restrictions
- reference monitor
- runtime provenance / taint sidecar
- automatic source tainting
- live IFC allow/block behavior
- attack benchmark integration
- benign regression testing

---

## 14. Important Remaining Work

CryptoFirewall is not finished yet.

Main remaining items:

1. Expand taint source coverage beyond the current calendar tools.
2. Improve propagation beyond normalized substring matching.
3. Add stronger provenance and transformation tests.
4. Generalize capability generation instead of manually defining policies for benchmark task IDs.
5. Add more automated tests for the new integration code.
6. Re-run the full defended benchmark after the latest IFC/taint changes.
7. Integrate the future privileged/quarantined LLM architecture.
8. Connect CryptoFirewall with SwarmSec and the final adaptive attack-defense loop.
9. Test failure cases, tampering, retries, and edge conditions more thoroughly.

---

## 15. Current Architecture in Simple Terms

The current flow is roughly:

**User task**  
→ LLM decides what it wants to do  
→ CryptoFirewall checks whether the action is allowed  
→ approved read tool executes  
→ CryptoFirewall records trusted taint/provenance information  
→ LLM sees the normal tool result  
→ LLM requests another action  
→ CryptoFirewall checks task permission  
→ CryptoFirewall checks whether sensitive data is allowed to flow there  
→ tool executes only if both checks pass

The LLM is therefore treated as **untrusted**.

The deterministic CryptoFirewall backend is responsible for the final security decision.

---

## 16. How to Resume Work

Repository worktree:

`E:\Desktop\GIKI\4th Year\adaptive-llm-security-fyp-taint`

Branch:

`cryptofirewall-agentdojo-integration`

Activate the virtual environment and verify:

```cmd
git status
git branch --show-current
python -m pytest tests\test_crypto_primitives.py -v
```

Expected primitive result:

`9 passed`

Useful benign benchmark:

```cmd
python scripts\integration\benchmark_cryptofirewall_benign.py
```

Expected result:

`5/5 = 100%`

Useful attacked benchmark:

```cmd
python scripts\integration\benchmark_cryptofirewall_attacked.py
```

The previously recorded protected result was:

- Utility: 100%
- Targeted ASR: 0%

---

## 17. Recommended Next Step

After resuming, the first priority should be to turn the latest normalization/taint work into proper automated tests, rerun benign and attacked regression tests, and then freeze the current CryptoFirewall milestone.

After that, development effort should begin shifting toward **SwarmSec and the adaptive co-evaluation loop**, because CryptoFirewall is already much further developed than the attacker/adaptation side of the FYP.

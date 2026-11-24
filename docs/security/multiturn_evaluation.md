# Multi-Turn Security Evaluation Methodology

## Architecture
- Persistent conversation history, environment, runtime and additional pipeline state.
- System instructions initialized only once per session.
- Task-scoped CryptoFirewall authorization retained across turns.
- Existing single-turn benchmark remains available.

## Evaluation Metrics
- Per-turn utility follows AgentDojo task criteria.
- Final utility represents the final completed turn.
- Cumulative attack success records whether any completed turn satisfies the injection objective.
- First success turn identifies the earliest positive injection outcome.
- Benign sessions without an injection task use None for attack success.
- Runtime enforcement evidence is recorded separately from benchmark outcomes.

## Verified Results
- Live benign conversation continuity demonstrated across two turns.
- Revised recall experiment achieved utility on both turns without additional tool calls in the second turn.
- Authorization, rejection, environment integrity and recovery verified offline.
- Runtime evidence verified for zero, one and multiple calls per turn.
- Interrupted-session evidence retained in an exception object.
- Actual AgentDojo security negative control passed.
- Full regression suite: 53 passing tests, zero failures.

## Experimental Controls
- Use isolated synthetic environments and fresh runtimes between sessions.
- Preserve identical task criteria when comparing configurations.
- Keep trusted user instructions separate from untrusted environment content.
- Report interrupted sessions separately from completed evaluations.
- Do not infer unauthorized tool execution solely from benchmark success.

## Limitations
- Existing escalation agent generates simulated dialogue rather than persistent adversarial interactions.
- Live adaptive adversarial effectiveness remains unverified.
- Actual benchmark positive control remains outstanding.
- Broader cross-turn information-flow enforcement requires further validation.
- Interrupted-session evidence is not yet durably persisted.
- Runtime records do not independently establish causal attribution.
- Current live benign experiments demonstrate functionality rather than statistical effectiveness.

# CryptoFirewall Threat Model - Verified Baseline

## Scope
AgentDojo v1.2.2 workspace, five user tasks, SwarmSec attack probes, and CryptoFirewall enforcement.

## Trust boundaries
- Trusted: task capability manifests, reference monitor, security key and policy configuration.
- Lower trust: attacker-controlled injection text, tool responses and LLM-generated arguments.
- Protected assets: authorized tool actions, calendar data and security-labeled information.

## Verified findings
1. Tool allowlisting rejects unauthorized calendar creation in isolated tests.
2. Constrained participant changes are rejected.
3. An extra location argument passes authorization for user_task_4.
4. The registered create_calendar_event tool accepts location.
5. Exact INTERNAL data is denied when checked against send_email policy.
6. Reformatted and partial values evade current registry matching.
7. HMAC integrity, TTL and consumed-record checks passed isolated tests.

## Unverified security questions
- Can the location argument produce an unauthorized side effect end-to-end?
- Can transformed sensitive data leave the system through an authorized write path?
- Are all sensitive egress destinations covered by IFC enforcement?
- How do these controls affect legitimate task success?

## Threat model assumptions
Attackers control lower-trust injection content, not trusted policy files or cryptographic keys.

## Next actions
- Add isolated regression tests for verified limitations.
- Validate suspected weaknesses in integrated AgentDojo execution.
- Add synthetic enterprise policies and compare attack success with legitimate utility.

## Evidence limitations
These findings are based on source inspection and isolated local checks. No end-to-end exploit has been demonstrated.

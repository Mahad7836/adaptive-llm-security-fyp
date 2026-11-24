from __future__ import annotations

from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, SystemMessage, InitQuery


def run_trusted_turns(pipeline, runtime, environment, queries, *, on_turn=None):
    """Execute legitimate user turns while preserving conversation state."""
    if not queries:
        raise ValueError('At least one user turn is required')
    elements = pipeline.elements
    if len(elements) < 2 or not isinstance(elements[0], SystemMessage) or not isinstance(elements[1], InitQuery):
        raise ValueError('Unsupported pipeline initialization structure')

    continuation = AgentPipeline(list(elements[1:]))
    messages = []
    extra_args = {}

    for index, query in enumerate(queries):
        if index and (not messages or messages[0]['role'] != 'system' or sum(m['role'] == 'system' for m in messages) != 1):
            raise ValueError('Invalid retained conversation history')
        active_pipeline = pipeline if index == 0 else continuation
        _, runtime, environment, messages, extra_args = active_pipeline.query(query, runtime, environment, messages, extra_args)

        if on_turn is not None:
            on_turn(index + 1, runtime, environment, messages)

    return runtime, environment, messages, extra_args


def evaluate_turn(suite, user_task, injection_task, pre_environment, environment, messages):
    """Evaluate a completed conversation turn using AgentDojo task criteria."""
    from agentdojo.task_suite.task_suite import model_output_from_messages, functions_stack_trace_from_messages

    if not messages or messages[-1]['role'] != 'assistant':
        raise ValueError('Evaluation requires a completed assistant turn')

    output = model_output_from_messages(messages) or []
    trace = functions_stack_trace_from_messages(messages)
    utility = suite._check_task_result(user_task, output, pre_environment, environment, trace)
    attack_success = None
    if injection_task is not None:
        attack_success = suite._check_task_result(injection_task, output, pre_environment, environment, trace)

    return {'utility': bool(utility), 'attack_success': None if attack_success is None else bool(attack_success)}


def run_evaluated_trusted_turns(suite, pipeline, runtime, environment, queries, user_task, injection_task=None):
    pre_environment = environment.model_copy(deep=True)
    outcomes = []

    def record_turn(index, runtime, current_environment, messages):
        outcome = evaluate_turn(suite, user_task, injection_task, pre_environment, current_environment, messages)
        outcomes.append({'turn': index, **outcome})

    runtime, environment, messages, extra_args = run_trusted_turns(pipeline, runtime, environment, queries, on_turn=record_turn)
    first_success = next((o['turn'] for o in outcomes if o['attack_success'] is True), None)

    return {'runtime': runtime, 'environment': environment, 'messages': messages, 'extra_args': extra_args, 'outcomes': outcomes, 'final_utility': outcomes[-1]['utility'], 'cumulative_attack_success': None if injection_task is None else first_success is not None, 'first_success_turn': first_success, 'total_turns': len(outcomes)}

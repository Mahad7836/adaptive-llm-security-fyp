import pytest
from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, SystemMessage, InitQuery
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from swarmsec.multiturn import run_trusted_turns


class MockLLM(BasePipelineElement):
    def query(self, query, runtime, env, messages, extra_args):
        reply = dict(messages[-1], role='assistant', tool_calls=[])
        return query, runtime, env, [*messages, reply], {**extra_args, 'turns': extra_args.get('turns', 0) + 1}


def test_multiturn_conversation_persistence():
    pipeline = AgentPipeline([SystemMessage('Offline test'), InitQuery(), MockLLM()])
    runtime, env = object(), object()
    r, e, messages, extra = run_trusted_turns(pipeline, runtime, env, ['First', 'Second', 'Third'])
    assert [m['role'] for m in messages] == ['system', 'user', 'assistant', 'user', 'assistant', 'user', 'assistant']
    assert r is runtime
    assert e is env
    assert extra['turns'] == 3


def test_multiturn_rejects_empty_queries():
    pipeline = AgentPipeline([SystemMessage('Offline test'), InitQuery(), MockLLM()])
    with pytest.raises(ValueError, match='At least one user turn'):
        run_trusted_turns(pipeline, object(), object(), [])


def test_multiturn_rejects_unsupported_pipeline():
    pipeline = AgentPipeline([InitQuery(), MockLLM()])
    with pytest.raises(ValueError, match='Unsupported pipeline'):
        run_trusted_turns(pipeline, object(), object(), ['First'])


def test_multiturn_security_enforcement(monkeypatch):
    from unittest.mock import patch
    from agentdojo.functions_runtime import FunctionsRuntime
    from cryptofirewall.integrations.agentdojo_runtime import make_cryptofirewall_runtime
    monkeypatch.setenv('CRYPTOFIREWALL_SECRET_KEY', 'offline-regression-test-key')
    runtime = make_cryptofirewall_runtime('user_task_0')([])
    registry = runtime.taint_registry
    class SecurityMockLLM(BasePipelineElement):
        def query(self, query, runtime, env, messages, extra_args):
            if query == 'Second':
                assert runtime.taint_registry.find_matches('2024-05-19')
                _, error = runtime.run_function(env, 'cancel_calendar_event', {})
                assert error.startswith('UnauthorizedActionError:')
            else:
                if query == 'Third':
                    assert runtime.taint_registry.find_matches('2024-05-19')
                result, error = runtime.run_function(env, 'get_current_day', {})
                assert error is None
                assert runtime.taint_registry.find_matches(result)
            return query, runtime, env, [*messages, dict(messages[-1], role='assistant', tool_calls=[])], extra_args
    pipeline = AgentPipeline([SystemMessage('Offline security test'), InitQuery(), SecurityMockLLM()])
    with patch.object(FunctionsRuntime, 'run_function', return_value=('2024-05-19', None)) as backend:
        r, e, messages, extra = run_trusted_turns(pipeline, runtime, object(), ['First', 'Second', 'Third'])
        assert backend.call_count == 2
    assert r is runtime
    assert r.taint_registry is registry
    assert r.task_id == 'user_task_0'


@pytest.mark.parametrize('with_injection', [True, False])
def test_cumulative_evaluation(with_injection):
    from unittest.mock import Mock
    from agentdojo.functions_runtime import EmptyEnv
    from swarmsec.multiturn import run_evaluated_trusted_turns
    pipeline = AgentPipeline([SystemMessage('Offline evaluation'), InitQuery(), MockLLM()])
    suite = Mock()
    suite._check_task_result.side_effect = [False, False, False, True, True, False] if with_injection else [False, False, True]
    user_task = object()
    injection_task = object() if with_injection else None
    result = run_evaluated_trusted_turns(suite, pipeline, object(), EmptyEnv(), ['First', 'Second', 'Third'], user_task, injection_task)
    assert result['total_turns'] == 3
    assert result['final_utility'] is True
    assert result['cumulative_attack_success'] is (True if with_injection else None)
    assert result['first_success_turn'] == (2 if with_injection else None)
    assert [o['utility'] for o in result['outcomes']] == [False, False, True]
    assert [o['attack_success'] for o in result['outcomes']] == ([False, True, False] if with_injection else [None, None, None])
    assert suite._check_task_result.call_count == (6 if with_injection else 3)


def test_benign_multiturn_agentdojo_integration(monkeypatch):
    from scripts.integration.run_adaptive_audit import run_benign_multiturn_session, get_suite, BENCHMARK_VERSION, SUITE_NAME
    from agentdojo.agent_pipeline.basic_elements import text_content_block_from_string
    monkeypatch.setenv('CRYPTOFIREWALL_SECRET_KEY', 'offline-regression-test-key')
    suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)
    user_task = suite.get_user_task_by_id('user_task_0')
    seen_queries = []
    class IntegrationMockLLM(BasePipelineElement):
        def query(self, query, runtime, env, messages, extra_args):
            seen_queries.append(query)
            result, error = runtime.run_function(env, 'get_current_day', {})
            assert error is None, error
            reply = dict(role='assistant', content=[text_content_block_from_string(str(result))], tool_calls=[])
            return query, runtime, env, [*messages, reply], extra_args
    pipeline = AgentPipeline([SystemMessage('Offline integration test'), InitQuery(), IntegrationMockLLM()])
    result = run_benign_multiturn_session(suite, pipeline, user_task, ['Please confirm the date.'])
    assert seen_queries == [user_task.PROMPT, 'Please confirm the date.']
    assert result['total_turns'] == 2
    assert isinstance(result['final_utility'], bool)
    assert result['cumulative_attack_success'] is None
    assert result['runtime'].task_id == user_task.ID
    assert result['intercepted_calls'] == [{'tool': 'get_current_day', 'status': 'EXECUTED'}] * 2


def test_integrated_multiturn_security_boundary(monkeypatch):
    from scripts.integration.run_adaptive_audit import run_benign_multiturn_session, get_suite, BENCHMARK_VERSION, SUITE_NAME
    monkeypatch.setenv('CRYPTOFIREWALL_SECRET_KEY', 'offline-regression-test-key')
    suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)
    user_task = suite.get_user_task_by_id('user_task_0')
    class BoundaryMockLLM(BasePipelineElement):
        def query(self, query, runtime, env, messages, extra_args):
            if query == 'Boundary check':
                before = env.model_copy(deep=True)
                count = len(runtime.taint_registry.records)
                _, error = runtime.run_function(env, 'cancel_calendar_event', {})
                assert error.startswith('UnauthorizedActionError:')
                assert env == before
                assert len(runtime.taint_registry.records) == count
            else:
                _, error = runtime.run_function(env, 'get_current_day', {})
                assert error is None
            return query, runtime, env, [*messages, dict(messages[-1], role='assistant', tool_calls=[])], extra_args
    pipeline = AgentPipeline([SystemMessage('Offline boundary test'), InitQuery(), BoundaryMockLLM()])
    result = run_benign_multiturn_session(suite, pipeline, user_task, ['Boundary check', 'Recovery check'])
    assert result['total_turns'] == 3
    assert result['intercepted_calls'] == [{'tool': 'get_current_day', 'status': 'EXECUTED'}, {'tool': 'cancel_calendar_event', 'status': 'BLOCKED'}, {'tool': 'get_current_day', 'status': 'EXECUTED'}]
    assert result['turn_evidence'] == [{'turn': i, 'calls': [call]} for i, call in enumerate(result['intercepted_calls'], start=1)]
    assert [call for turn in result['turn_evidence'] for call in turn['calls']] == result['intercepted_calls']
    assert result['runtime'].task_id == user_task.ID


def test_multiturn_variable_call_counts(monkeypatch):
    from scripts.integration.run_adaptive_audit import run_benign_multiturn_session, get_suite, BENCHMARK_VERSION, SUITE_NAME
    monkeypatch.setenv('CRYPTOFIREWALL_SECRET_KEY', 'offline-regression-test-key')
    suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)
    user_task = suite.get_user_task_by_id('user_task_0')
    class VariableCallMockLLM(BasePipelineElement):
        def query(self, query, runtime, env, messages, extra_args):
            count = 0 if query == 'No tools' else (1 if query == 'Final turn' else 2)
            for _ in range(count):
                _, error = runtime.run_function(env, 'get_current_day', {})
                assert error is None
            return query, runtime, env, [*messages, dict(messages[-1], role='assistant', tool_calls=[])], extra_args
    pipeline = AgentPipeline([SystemMessage('Offline evidence test'), InitQuery(), VariableCallMockLLM()])
    result = run_benign_multiturn_session(suite, pipeline, user_task, ['No tools', 'Final turn'])
    assert result['total_turns'] == 3
    assert [t['turn'] for t in result['turn_evidence']] == [1, 2, 3]
    assert [len(t['calls']) for t in result['turn_evidence']] == [2, 0, 1]
    assert [c for t in result['turn_evidence'] for c in t['calls']] == result['intercepted_calls']
    assert len(result['intercepted_calls']) == 3


def test_interrupted_multiturn_session(monkeypatch):
    from scripts.integration.run_adaptive_audit import run_benign_multiturn_session, MultiTurnSessionError, get_suite, BENCHMARK_VERSION, SUITE_NAME
    monkeypatch.setenv('CRYPTOFIREWALL_SECRET_KEY', 'offline-regression-test-key')
    suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)
    user_task = suite.get_user_task_by_id('user_task_0')
    class InterruptedMockLLM(BasePipelineElement):
        def query(self, query, runtime, env, messages, extra_args):
            _, error = runtime.run_function(env, 'get_current_day', {})
            assert error is None
            if query == 'Interrupt':
                raise RuntimeError('Simulated pipeline failure')
            return query, runtime, env, [*messages, dict(messages[-1], role='assistant', tool_calls=[])], extra_args
    pipeline = AgentPipeline([SystemMessage('Offline interruption test'), InitQuery(), InterruptedMockLLM()])
    with pytest.raises(MultiTurnSessionError) as caught:
        run_benign_multiturn_session(suite, pipeline, user_task, ['Interrupt'])
    error = caught.value
    assert error.completed_turns == 1
    assert error.completed_evidence == [{'turn': 1, 'calls': [{'tool': 'get_current_day', 'status': 'EXECUTED'}]}]
    assert error.unfinalized_calls == [{'tool': 'get_current_day', 'status': 'EXECUTED'}]
    assert isinstance(error.__cause__, RuntimeError)


def test_actual_agentdojo_security_negative_control(monkeypatch):
    from scripts.integration.run_adaptive_audit import get_suite, BENCHMARK_VERSION, SUITE_NAME
    from cryptofirewall.integrations.agentdojo_runtime import make_cryptofirewall_runtime
    from swarmsec.multiturn import run_evaluated_trusted_turns
    monkeypatch.setenv('CRYPTOFIREWALL_SECRET_KEY', 'offline-regression-test-key')
    suite = get_suite(BENCHMARK_VERSION, SUITE_NAME)
    user_task = suite.get_user_task_by_id('user_task_0')
    injection_task = suite.get_injection_task_by_id('injection_task_0')
    environment = user_task.init_environment(suite.load_and_inject_default_environment({}))
    runtime = make_cryptofirewall_runtime(user_task.ID)(suite.tools)
    pipeline = AgentPipeline([SystemMessage('Offline negative control'), InitQuery(), MockLLM()])
    result = run_evaluated_trusted_turns(suite, pipeline, runtime, environment, [user_task.PROMPT, 'End of control session'], user_task, injection_task)
    assert result['total_turns'] == 2
    assert result['cumulative_attack_success'] is False
    assert result['first_success_turn'] is None
    assert all(o['attack_success'] is False for o in result['outcomes'])

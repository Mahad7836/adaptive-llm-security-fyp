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

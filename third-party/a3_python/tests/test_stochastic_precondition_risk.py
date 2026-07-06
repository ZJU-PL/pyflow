from a3_python.stochastic_risk import risk_interval_for_precondition
from a3_python.semantics.crash_summaries import Precondition, PreconditionType
from a3_python.semantics.interprocedural_bugs import ValueState


def test_not_zero_risk_uses_upper_bound():
    precond = Precondition(param_index=0, condition_type=PreconditionType.NOT_ZERO)
    state = ValueState(may_be_negative=False, has_upper_bound=True, upper_bound=9)
    risk = risk_interval_for_precondition(precond, state)
    assert risk is not None
    assert abs(risk.risk_ub - 0.1) < 1e-6

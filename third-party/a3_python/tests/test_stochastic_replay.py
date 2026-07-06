from a3_python.dse.stochastic_replay import stochastic_replay_find_bug


def test_stochastic_replay_finds_real_div_zero_bug():
    def f():
        d = 0
        return 1 / d

    res = stochastic_replay_find_bug(f.__code__, max_steps=50, verbose=False)
    assert res is not None
    assert res.bug.get("bug_type") == "DIV_ZERO"


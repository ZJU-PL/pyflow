from pyflow.concolic import explore_file

from .helpers import assert_matches_cpython, target_file


def test_explorer_supports_qualified_method_entries(tmp_path):
    target = target_file(
        tmp_path,
        "class Operations:\n"
        "    base = 5\n"
        "\n"
        "    def __init__(self):\n"
        "        self.bias = 2\n"
        "\n"
        "    @staticmethod\n"
        "    def classify(value: int):\n"
        "        return 'positive' if value > 0 else 'other'\n"
        "\n"
        "    @classmethod\n"
        "    def offset(cls, value: int):\n"
        "        return cls.base + value\n"
        "\n"
        "    def shift(self, value: int):\n"
        "        return self.bias + value\n",
    )

    static_result = explore_file(target, entry="Operations.classify", initial_inputs=[0])
    class_result = explore_file(target, entry="Operations.offset", initial_inputs=[3])
    instance_result = explore_file(target, entry="Operations.shift", initial_inputs=[3])

    assert {run.result for run in static_result.runs} == {"positive", "other"}
    assert class_result.runs[0].result == 8
    assert instance_result.runs[0].result == 5
    assert static_result.parameter_names == ("value",)
    assert class_result.parameter_names == ("value",)
    assert instance_result.parameter_names == ("value",)
    assert_matches_cpython(target, static_result)
    assert_matches_cpython(target, class_result)
    assert_matches_cpython(target, instance_result)

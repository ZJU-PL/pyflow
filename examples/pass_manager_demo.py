"""Define, run, and read the result of a custom analysis pass.

Run: python examples/pass_manager_demo.py
"""

from pathlib import Path

from pyflow.api.ifds import load_analysis_session
from pyflow.application.passes.base import AnalysisPass, PassResult
from pyflow.application.passes.manager import PassManager


class ListFunctions(AnalysisPass):
    def __init__(self):
        super().__init__("list_functions", "List functions in the loaded program")

    def run(self, compiler, program):
        names = sorted(
            code.codeName()
            for code in program.liveCode
            if not code.codeName().endswith(".<module>")
        )
        # An analysis returns data without modifying the program.
        return PassResult(changed=False, data=names)


def main():
    path = Path(__file__).resolve().parents[1] / "tests/fixtures/analysis_inputs/ifds_demo.py"
    session = load_analysis_session([path], entry_file=path)
    manager = PassManager()
    manager.register_pass(ListFunctions())
    results = manager.run_passes(session.compiler, session.program, ["list_functions"])
    result = results["list_functions"]
    if not result.success:
        print(f"Pass failed: {result.error}")
        return 2
    print("Loaded functions: " + ", ".join(result.data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

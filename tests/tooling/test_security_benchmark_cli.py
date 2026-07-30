from tools.security_benchmark_runner.cli import build_parser


def test_runner_cli_accepts_configured_engine_names(tmp_path):
    args = build_parser().parse_args(
        [
            "run",
            str(tmp_path / "manifest.json"),
            "-o",
            str(tmp_path),
            "--engine",
            "custom",
        ]
    )

    assert args.engine == ["custom"]

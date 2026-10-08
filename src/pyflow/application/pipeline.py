"""Pipeline definitions executed exclusively by the session pass manager."""


class Pipeline:
    """Defines analysis stages; scheduling and run state belong to the session."""

    def default_pass_names(
        self,
        *,
        include_experimental_inlining: bool = False,
        dump_stats: bool = False,
        dump_reports: bool = False,
    ) -> list[str]:
        passes = [
            "ipa",
            "cpa",
            "methodcall",
            "simplify",
            "ipa_after_simplify",
            "cpa_after_simplify",
            "lifetime_after_simplify",
            "clone",
            "argument_normalization",
        ]
        if dump_stats:
            passes.insert(2, "stats")
        if include_experimental_inlining:
            passes.append("inlining")
        passes.extend(
            [
                "cull_program",
                "ipa_refresh",
                "cpa_path_sensitive",
                "lifetime_refresh",
                "simplify_final",
            ]
        )
        if dump_reports:
            passes.extend(["ipa_refresh", "cpa_path_sensitive", "lifetime_refresh"])
        return passes

    def run(
        self,
        program,
        compiler=None,
        name: str = "main",
        *,
        include_experimental_inlining: bool = False,
    ):
        """Run the default stages and optional reports for this program's session."""
        if compiler is None:
            raise ValueError("Compiler instance required to run the pipeline")
        options = program.session.options
        results = self.run_custom_pipeline(
            compiler,
            program,
            self.default_pass_names(
                include_experimental_inlining=include_experimental_inlining,
                dump_stats=options.dump_stats,
                dump_reports=options.dump_reports,
            ),
        )
        if options.dump_reports:
            from pyflow.analysis.dump import dumpreport

            try:
                dumpreport.evaluate(compiler, program, name)
            except Exception as exc:
                if not options.mask_dump_errors:
                    raise
                compiler.console.output(f"Exception dumping the report: {exc}")
        total_time = results.total_time
        successful = sum(record.success for record in results.records)
        compiler.console.output(
            f"Pass Manager: {successful}/{len(results.records)} passes successful "
            f"in {total_time:.3f}s"
        )
        return results

    def run_custom_pipeline(self, compiler, program, pass_names: list[str]):
        """Run explicit stages using the same scheduler as the default pipeline."""
        manager = program.session.pass_manager
        pipeline = manager.build_pipeline(pass_names)
        results = manager.run_pipeline(compiler, program, pipeline)
        for name, result in results.items():
            if not result.success:
                raise RuntimeError(
                    f"Pass pipeline aborted at '{name}': {result.error or 'unknown pass failure'}"
                )
        return results

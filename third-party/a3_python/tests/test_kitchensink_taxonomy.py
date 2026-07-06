"""
Tests for Kitchensink Bug Taxonomy with Maximum FP/TP Discernment.

These tests verify that:
1. All new bug types have complete strategies
2. Strategies correctly map to SOTA papers
3. Inter/intra-procedural strategies are properly defined
4. FP rates improve with kitchensink
"""

import pytest
from a3_python.barriers.kitchensink_taxonomy import (
    BugCategory,
    SemanticBugType,
    KitchensinkBugStrategy,
    KITCHENSINK_BUG_STRATEGIES,
    FunctionSummary,
    CompositionResult,
    compose_summaries,
    KitchensinkOrchestrator,
    get_strategy_for_bug,
    list_all_bug_types,
    get_fp_reduction_rate,
    get_optimal_papers_for_bug,
)


class TestBugTaxonomy:
    """Test the bug taxonomy structure."""
    
    def test_all_contract_bugs_defined(self):
        """All 5 contract-based bugs should have strategies."""
        contract_bugs = [
            "PRECONDITION_VIOLATION",
            "POSTCONDITION_VIOLATION",
            "INVARIANT_VIOLATION",
            "REPRESENTATION_INVARIANT",
            "LISKOV_VIOLATION",
        ]
        for bug in contract_bugs:
            assert bug in KITCHENSINK_BUG_STRATEGIES, f"Missing {bug}"
            assert KITCHENSINK_BUG_STRATEGIES[bug].category == BugCategory.CONTRACT
    
    def test_all_temporal_bugs_defined(self):
        """All 6 temporal/ordering bugs should have strategies."""
        temporal_bugs = [
            "USE_BEFORE_INIT",
            "USE_AFTER_CLOSE",
            "DOUBLE_CLOSE",
            "MISSING_CLEANUP",
            "ORDER_VIOLATION",
            "CONCURRENT_MODIFICATION",
        ]
        for bug in temporal_bugs:
            assert bug in KITCHENSINK_BUG_STRATEGIES, f"Missing {bug}"
            assert KITCHENSINK_BUG_STRATEGIES[bug].category == BugCategory.TEMPORAL
    
    def test_all_dataflow_bugs_defined(self):
        """All 5 data flow bugs should have strategies."""
        dataflow_bugs = [
            "UNVALIDATED_INPUT",
            "UNCHECKED_RETURN",
            "IGNORED_EXCEPTION",
            "PARTIAL_INIT",
            "STALE_VALUE",
        ]
        for bug in dataflow_bugs:
            assert bug in KITCHENSINK_BUG_STRATEGIES, f"Missing {bug}"
            assert KITCHENSINK_BUG_STRATEGIES[bug].category == BugCategory.DATA_FLOW
    
    def test_all_protocol_bugs_defined(self):
        """All 4 protocol bugs should have strategies."""
        protocol_bugs = [
            "ITERATOR_PROTOCOL",
            "CONTEXT_MANAGER_PROTOCOL",
            "DESCRIPTOR_PROTOCOL",
            "CALLABLE_PROTOCOL",
        ]
        for bug in protocol_bugs:
            assert bug in KITCHENSINK_BUG_STRATEGIES, f"Missing {bug}"
            assert KITCHENSINK_BUG_STRATEGIES[bug].category == BugCategory.PROTOCOL
    
    def test_all_resource_bugs_defined(self):
        """All 4 resource bugs should have strategies."""
        resource_bugs = [
            "MEMORY_EXHAUSTION",
            "CPU_EXHAUSTION",
            "DISK_EXHAUSTION",
            "HANDLE_EXHAUSTION",
        ]
        for bug in resource_bugs:
            assert bug in KITCHENSINK_BUG_STRATEGIES, f"Missing {bug}"
            assert KITCHENSINK_BUG_STRATEGIES[bug].category == BugCategory.RESOURCE
    
    def test_total_new_bug_types(self):
        """Should have 24 new semantic bug types."""
        assert len(KITCHENSINK_BUG_STRATEGIES) == 24


class TestKitchensinkStrategies:
    """Test that strategies are properly defined."""
    
    def test_all_strategies_have_intra_procedural(self):
        """All strategies should have intra-procedural methods."""
        for bug_type, strategy in KITCHENSINK_BUG_STRATEGIES.items():
            assert strategy.intra is not None, f"{bug_type} missing intra"
            assert len(strategy.intra.fp_papers) > 0, f"{bug_type} missing FP papers"
            assert len(strategy.intra.tp_papers) > 0, f"{bug_type} missing TP papers"
            assert strategy.intra.z3_theory, f"{bug_type} missing Z3 theory"
    
    def test_all_strategies_have_inter_procedural(self):
        """All strategies should have inter-procedural methods."""
        for bug_type, strategy in KITCHENSINK_BUG_STRATEGIES.items():
            assert strategy.inter is not None, f"{bug_type} missing inter"
            assert strategy.inter.summary_type, f"{bug_type} missing summary type"
            assert strategy.inter.composition_rule, f"{bug_type} missing composition rule"
            assert len(strategy.inter.papers) > 0, f"{bug_type} missing inter papers"
    
    def test_paper_numbers_valid(self):
        """All paper numbers should be in range [1, 20]."""
        for bug_type, strategy in KITCHENSINK_BUG_STRATEGIES.items():
            all_papers = (
                strategy.intra.fp_papers +
                strategy.intra.tp_papers +
                strategy.inter.papers
            )
            for paper in all_papers:
                assert 1 <= paper <= 20, f"Invalid paper #{paper} in {bug_type}"
    
    def test_kitchensink_improves_fp_rate(self):
        """Kitchensink FP rate should be lower than baseline for all bugs."""
        for bug_type, strategy in KITCHENSINK_BUG_STRATEGIES.items():
            assert strategy.kitchensink_fp_rate < strategy.baseline_fp_rate, \
                f"{bug_type}: kitchensink should reduce FP rate"
    
    def test_significant_fp_reduction(self):
        """Kitchensink should achieve significant FP reduction."""
        total_reduction = 0
        for strategy in KITCHENSINK_BUG_STRATEGIES.values():
            reduction = strategy.baseline_fp_rate - strategy.kitchensink_fp_rate
            total_reduction += reduction
        
        avg_reduction = total_reduction / len(KITCHENSINK_BUG_STRATEGIES)
        assert avg_reduction >= 0.30, f"Average FP reduction should be >= 30%, got {avg_reduction:.0%}"


class TestContractBugs:
    """Test contract-based bug detection strategies."""
    
    def test_precondition_uses_houdini(self):
        """PRECONDITION_VIOLATION should use Houdini for inference."""
        strategy = KITCHENSINK_BUG_STRATEGIES["PRECONDITION_VIOLATION"]
        assert 18 in strategy.intra.fp_papers  # Houdini
        assert "Houdini" in strategy.intra.fp_description
    
    def test_postcondition_uses_ice(self):
        """POSTCONDITION_VIOLATION should use ICE for learning."""
        strategy = KITCHENSINK_BUG_STRATEGIES["POSTCONDITION_VIOLATION"]
        assert 17 in strategy.intra.fp_papers  # ICE
    
    def test_invariant_uses_ic3(self):
        """INVARIANT_VIOLATION should use IC3/PDR for preservation."""
        strategy = KITCHENSINK_BUG_STRATEGIES["INVARIANT_VIOLATION"]
        assert 10 in strategy.intra.fp_papers  # IC3/PDR
    
    def test_liskov_uses_assume_guarantee(self):
        """LISKOV_VIOLATION should use Assume-Guarantee."""
        strategy = KITCHENSINK_BUG_STRATEGIES["LISKOV_VIOLATION"]
        assert 20 in strategy.intra.fp_papers  # Assume-Guarantee
        assert 20 in strategy.inter.papers


class TestTemporalBugs:
    """Test temporal/ordering bug detection strategies."""
    
    def test_use_before_init_tracks_initialization(self):
        """USE_BEFORE_INIT should track initialization state."""
        strategy = KITCHENSINK_BUG_STRATEGIES["USE_BEFORE_INIT"]
        assert "initialized" in strategy.intra.z3_encoding
        assert strategy.semantic_domain == "temporal"
    
    def test_use_after_close_tracks_closed_state(self):
        """USE_AFTER_CLOSE should track closed state."""
        strategy = KITCHENSINK_BUG_STRATEGIES["USE_AFTER_CLOSE"]
        assert "closed" in strategy.intra.z3_encoding
    
    def test_missing_cleanup_uses_ranking(self):
        """MISSING_CLEANUP should use ranking for temporal property."""
        strategy = KITCHENSINK_BUG_STRATEGIES["MISSING_CLEANUP"]
        assert strategy.barrier_type == "ranking"
    
    def test_double_close_uses_polynomial(self):
        """DOUBLE_CLOSE should use polynomial barrier for counting."""
        strategy = KITCHENSINK_BUG_STRATEGIES["DOUBLE_CLOSE"]
        assert strategy.barrier_type == "polynomial"


class TestDataFlowBugs:
    """Test data flow bug detection strategies."""
    
    def test_unvalidated_input_uses_taint(self):
        """UNVALIDATED_INPUT should use taint tracking."""
        strategy = KITCHENSINK_BUG_STRATEGIES["UNVALIDATED_INPUT"]
        assert strategy.inter.summary_type == "taint"
        assert strategy.semantic_domain == "taint"
    
    def test_unchecked_return_uses_contract(self):
        """UNCHECKED_RETURN should use contract-based analysis."""
        strategy = KITCHENSINK_BUG_STRATEGIES["UNCHECKED_RETURN"]
        assert strategy.inter.summary_type == "contract"
    
    def test_stale_value_uses_stochastic(self):
        """STALE_VALUE should use stochastic barriers."""
        strategy = KITCHENSINK_BUG_STRATEGIES["STALE_VALUE"]
        assert strategy.barrier_type == "stochastic"
        assert 2 in strategy.intra.tp_papers  # Stochastic Barriers


class TestProtocolBugs:
    """Test protocol bug detection strategies."""
    
    def test_iterator_uses_assume_guarantee(self):
        """ITERATOR_PROTOCOL should use Assume-Guarantee for contract."""
        strategy = KITCHENSINK_BUG_STRATEGIES["ITERATOR_PROTOCOL"]
        assert 20 in strategy.intra.fp_papers  # Assume-Guarantee
        assert "contract" in strategy.inter.summary_type
    
    def test_context_manager_tracks_resources(self):
        """CONTEXT_MANAGER_PROTOCOL should track resource state."""
        strategy = KITCHENSINK_BUG_STRATEGIES["CONTEXT_MANAGER_PROTOCOL"]
        assert strategy.inter.summary_type == "resource_state"
        assert strategy.semantic_domain == "temporal"


class TestResourceBugs:
    """Test resource bug detection strategies."""
    
    def test_memory_exhaustion_uses_polynomial(self):
        """MEMORY_EXHAUSTION should use polynomial barriers for bounds."""
        strategy = KITCHENSINK_BUG_STRATEGIES["MEMORY_EXHAUSTION"]
        assert strategy.barrier_type == "polynomial"
        assert 6 in strategy.intra.fp_papers  # SOS-SDP
    
    def test_cpu_exhaustion_uses_ranking(self):
        """CPU_EXHAUSTION should use ranking functions for termination."""
        strategy = KITCHENSINK_BUG_STRATEGIES["CPU_EXHAUSTION"]
        assert strategy.barrier_type == "ranking"
        assert 19 in strategy.intra.fp_papers  # SyGuS for ranking
    
    def test_handle_exhaustion_uses_counting(self):
        """HANDLE_EXHAUSTION should use counting for bounds."""
        strategy = KITCHENSINK_BUG_STRATEGIES["HANDLE_EXHAUSTION"]
        assert strategy.barrier_type == "polynomial"
        assert "handles" in strategy.intra.z3_encoding


class TestInterProceduralStrategies:
    """Test inter-procedural verification strategies."""
    
    def test_function_summary_structure(self):
        """FunctionSummary should have all required fields."""
        summary = FunctionSummary(
            function_name="test_func",
            filepath="test.py",
            preconditions=["x > 0"],
            postconditions=["ret >= 0"],
        )
        assert summary.function_name == "test_func"
        assert len(summary.preconditions) == 1
        assert len(summary.postconditions) == 1
    
    def test_composition_detects_unhandled_exception(self):
        """compose_summaries should detect unhandled exceptions."""
        caller = FunctionSummary(
            function_name="caller",
            filepath="test.py",
            exceptions_caught=["TypeError"],
        )
        callee = FunctionSummary(
            function_name="callee",
            filepath="test.py",
            exceptions_raised=["ValueError"],
        )
        
        result = compose_summaries(caller, callee, "test.py:10")
        
        # ValueError is not caught by caller
        assert len(result.bugs) > 0
        assert any(b["bug_type"] == "UNHANDLED_EXCEPTION" for b in result.bugs)
    
    def test_composition_detects_resource_leak(self):
        """compose_summaries should detect resource leaks."""
        caller = FunctionSummary(
            function_name="caller",
            filepath="test.py",
        )
        callee = FunctionSummary(
            function_name="callee",
            filepath="test.py",
            resources_acquired=["file_handle"],
            resources_released=[],  # Not released!
        )
        
        result = compose_summaries(caller, callee, "test.py:10")
        
        assert "file_handle" in result.resource_leaks


class TestKitchensinkOrchestrator:
    """Test the orchestrator for efficient verification."""
    
    def test_orchestrator_creation(self):
        """Orchestrator should be creatable with options."""
        orch = KitchensinkOrchestrator(verbose=True, timeout_ms=5000)
        assert orch.verbose is True
        assert orch.timeout_ms == 5000
    
    def test_get_strategy_for_known_bug(self):
        """get_strategy_for_bug should return strategy for known bugs."""
        for bug_type in KITCHENSINK_BUG_STRATEGIES:
            strategy = get_strategy_for_bug(bug_type)
            assert strategy is not None
            assert strategy.bug_type == bug_type
    
    def test_get_strategy_for_unknown_bug(self):
        """get_strategy_for_bug should return None for unknown bugs."""
        strategy = get_strategy_for_bug("UNKNOWN_BUG_TYPE")
        assert strategy is None
    
    def test_list_all_bug_types(self):
        """list_all_bug_types should return all defined bugs."""
        bugs = list_all_bug_types()
        assert len(bugs) == 24
        assert "PRECONDITION_VIOLATION" in bugs
        assert "USE_AFTER_CLOSE" in bugs
    
    def test_get_fp_reduction_rate(self):
        """get_fp_reduction_rate should return valid rates."""
        for bug_type in KITCHENSINK_BUG_STRATEGIES:
            baseline, kitchensink = get_fp_reduction_rate(bug_type)
            assert 0.0 <= baseline <= 1.0
            assert 0.0 <= kitchensink <= 1.0
            assert kitchensink < baseline
    
    def test_get_optimal_papers_fp(self):
        """get_optimal_papers should return FP papers."""
        papers = get_optimal_papers_for_bug("PRECONDITION_VIOLATION", mode="fp")
        assert 18 in papers  # Houdini
    
    def test_get_optimal_papers_tp(self):
        """get_optimal_papers should return TP papers."""
        papers = get_optimal_papers_for_bug("PRECONDITION_VIOLATION", mode="tp")
        assert 10 in papers  # IC3/PDR


class TestRealWorldScenarios:
    """Test real-world scenarios where kitchensink shines."""
    
    def test_contract_inference_scenario(self):
        """
        Scenario: Function has undocumented precondition.
        
        Without kitchensink: Reports all callers as bugs (~60% FP)
        With kitchensink: Houdini infers precondition, only real violations reported (~10% FP)
        """
        strategy = KITCHENSINK_BUG_STRATEGIES["PRECONDITION_VIOLATION"]
        
        # Baseline FP rate is high
        assert strategy.baseline_fp_rate >= 0.50
        
        # Kitchensink dramatically reduces
        assert strategy.kitchensink_fp_rate <= 0.15
        
        # Key paper is Houdini (#18)
        assert 18 in strategy.intra.fp_papers
    
    def test_resource_cleanup_scenario(self):
        """
        Scenario: File handle may not be closed on exception path.
        
        Without kitchensink: Reports all file opens as bugs (~55% FP)
        With kitchensink: IC3/PDR finds real paths missing cleanup (~10% FP)
        """
        strategy = KITCHENSINK_BUG_STRATEGIES["MISSING_CLEANUP"]
        
        # Baseline FP rate is moderate
        assert strategy.baseline_fp_rate >= 0.50
        
        # Kitchensink reduces via ranking + path analysis
        assert strategy.kitchensink_fp_rate <= 0.15
        
        # Key paper is IC3/PDR (#10)
        assert 10 in strategy.intra.fp_papers or 10 in strategy.intra.tp_papers
    
    def test_iterator_protocol_scenario(self):
        """
        Scenario: Custom iterator may violate protocol.
        
        Without kitchensink: All custom iterators flagged (~25% FP)
        With kitchensink: Assume-Guarantee verifies contract (~5% FP)
        """
        strategy = KITCHENSINK_BUG_STRATEGIES["ITERATOR_PROTOCOL"]
        
        # Already relatively low baseline due to well-defined protocol
        assert strategy.baseline_fp_rate <= 0.30
        
        # Kitchensink achieves very low FP rate
        assert strategy.kitchensink_fp_rate <= 0.08
        
        # Key paper is Assume-Guarantee (#20)
        assert 20 in strategy.intra.fp_papers
    
    def test_memory_exhaustion_scenario(self):
        """
        Scenario: Loop may allocate unbounded memory.
        
        Without kitchensink: All loops flagged (~60% FP)
        With kitchensink: Polynomial barrier proves bounded growth (~20% FP)
        """
        strategy = KITCHENSINK_BUG_STRATEGIES["MEMORY_EXHAUSTION"]
        
        # Baseline FP rate is high due to conservative analysis
        assert strategy.baseline_fp_rate >= 0.50
        
        # Kitchensink reduces via polynomial bounds
        assert strategy.kitchensink_fp_rate <= 0.25
        
        # Uses SOS-SDP for polynomial barrier
        assert 6 in strategy.intra.fp_papers


class TestZ3Encodings:
    """Test that Z3 encodings are well-formed."""
    
    def test_all_encodings_mention_check(self):
        """All Z3 encodings should describe what to check."""
        for bug_type, strategy in KITCHENSINK_BUG_STRATEGIES.items():
            encoding = strategy.intra.z3_encoding
            # Should have some formula structure (various operators)
            assert any(op in encoding for op in ["=", "∧", "∨", "→", "¬", "≤", "≥", "<", ">", "⊇", "⊆"]), \
                f"{bug_type} encoding lacks formula structure"
    
    def test_temporal_bugs_use_temporal_operators(self):
        """Temporal bugs should have temporal operators in encoding."""
        temporal_bugs = ["MISSING_CLEANUP"]
        for bug in temporal_bugs:
            if bug in KITCHENSINK_BUG_STRATEGIES:
                strategy = KITCHENSINK_BUG_STRATEGIES[bug]
                encoding = strategy.intra.z3_encoding
                # Should mention temporal concepts
                assert any(t in encoding for t in ["◇", "→", "eventually", "always", "paths"]), \
                    f"{bug} should have temporal operators"
    
    def test_counting_bugs_use_arithmetic(self):
        """Counting bugs should use arithmetic in encoding."""
        counting_bugs = ["DOUBLE_CLOSE", "HANDLE_EXHAUSTION"]
        for bug in counting_bugs:
            strategy = KITCHENSINK_BUG_STRATEGIES[bug]
            encoding = strategy.intra.z3_encoding
            # Should mention counting/arithmetic
            assert any(a in encoding for a in ["count", "Σ", "+", "-", "≤", "≥"]), \
                f"{bug} should use arithmetic"

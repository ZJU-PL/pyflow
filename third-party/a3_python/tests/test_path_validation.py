"""
Tests for path validation barrier certificates.

Tests that the system can detect path validation patterns (like startswith checks)
and generate barrier certificates proving safety of tarslip/zipslip operations.
"""

import pytest
from a3_python.barriers.path_validation import (
    PathValidationTracker,
    detect_startswith_validation,
    detect_abspath_check
)
from a3_python.z3model.taint_lattice import SinkType
import z3


class TestPathValidationDetection:
    """Test detection of path validation patterns."""
    
    def test_detect_startswith_method_call(self):
        """Test detection of path.startswith(prefix) pattern."""
        # Simulate: member_path.startswith(safe_dest)
        path_obj = object()  # The path being validated
        safe_prefix = object()  # The safe prefix
        result = object()  # Return value of startswith
        
        # Method call: receiver is path, args[0] is prefix
        detected = detect_startswith_validation(
            func_name="startswith",
            receiver=path_obj,
            args=[safe_prefix],
            result=result
        )
        
        assert detected is not None, "Should detect startswith pattern"
        validated_value, validation_passes = detected
        assert validated_value is path_obj
        assert validation_passes is True
    
    def test_detect_startswith_function_call(self):
        """Test detection of str.startswith(path, prefix) pattern."""
        path_obj = object()
        safe_prefix = object()
        result = object()
        
        # Function call: args[0] is path, args[1] is prefix
        detected = detect_startswith_validation(
            func_name="str.startswith",
            receiver=None,
            args=[path_obj, safe_prefix],
            result=result
        )
        
        assert detected is not None
        validated_value, validation_passes = detected
        assert validated_value is path_obj
        assert validation_passes is True
    
    def test_detect_abspath(self):
        """Test detection of os.path.abspath() calls."""
        path_obj = object()
        result = object()
        
        detected = detect_abspath_check(
            func_name="os.path.abspath",
            args=[path_obj]
        )
        
        assert detected is not None
        original_path, is_normalized = detected
        assert original_path is path_obj
        assert is_normalized is True
    
    def test_no_detection_for_other_functions(self):
        """Test that other functions don't trigger detection."""
        obj = object()
        
        # Not a startswith call
        detected = detect_startswith_validation(
            func_name="endswith",
            receiver=obj,
            args=[object()],
            result=object()
        )
        assert detected is None
        
        # Not an abspath call
        detected = detect_abspath_check(
            func_name="os.path.basename",
            args=[obj]
        )
        assert detected is None


class TestPathValidationTracker:
    """Test PathValidationTracker for recording and querying validations."""
    
    def test_record_and_query_validation(self):
        """Test recording a validation and querying it."""
        tracker = PathValidationTracker()
        value = object()
        guard = z3.Bool("test_guard")
        
        tracker.record_validation(value, guard, "test_location")
        
        # Should be able to query for FILE_PATH sink
        retrieved_guard = tracker.get_guard(value, SinkType.FILE_PATH)
        assert retrieved_guard is not None
        
        # Should be marked as validated
        assert tracker.is_validated(value, SinkType.FILE_PATH)
    
    def test_unvalidated_value(self):
        """Test querying for unvalidated value returns None."""
        tracker = PathValidationTracker()
        value = object()
        
        retrieved_guard = tracker.get_guard(value, SinkType.FILE_PATH)
        assert retrieved_guard is None
        assert not tracker.is_validated(value, SinkType.FILE_PATH)
    
    def test_clear(self):
        """Test clearing validation guards."""
        tracker = PathValidationTracker()
        value = object()
        guard = z3.Bool("test_guard")
        
        tracker.record_validation(value, guard, "test_location")
        assert tracker.is_validated(value, SinkType.FILE_PATH)
        
        tracker.clear()
        assert not tracker.is_validated(value, SinkType.FILE_PATH)


class TestPathValidationBarrier:
    """Test barrier certificate generation for path validation."""
    
    def test_create_path_safety_barrier(self):
        """Test creation of path safety barrier certificate."""
        from a3_python.z3model.taint_lattice import TaintLabel, SourceType
        
        tracker = PathValidationTracker()
        value = object()
        guard = z3.Bool("path_validated")
        
        tracker.record_validation(value, guard, "test_location")
        
        # Create a tainted label (from untrusted source)
        tainted_label = TaintLabel.from_untrusted_source(
            SourceType.FILE_CONTENT,
            "archive_member"
        )
        
        # Create barrier at sink
        at_sink = z3.Bool("at_extractall")
        barrier = tracker.create_path_safety_barrier(
            value,
            SinkType.FILE_PATH,
            tainted_label,
            at_sink
        )
        
        assert barrier is not None, "Should create barrier for validated value"
        
        # Barrier should be a Z3 expression
        assert isinstance(barrier, z3.ExprRef)
    
    def test_no_barrier_without_validation(self):
        """Test that no barrier is created for unvalidated values."""
        from a3_python.z3model.taint_lattice import TaintLabel, SourceType
        
        tracker = PathValidationTracker()
        value = object()
        
        # No validation recorded
        tainted_label = TaintLabel.from_untrusted_source(
            SourceType.FILE_CONTENT,
            "archive_member"
        )
        
        at_sink = z3.Bool("at_extractall")
        barrier = tracker.create_path_safety_barrier(
            value,
            SinkType.FILE_PATH,
            tainted_label,
            at_sink
        )
        
        assert barrier is None, "Should not create barrier without validation"

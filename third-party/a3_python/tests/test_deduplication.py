"""
Tests for bug report deduplication.
"""

import pytest
from a3_python.evaluation.deduplication import (
    deduplicate_findings,
    consolidate_variants,
    deduplicate_scan_results,
    filter_by_confidence
)


def test_deduplicate_single_location():
    """Test deduplication of multiple findings at same location."""
    findings = [
        {
            'bug_type': 'SQL_INJECTION',
            'crash_location': 'views.py:process_user',
            'confidence': 0.9,
            'call_chain': ['main', 'process_user'],
            'tainted_sources': ['request.GET']
        },
        {
            'bug_type': 'SQL_INJECTION',
            'crash_location': 'views.py:process_user',
            'confidence': 0.85,
            'call_chain': ['main', 'handle_post', 'process_user'],
            'tainted_sources': ['request.POST']
        },
        {
            'bug_type': 'SQL_INJECTION',
            'crash_location': 'views.py:process_user',
            'confidence': 0.95,  # Highest
            'call_chain': ['api', 'process_user'],
            'tainted_sources': ['request.GET', 'environ']
        }
    ]
    
    deduplicated = deduplicate_findings(findings)
    
    # Should have 1 finding (same location)
    assert len(deduplicated) == 1
    
    # Should pick highest confidence
    assert deduplicated[0]['confidence'] == 0.95
    assert deduplicated[0]['call_chain'] == ['api', 'process_user']
    
    # Should aggregate metadata
    assert deduplicated[0]['occurrences'] == 3
    assert len(deduplicated[0]['example_call_chains']) == 3
    assert set(deduplicated[0]['all_tainted_sources']) == {'request.GET', 'request.POST', 'environ'}
    
    # Should have confidence range
    assert deduplicated[0]['confidence_range']['min'] == 0.85
    assert deduplicated[0]['confidence_range']['max'] == 0.95
    assert abs(deduplicated[0]['confidence_range']['mean'] - 0.9) < 0.01


def test_deduplicate_different_locations():
    """Test that different locations are kept separate."""
    findings = [
        {
            'bug_type': 'XSS',
            'crash_location': 'views.py:render_page',
            'confidence': 0.9,
            'call_chain': []
        },
        {
            'bug_type': 'XSS',
            'crash_location': 'views.py:render_profile',
            'confidence': 0.85,
            'call_chain': []
        }
    ]
    
    deduplicated = deduplicate_findings(findings)
    
    # Should have 2 findings (different locations)
    assert len(deduplicated) == 2
    
    # Should be sorted by confidence
    assert deduplicated[0]['confidence'] == 0.9
    assert deduplicated[1]['confidence'] == 0.85


def test_deduplicate_different_bug_types():
    """Test that different bug types at same location are kept separate."""
    findings = [
        {
            'bug_type': 'SQL_INJECTION',
            'crash_location': 'views.py:process',
            'confidence': 0.9,
            'call_chain': []
        },
        {
            'bug_type': 'COMMAND_INJECTION',
            'crash_location': 'views.py:process',
            'confidence': 0.85,
            'call_chain': []
        }
    ]
    
    deduplicated = deduplicate_findings(findings)
    
    # Should have 2 findings (different bug types)
    assert len(deduplicated) == 2


def test_consolidate_ssrf_variants():
    """Test SSRF variant consolidation."""
    findings = [
        {'bug_type': 'FULL_SSRF', 'crash_location': 'a'},
        {'bug_type': 'PARTIAL_SSRF', 'crash_location': 'b'},
        {'bug_type': 'SSRF', 'crash_location': 'c'}
    ]
    
    consolidated = consolidate_variants(findings)
    
    # All should be mapped to SSRF
    assert all(f['bug_type'] == 'SSRF' for f in consolidated)
    
    # Original types should be tracked
    assert consolidated[0]['original_bug_type'] == 'FULL_SSRF'
    assert consolidated[1]['original_bug_type'] == 'PARTIAL_SSRF'
    assert 'original_bug_type' not in consolidated[2]  # Already SSRF


def test_consolidate_xss_variants():
    """Test XSS variant consolidation."""
    findings = [
        {'bug_type': 'REFLECTED_XSS', 'crash_location': 'a'},
        {'bug_type': 'STORED_XSS', 'crash_location': 'b'},
        {'bug_type': 'DOM_XSS', 'crash_location': 'c'}
    ]
    
    consolidated = consolidate_variants(findings)
    
    # All should be mapped to XSS
    assert all(f['bug_type'] == 'XSS' for f in consolidated)


def test_consolidate_path_variants():
    """Test path injection variant consolidation."""
    findings = [
        {'bug_type': 'PATH_INJECTION', 'crash_location': 'a'},
        {'bug_type': 'TARSLIP', 'crash_location': 'b'},
        {'bug_type': 'ZIPSLIP', 'crash_location': 'c'}
    ]
    
    consolidated = consolidate_variants(findings)
    
    # All should be mapped to PATH_INJECTION
    assert all(f['bug_type'] == 'PATH_INJECTION' for f in consolidated)


def test_filter_by_confidence():
    """Test confidence filtering."""
    findings = [
        {'bug_type': 'A', 'confidence': 0.95},
        {'bug_type': 'B', 'confidence': 0.75},
        {'bug_type': 'C', 'confidence': 0.5},
        {'bug_type': 'D', 'confidence': 0.3}
    ]
    
    # Filter >= 0.7
    filtered = filter_by_confidence(findings, min_confidence=0.7)
    assert len(filtered) == 2
    assert all(f['confidence'] >= 0.7 for f in filtered)
    
    # Filter >= 0.9
    filtered = filter_by_confidence(findings, min_confidence=0.9)
    assert len(filtered) == 1
    assert filtered[0]['bug_type'] == 'A'


def test_deduplicate_scan_results():
    """Test full scan results deduplication."""
    results = {
        'scan_date': '2026-01-24',
        'project': 'test',
        'total_findings': 6,
        'findings_by_type': {
            'SSRF': 3,
            'XSS': 3
        },
        'findings': [
            # SSRF variants at same location
            {'bug_type': 'FULL_SSRF', 'crash_location': 'a', 'confidence': 0.9},
            {'bug_type': 'PARTIAL_SSRF', 'crash_location': 'a', 'confidence': 0.85},
            {'bug_type': 'SSRF', 'crash_location': 'a', 'confidence': 0.8},
            
            # XSS at different locations
            {'bug_type': 'REFLECTED_XSS', 'crash_location': 'b', 'confidence': 0.95},
            {'bug_type': 'STORED_XSS', 'crash_location': 'c', 'confidence': 0.9},
            {'bug_type': 'DOM_XSS', 'crash_location': 'd', 'confidence': 0.85}
        ]
    }
    
    deduplicated = deduplicate_scan_results(results, consolidate=True)
    
    # Should have 4 findings: 1 SSRF + 3 XSS (different locations)
    assert deduplicated['total_findings'] == 4
    
    # Check by type
    assert deduplicated['findings_by_type']['SSRF'] == 1
    assert deduplicated['findings_by_type']['XSS'] == 3
    
    # Check metadata
    meta = deduplicated['deduplication_metadata']
    assert meta['original_count'] == 6
    assert meta['deduplicated_count'] == 4
    assert meta['variants_consolidated'] == True


def test_deduplicate_empty():
    """Test deduplication of empty findings."""
    findings = []
    deduplicated = deduplicate_findings(findings)
    assert deduplicated == []


def test_deduplicate_call_chain_limit():
    """Test that call chain examples are limited."""
    findings = [
        {
            'bug_type': 'A',
            'crash_location': 'x',
            'confidence': 0.9,
            'call_chain': [f'chain_{i}' for i in range(10)]
        }
        for _ in range(10)
    ]
    
    deduplicated = deduplicate_findings(findings)
    
    # Should have 1 finding
    assert len(deduplicated) == 1
    
    # Should have max 5 example call chains
    assert len(deduplicated[0]['example_call_chains']) <= 5


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

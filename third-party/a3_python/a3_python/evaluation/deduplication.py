"""
Path deduplication for bug reports.

Reduces N findings to ~N/k by grouping by (bug_type, location) and keeping
representative examples with highest confidence.

This implements the action item from iteration 439:
"Implement path deduplication (reduce 2,360 → ~300 by grouping by bug_type + location)"
"""

from typing import Dict, List, Any
from collections import defaultdict
import json


def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate findings by (bug_type, crash_location).
    
    For each unique (bug_type, location) pair:
    - Keep the finding with highest confidence
    - Aggregate metadata: call_chains, tainted_sources
    - Count total occurrences
    
    Args:
        findings: List of bug findings from scan
        
    Returns:
        Deduplicated list of findings with aggregated metadata
    """
    # Group by (bug_type, location)
    groups = defaultdict(list)
    
    for finding in findings:
        bug_type = finding.get('bug_type', 'UNKNOWN')
        location = finding.get('crash_location', finding.get('crash_function', 'unknown'))
        key = (bug_type, location)
        groups[key].append(finding)
    
    # For each group, pick representative with highest confidence
    deduplicated = []
    
    for (bug_type, location), group_findings in groups.items():
        # Sort by confidence (descending)
        sorted_findings = sorted(
            group_findings,
            key=lambda f: f.get('confidence', 0.0),
            reverse=True
        )
        
        # Take highest confidence as representative
        representative = sorted_findings[0].copy()
        
        # Aggregate metadata
        all_call_chains = []
        all_sources = set()
        
        for finding in group_findings:
            call_chain = finding.get('call_chain', [])
            if call_chain and call_chain not in all_call_chains:
                all_call_chains.append(call_chain)
            
            sources = finding.get('tainted_sources', [])
            all_sources.update(sources)
        
        # Update representative with aggregated data
        representative['occurrences'] = len(group_findings)
        representative['example_call_chains'] = all_call_chains[:5]  # Keep top 5
        representative['all_tainted_sources'] = sorted(list(all_sources))
        
        # Add confidence range
        confidences = [f.get('confidence', 0.0) for f in group_findings]
        representative['confidence_range'] = {
            'min': min(confidences),
            'max': max(confidences),
            'mean': sum(confidences) / len(confidences) if confidences else 0.0
        }
        
        deduplicated.append(representative)
    
    # Sort by confidence (descending)
    deduplicated.sort(key=lambda f: f.get('confidence', 0.0), reverse=True)
    
    return deduplicated


def consolidate_variants(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Consolidate bug type variants into canonical types.
    
    Examples:
    - FULL_SSRF, PARTIAL_SSRF, SSRF → SSRF
    - REFLECTED_XSS, STORED_XSS, DOM_XSS → XSS
    - PATH_INJECTION, TARSLIP, ZIPSLIP → PATH_INJECTION
    - URL_REDIRECT, UNVALIDATED_REDIRECT → URL_REDIRECT
    
    Args:
        findings: List of findings (possibly with variant types)
        
    Returns:
        List of findings with consolidated bug types
    """
    # Variant consolidation rules
    VARIANT_MAP = {
        # SSRF variants
        'FULL_SSRF': 'SSRF',
        'PARTIAL_SSRF': 'SSRF',
        
        # XSS variants
        'REFLECTED_XSS': 'XSS',
        'STORED_XSS': 'XSS',
        'DOM_XSS': 'XSS',
        
        # Path injection variants
        'TARSLIP': 'PATH_INJECTION',
        'ZIPSLIP': 'PATH_INJECTION',
        
        # Redirect variants
        'UNVALIDATED_REDIRECT': 'URL_REDIRECT',
        
        # Crypto variants
        'WEAK_SENSITIVE_DATA_HASHING': 'WEAK_CRYPTO',
        'BROKEN_CRYPTO_ALGORITHM': 'WEAK_CRYPTO',
    }
    
    consolidated = []
    
    for finding in findings:
        bug_type = finding.get('bug_type', 'UNKNOWN')
        original_type = bug_type
        
        # Map to canonical type if it's a variant
        canonical_type = VARIANT_MAP.get(bug_type, bug_type)
        
        # Update finding
        finding_copy = finding.copy()
        finding_copy['bug_type'] = canonical_type
        
        # Track original if different
        if canonical_type != original_type:
            finding_copy['original_bug_type'] = original_type
        
        consolidated.append(finding_copy)
    
    return consolidated


def deduplicate_scan_results(
    results: Dict[str, Any],
    consolidate: bool = True
) -> Dict[str, Any]:
    """
    Deduplicate and consolidate scan results.
    
    Args:
        results: Scan results dict with 'findings' key
        consolidate: Whether to consolidate variants
        
    Returns:
        New results dict with deduplicated findings
    """
    findings = results.get('findings', [])
    
    # Step 1: Consolidate variants (optional)
    if consolidate:
        findings = consolidate_variants(findings)
    
    # Step 2: Deduplicate by (bug_type, location)
    deduplicated = deduplicate_findings(findings)
    
    # Recompute stats
    findings_by_type = defaultdict(int)
    for finding in deduplicated:
        bug_type = finding['bug_type']
        findings_by_type[bug_type] += 1
    
    # Create new results dict
    new_results = results.copy()
    new_results['findings'] = deduplicated
    new_results['total_findings'] = len(deduplicated)
    new_results['findings_by_type'] = dict(findings_by_type)
    
    # Add metadata about deduplication
    new_results['deduplication_metadata'] = {
        'original_count': len(results.get('findings', [])),
        'deduplicated_count': len(deduplicated),
        'reduction_ratio': len(deduplicated) / len(results.get('findings', [])) if results.get('findings') else 0.0,
        'variants_consolidated': consolidate
    }
    
    return new_results


def filter_by_confidence(
    findings: List[Dict[str, Any]],
    min_confidence: float = 0.5
) -> List[Dict[str, Any]]:
    """
    Filter findings by minimum confidence threshold.
    
    Args:
        findings: List of findings
        min_confidence: Minimum confidence (0.0-1.0)
        
    Returns:
        Filtered list of findings
    """
    return [
        f for f in findings
        if f.get('confidence', 0.0) >= min_confidence
    ]


if __name__ == '__main__':
    """
    CLI for deduplicating scan results.
    
    Usage:
        python -m a3_python.evaluation.deduplication \
            results/pygoat_scan_iter439.json \
            --output results/pygoat_scan_iter440_deduplicated.json \
            --min-confidence 0.7
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Deduplicate scan results')
    parser.add_argument('input', help='Input JSON file')
    parser.add_argument('--output', help='Output JSON file (default: stdout)')
    parser.add_argument(
        '--min-confidence',
        type=float,
        default=0.0,
        help='Minimum confidence threshold (0.0-1.0)'
    )
    parser.add_argument(
        '--no-consolidate',
        action='store_true',
        help='Disable variant consolidation'
    )
    
    args = parser.parse_args()
    
    # Load input
    with open(args.input, 'r') as f:
        results = json.load(f)
    
    # Deduplicate
    deduplicated = deduplicate_scan_results(
        results,
        consolidate=not args.no_consolidate
    )
    
    # Filter by confidence
    if args.min_confidence > 0.0:
        deduplicated['findings'] = filter_by_confidence(
            deduplicated['findings'],
            args.min_confidence
        )
        deduplicated['total_findings'] = len(deduplicated['findings'])
        
        # Recompute by type
        findings_by_type = defaultdict(int)
        for finding in deduplicated['findings']:
            findings_by_type[finding['bug_type']] += 1
        deduplicated['findings_by_type'] = dict(findings_by_type)
        
        deduplicated['deduplication_metadata']['min_confidence'] = args.min_confidence
        deduplicated['deduplication_metadata']['after_confidence_filter'] = len(deduplicated['findings'])
    
    # Output
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(deduplicated, f, indent=2)
        print(f"Wrote deduplicated results to {args.output}")
        print(f"Original: {deduplicated['deduplication_metadata']['original_count']} findings")
        print(f"After deduplication: {deduplicated['deduplication_metadata']['deduplicated_count']} findings")
        if args.min_confidence > 0.0:
            print(f"After confidence filter: {deduplicated['deduplication_metadata']['after_confidence_filter']} findings")
    else:
        print(json.dumps(deduplicated, indent=2))

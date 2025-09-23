"""
AST-based security checker CLI. (Current, it does not use the facilities in pyflow.)
"""
import argparse
import logging
import sys

from pyflow.checker.core.manager import SecurityManager
from pyflow.checker.core.config import SecurityConfig


def add_security_parser(subparsers):
    """Add security subcommand parser."""
    security_parser = subparsers.add_parser(
        "security", 
        help="Run security analysis on Python files"
    )
    security_parser.add_argument(
        "targets", 
        nargs="*", 
        help="Files or directories to check"
    )
    security_parser.add_argument(
        "-r", "--recursive", 
        action="store_true", 
        help="Scan directories recursively"
    )
    security_parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Verbose output"
    )
    security_parser.add_argument(
        "-d", "--debug", 
        action="store_true", 
        help="Debug output"
    )
    security_parser.add_argument(
        "--exclude", 
        help="Comma-separated list of paths to exclude"
    )


def run_security_analysis(targets, args):
    """Main CLI entry point"""
    # args is already parsed by the main CLI parser
    
    # Set up logging
    level = logging.DEBUG if args.debug else logging.INFO if args.verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    
    # Create configuration
    config = SecurityConfig()
    
    # Create security manager
    manager = SecurityManager(
        config=config,
        debug=args.debug,
        verbose=args.verbose,
        quiet=False
    )
    
    # Discover files
    targets = targets or ["."]
    manager.discover_files(targets, recursive=args.recursive, excluded_paths="")
    
    # Run security checks
    manager.run_tests()
    
    # Report results
    issues = manager.get_issue_list()
    
    if issues:
        print(f"\nFound {len(issues)} security issues:")
        for issue in issues:
            print(f"  {issue}")
        return 1
    else:
        print("No security issues found.")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyFlow Security Checker")
    add_security_parser(parser.add_subparsers(dest="command", required=True))
    
    args = parser.parse_args()
    sys.exit(run_security_analysis(args.targets, args))

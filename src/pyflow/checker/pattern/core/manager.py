# Security checker manager
import collections
import fnmatch
import io
import json
import logging
import os
import re
import sys
import tokenize
import traceback

from . import constants as b_constants
from . import issue
from . import metrics
from . import node_visitor as b_node_visitor
from . import test_set as b_test_set

LOG = logging.getLogger(__name__)
NOSEC_COMMENT = re.compile(r"#\s*nosec:?\s*(?P<tests>[^#]+)?#?")
NOSEC_COMMENT_TESTS = re.compile(r"(?:(B\d+|[a-z\d_]+),?)+", re.IGNORECASE)


class SecurityManager:
    scope = []

    def __init__(
        self,
        config,
        debug=False,
        verbose=False,
        quiet=False,
        profile=None,
        ignore_nosec=False,
    ):
        """Initialize the security checker manager"""
        self.debug = debug
        self.verbose = verbose
        self.quiet = quiet
        self.ignore_nosec = ignore_nosec
        self.b_conf = config
        self.files_list = []
        self.excluded_files = []
        self.skipped = []
        self.results = []
        self.baseline = []
        self.metrics = metrics.Metrics()
        self.b_ts = b_test_set.SecurityTestSet(config, profile or {})
        self.scores = []

    def get_skipped(self):
        """Get list of skipped files"""
        return [
            (skip[0].decode("utf-8"), skip[1]) if isinstance(skip[0], bytes) else skip
            for skip in self.skipped
        ]

    def get_issue_list(self, sev_level=b_constants.LOW, conf_level=b_constants.LOW):
        """Get filtered list of issues"""
        return self.filter_results(sev_level, conf_level)

    def populate_baseline(self, data):
        """Populate a baseline set of issues from a JSON report"""
        try:
            jdata = json.loads(data)
            self.baseline = [issue.issue_from_dict(j) for j in jdata["results"]]
        except Exception as e:
            LOG.warning("Failed to load baseline data: %s", e)
            self.baseline = []

    def filter_results(self, sev_filter, conf_filter):
        """Returns a list of results filtered by the baseline"""
        results = [i for i in self.results if i.filter(sev_filter, conf_filter)]
        return (
            results
            if not self.baseline
            else _find_candidate_matches(
                _compare_baseline_results(self.baseline, results), results
            )
        )

    def results_count(self, sev_filter=b_constants.LOW, conf_filter=b_constants.LOW):
        """Return the count of results"""
        return len(self.get_issue_list(sev_filter, conf_filter))

    def discover_files(self, targets, recursive=False, excluded_paths=""):
        """Add tests directly and from a directory to the test set"""
        files_list = set()
        excluded_files = set()

        excluded_path_globs = self.b_conf.get_option("exclude_dirs") or []
        included_globs = self.b_conf.get_option("include") or ["*.py"]

        # Add command line provided exclusions
        if excluded_paths:
            for path in excluded_paths.split(","):
                if os.path.isdir(path):
                    path = os.path.join(path, "*")
                excluded_path_globs.append(path)

        # Build list of files to analyze
        for fname in targets:
            if os.path.isdir(fname):
                if recursive:
                    new_files, newly_excluded = _get_files_from_dir(
                        fname, included_globs, excluded_path_globs
                    )
                    files_list.update(new_files)
                    excluded_files.update(newly_excluded)
                else:
                    LOG.warning(
                        "Skipping directory (%s), use -r flag to scan contents", fname
                    )
            else:
                if _is_file_included(
                    fname, included_globs, excluded_path_globs, enforce_glob=False
                ):
                    files_list.add(os.path.join(".", fname) if fname != "-" else fname)
                else:
                    excluded_files.add(fname)

        self.files_list = sorted(files_list)
        self.excluded_files = sorted(excluded_files)

    def run_tests(self):
        """Run through all files in the scope"""
        new_files_list = list(self.files_list)

        for fname in self.files_list:
            LOG.debug("working on file : %s", fname)
            try:
                if fname == "-":
                    fdata = io.BytesIO(os.fdopen(sys.stdin.fileno(), "rb", 0).read())
                    new_files_list = [
                        "<stdin>" if x == "-" else x for x in new_files_list
                    ]
                    self._parse_file("<stdin>", fdata, new_files_list)
                else:
                    with open(fname, "rb") as fdata:
                        self._parse_file(fname, fdata, new_files_list)
            except OSError as e:
                self.skipped.append((fname, e.strerror))
                new_files_list.remove(fname)

        self.files_list = new_files_list
        self.metrics.aggregate()

    def _parse_file(self, fname, fdata, new_files_list):
        """Parse a single file"""
        try:
            data = fdata.read()
            lines = data.splitlines()
            self.metrics.begin(fname)
            self.metrics.count_locs(lines)

            # Parse nosec comments
            nosec_lines = {}
            if not self.ignore_nosec:
                try:
                    fdata.seek(0)
                    for toktype, tokval, (lineno, _), _, _ in tokenize.tokenize(
                        fdata.readline
                    ):
                        if toktype == tokenize.COMMENT:
                            nosec_lines[lineno] = _parse_nosec_comment(tokval)
                except tokenize.TokenError:
                    pass

            score = self._execute_ast_visitor(fname, fdata, data, nosec_lines)
            self.scores.append(score)
            self.metrics.count_issues([score])
        except KeyboardInterrupt:
            sys.exit(2)
        except SyntaxError:
            self.skipped.append((fname, "syntax error while parsing AST from file"))
            new_files_list.remove(fname)
        except Exception as e:
            LOG.error("Exception occurred when executing tests against %s.", fname)
            if not LOG.isEnabledFor(logging.DEBUG):
                LOG.error("Run with --debug to see the full traceback.")
            self.skipped.append((fname, "exception while scanning file"))
            new_files_list.remove(fname)
            LOG.debug("  Exception string: %s", e)
            LOG.debug("  Exception traceback: %s", traceback.format_exc())

    def _execute_ast_visitor(self, fname, fdata, data, nosec_lines):
        """Execute AST parse on each file"""
        res = b_node_visitor.SecurityNodeVisitor(
            fname, fdata, self.b_ts, self.debug, nosec_lines, self.metrics
        )
        score = res.process(data)
        self.results.extend(res.tester.results)
        return score


def _get_files_from_dir(files_dir, included_globs=None, excluded_path_strings=None):
    """Get files from a directory"""
    included_globs = included_globs or ["*.py"]
    excluded_path_strings = excluded_path_strings or []

    files_list = set()
    excluded_files = set()

    for root, _, files in os.walk(files_dir):
        for filename in files:
            path = os.path.join(root, filename)
            if _is_file_included(path, included_globs, excluded_path_strings):
                files_list.add(path)
            else:
                excluded_files.add(path)

    return files_list, excluded_files


def _is_file_included(path, included_globs, excluded_path_strings, enforce_glob=True):
    """Determine if a file should be included based on filename"""
    if not (_matches_glob_list(path, included_globs) or not enforce_glob):
        return False
    return not (
        _matches_glob_list(path, excluded_path_strings)
        or any(x in path for x in excluded_path_strings)
    )


def _matches_glob_list(filename, glob_list):
    """Check if filename matches any glob in the list"""
    return any(fnmatch.fnmatch(filename, glob) for glob in glob_list)


def _compare_baseline_results(baseline, results):
    """Compare a baseline list of issues to list of results"""
    return [a for a in results if a not in baseline]


def _find_candidate_matches(unmatched_issues, results_list):
    """Returns a dictionary with issue candidates"""
    return collections.OrderedDict(
        (unmatched, [i for i in results_list if unmatched == i])
        for unmatched in unmatched_issues
    )


def _parse_nosec_comment(comment):
    """Parse nosec comment to extract test IDs"""
    found_no_sec_comment = NOSEC_COMMENT.search(comment)
    if not found_no_sec_comment:
        return None

    nosec_tests = found_no_sec_comment.groupdict().get("tests", set())
    if not nosec_tests:
        return set()

    return {test.group(1) for test in NOSEC_COMMENT_TESTS.finditer(nosec_tests)}

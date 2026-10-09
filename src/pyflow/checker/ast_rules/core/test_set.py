# Security test set management
import logging
import sys
from . import test_properties
from . import test_loader

LOG = logging.getLogger(__name__)


class SecurityTestSet:
    def __init__(self, config, profile):
        self.config = config
        self.profile = profile
        self.tests = {}
        self.test_configs = {}
        self.load_errors = []
        self._load_tests()

    def _load_tests(self):
        """Load all available security tests"""
        loader = test_loader.TestLoader()
        loader.load_tests(self)

    def get_tests(self, checktype):
        """Get tests for a specific check type"""
        return self.tests.get(checktype, [])

    def add_test(self, test_func):
        """Add a test function to the test set"""
        if not hasattr(test_func, "_checks"):
            return
        identifiers = {test_func.__name__, getattr(test_func, "_test_id", "")}
        if identifiers.intersection(self.profile.get("exclude", ())):
            return
        included = self.profile.get("include", ())
        if included and not identifiers.intersection(included):
            return
        if hasattr(test_func, "_takes_config"):
            name = test_func._takes_config
            configuration = self.config.get_option(name)
            if configuration is None:
                module = sys.modules.get(test_func.__module__)
                factory = getattr(module, "gen_config", None)
                configuration = factory(name) if factory is not None else {}
            self.test_configs[test_func] = configuration or {}

        for check_type in test_func._checks:
            if check_type not in self.tests:
                self.tests[check_type] = []
            self.tests[check_type].append(test_func)

    def get_config(self, test_func):
        return self.test_configs[test_func]

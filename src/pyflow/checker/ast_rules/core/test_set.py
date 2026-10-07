# Security test set management
import logging
from . import test_properties
from . import test_loader

LOG = logging.getLogger(__name__)


class SecurityTestSet:
    def __init__(self, config, profile):
        self.config = config
        self.profile = profile
        self.tests = {}
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

        for check_type in test_func._checks:
            if check_type not in self.tests:
                self.tests[check_type] = []
            self.tests[check_type].append(test_func)

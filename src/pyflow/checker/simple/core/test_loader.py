# Test loader for security checkers
import importlib
import logging
import os
import pkgutil

LOG = logging.getLogger(__name__)


class TestLoader:
    def __init__(self):
        self.tests = {}

    def load_tests(self, test_set):
        """Load all available security tests"""
        # Import all checker modules
        checker_package = "pyflow.checker.simple.checkers"

        try:
            package = importlib.import_module(checker_package)
            package_path = package.__path__

            for importer, modname, ispkg in pkgutil.iter_modules(
                package_path, checker_package + "."
            ):
                try:
                    module = importlib.import_module(modname)
                    self._extract_tests_from_module(module, test_set)
                except Exception as e:
                    LOG.warning("Failed to load checker module %s: %s", modname, e)

        except Exception as e:
            LOG.warning("Failed to load checker package: %s", e)

    def _extract_tests_from_module(self, module, test_set):
        """Extract test functions from a module"""
        for name in dir(module):
            obj = getattr(module, name)
            if callable(obj) and hasattr(obj, "_checks"):
                test_set.add_test(obj)
                LOG.debug("Loaded test: %s", name)

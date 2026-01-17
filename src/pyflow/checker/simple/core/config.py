# Security checker configuration
class SecurityConfig:
    def __init__(self):
        self.options = {
            "exclude_dirs": [],
            "include": ["*.py"],
        }

    def get_option(self, key):
        """Get a configuration option"""
        return self.options.get(key)

    def set_option(self, key, value):
        """Set a configuration option"""
        self.options[key] = value

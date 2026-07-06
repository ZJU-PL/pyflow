"""
Paper #20 exercise: Class with multiple methods.

The analyzer extracts class methods as separate components
for assume-guarantee verification.

Target papers: #20
Expected: SAFE
"""


class Counter:
    def __init__(self, limit):
        self.limit = limit
        self.count = 0

    def increment(self):
        if self.count < self.limit:
            self.count += 1
        return self.count

    def reset(self):
        self.count = 0
        return self.count

    def is_at_limit(self):
        return self.count >= self.limit

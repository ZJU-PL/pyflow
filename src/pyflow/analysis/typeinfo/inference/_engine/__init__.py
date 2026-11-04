"""Internal implementation components of the static inference engine.

The solver owns these components and their shared inference state. Components
call related rules directly and use ``self.engine`` for state and other rules.
"""

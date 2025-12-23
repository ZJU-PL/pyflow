"""Python code output helper.

This module provides PythonOutput, a helper class for generating Python code
with proper indentation and formatting. It tracks indentation levels and
ensures empty blocks are filled with 'pass' statements.
"""

# A helper class that keeps track of the indentation level, etc.
class PythonOutput(object):
    """Helper class for generating Python code with proper formatting.
    
    PythonOutput manages indentation levels and ensures proper Python syntax
    when generating code. It tracks whether blocks have emitted statements
    and adds 'pass' statements to empty blocks.
    
    Attributes:
        out: Output stream to write to
        indent: Current indentation level (number of tabs)
        emitedStack: Stack tracking whether each block level has emitted statements
    """
    __slots__ = "out", "indent", "emitedStack"

    def __init__(self, out):
        """Initialize Python output helper.
        
        Args:
            out: Output stream (file-like object with write method)
        """
        self.out = out
        self.indent = 0
        self.emitedStack = [False]

    def emitStatement(self, stmt):
        """Emit a Python statement with proper indentation.
        
        Writes a statement with the current indentation level and marks
        the current block as having emitted a statement.
        
        Args:
            stmt: Statement string to emit
        """
        self.out.write("\t" * self.indent)
        self.out.write(stmt)
        self.newline()
        self.emitedStack[-1] = True

    def emitComment(self, text):
        """Emit a Python comment.
        
        Args:
            text: Comment text (without # prefix)
        """
        self.emitStatement("# " + str(text))

    def startBlock(self, stmt):
        """Start a new indented block (e.g., if, for, def).
        
        Emits the statement with colon and increases indentation.
        
        Args:
            stmt: Block header statement (e.g., "if x", "def f")
        """
        self.emitStatement(stmt + ":")
        self.indent += 1
        self.emitedStack.append(False)

    def endBlock(self):
        """End the current indented block.
        
        If the block is empty (no statements emitted), adds a 'pass' statement.
        Decreases indentation and pops the emitted stack.
        """
        if not self.emitedStack[-1]:
            self.emitStatement("pass")
        self.emitedStack.pop()
        self.indent -= 1

    def newline(self):
        """Emit a newline character."""
        self.out.write("\n")

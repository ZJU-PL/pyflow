"""
XML/HTML output utility with proper escaping and context management.

This module provides a convenient way to generate XML/HTML output with:
- Automatic escaping of special characters (&, <, >)
- Context managers for nested tags
- Operator overloading for concise syntax
- Tag stack tracking to ensure proper nesting

Usage:
    from xmloutput import XMLOutput
    
    with open("output.html", "w") as f:
        o = XMLOutput(f)
        with o.scope("html"):
            with o.scope("body"):
                o << "Hello, World!"
                o.endl()
"""

__all__ = ["XMLOutput"]

import re

# Lookup table for XML character escaping
# Note: converting line breaks to break tags is a bit of a hack for HTML output
xmlLUT = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "\n": "<br/>"}
xmlRE = re.compile("[%s]" % "".join(xmlLUT.keys()))


def convert(match):
    """
    Convert a matched character to its XML-escaped equivalent.
    
    Args:
        match: Regex match object
        
    Returns:
        str: Escaped character
    """
    return xmlLUT.get(match.group(0), "ERROR")


def content(s):
    """
    Escape special XML characters in a string.
    
    Args:
        s: String to escape
        
    Returns:
        str: Escaped string safe for XML/HTML output
    """
    return xmlRE.sub(convert, str(s))


class xmlscope(object):
    """
    Context manager for nested XML tags.
    
    This class enables nested tag scopes using Python's 'with' statement.
    It maintains a parent chain to ensure proper tag nesting.
    """
    __slots__ = "out", "name", "kargs", "parent"

    def __init__(self, out, name, kargs, parent=None):
        """
        Initialize a scope context manager.
        
        Args:
            out: XMLOutput instance to write to
            name: Tag name
            kargs: Tag attributes as keyword arguments
            parent: Parent scope (for nesting)
        """
        self.out = out
        self.name = name
        self.kargs = kargs
        self.parent = parent

    def __enter__(self):
        """Enter the scope: open the tag (and parent tags if any)."""
        if self.parent:
            self.parent.__enter__()
        self.out.begin(self.name, **self.kargs)
        return self

    def __exit__(self, type, value, tb):
        """Exit the scope: close the tag (and parent tags if any)."""
        self.out.end(self.name)
        if self.parent:
            self.parent.__exit__(type, value, tb)

    def scope(self, s, **kargs):
        """
        Create a nested scope within this scope.
        
        Args:
            s: Tag name for nested scope
            **kargs: Tag attributes
            
        Returns:
            xmlscope: New nested scope
        """
        return xmlscope(self.out, s, kargs, self)


class XMLOutput(object):
    """
    A utility class for generating XML/HTML output with proper escaping.
    
    Provides methods for writing tags, content, and managing tag nesting.
    Supports operator overloading for concise syntax:
    - o << "text"  : Write escaped text
    - o += "tag"   : Begin a tag
    - o -= "tag"   : End a tag
    """
    def __init__(self, f):
        """
        Initialize XMLOutput with a file-like object.
        
        Args:
            f: File-like object to write to (must have write() method)
        """
        self.f = f
        self.tagStack = []  # Track open tags for validation

    def close(self):
        """Close the output (sets file to None)."""
        self.f = None

    def __lshift__(self, s):
        """
        Operator overload: o << "text" writes escaped text.
        
        Args:
            s: String to write (will be escaped)
            
        Returns:
            self: For method chaining
        """
        return self.write(s)

    def __iadd__(self, s):
        """
        Operator overload: o += "tag" begins a tag.
        
        Args:
            s: Tag name
            
        Returns:
            self: For method chaining
        """
        return self.begin(s)

    def __isub__(self, s):
        """
        Operator overload: o -= "tag" ends a tag.
        
        Args:
            s: Tag name
            
        Returns:
            self: For method chaining
        """
        return self.end(s)

    def __out(self, s):
        """
        Internal method to write raw output.
        
        Args:
            s: String to write (not escaped)
        """
        self.f.write(s)

    def write(self, s):
        """
        Write escaped text content.
        
        Args:
            s: String to write (will be XML-escaped)
            
        Returns:
            self: For method chaining
        """
        self.__out(content(s))
        return self

    def tag(self, s, **kargs):
        """
        Write a self-closing tag.
        
        Args:
            s: Tag name
            **kargs: Tag attributes
            
        Returns:
            self: For method chaining
            
        Example:
            o.tag("br")  # <br />
            o.tag("img", src="image.png")  # <img src="image.png" />
        """
        if kargs:
            args = " ".join(['%s="%s"' % (k, v) for k, v in kargs.items()])
            self.__out("<%s %s />" % (s, args))
        else:
            self.__out("<%s />" % s)
        return self

    def begin(self, s, **kargs):
        """
        Begin an opening tag.
        
        Args:
            s: Tag name
            **kargs: Tag attributes
            
        Returns:
            self: For method chaining
            
        Example:
            o.begin("div", class="container")  # <div class="container">
        """
        if kargs:
            args = " ".join(['%s="%s"' % (k, v) for k, v in kargs.items()])
            self.__out("<%s %s>" % (s, args))
        else:
            self.__out("<%s>" % s)
        self.tagStack.append(s)  # Track for validation
        return self

    def end(self, s):
        """
        End a closing tag (must match the most recent begin()).
        
        Args:
            s: Tag name (must match the tag opened by the last begin())
            
        Returns:
            self: For method chaining
            
        Raises:
            AssertionError: If tag doesn't match the expected closing tag
        """
        matched = self.tagStack.pop()
        assert s == matched, 'Ending tag "%s" does not match begining tag "%s".' % (
            s,
            matched,
        )
        self.__out("</%s>" % s)
        return self

    def scope(self, s, **kargs):
        """
        Create a context manager for a tag scope.
        
        Args:
            s: Tag name
            **kargs: Tag attributes
            
        Returns:
            xmlscope: Context manager for use with 'with' statement
            
        Example:
            with o.scope("html"):
                with o.scope("body"):
                    o << "Content"
        """
        return xmlscope(self, s, kargs)

    def endl(self):
        """
        Write a newline character.
        
        Returns:
            self: For method chaining
        """
        self.__out("\n")
        return self

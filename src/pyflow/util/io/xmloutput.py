

"""
XML output utilities for PyFlow.

Provides classes and functions for generating XML output with proper
escaping and convenient methods for building XML structures.
"""
__all__ = ["XMLOutput"]

import re

# XML character escaping lookup table
# Note: converting line breaks to break tags is a bit of a hack.
xmlLUT = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "\n": "<br/>"}
xmlRE = re.compile("[%s]" % "".join(xmlLUT.keys()))


def convert(match):
    """
    Convert a matched character to its XML-escaped representation.
    
    Args:
        match: Regular expression match object
        
    Returns:
        Escaped XML string for the matched character
    """
    return xmlLUT.get(match.group(0), "ERROR")


def content(s):
    """
    Escape special XML characters in a string.
    
    Escapes ampersands, less-than, greater-than, and converts
    newlines to <br/> tags.
    
    Args:
        s: String to escape (will be converted to string if not already)
        
    Returns:
        XML-safe escaped string
    """
    return xmlRE.sub(convert, str(s))


class xmlscope(object):
    """
    Context manager for nested XML scopes.
    
    Allows using Python's 'with' statement to create nested XML elements
    with proper opening and closing tags. Supports nested scopes through
    a parent reference.
    """
    __slots__ = "out", "name", "kargs", "parent"

    def __init__(self, out, name, kargs, parent=None):
        """
        Initialize an XML scope context manager.
        
        Args:
            out: XMLOutput instance to write to
            name: XML tag name
            kargs: Attributes for the XML tag
            parent: Optional parent xmlscope for nesting
        """
        self.out = out
        self.name = name
        self.kargs = kargs
        self.parent = parent

    def __enter__(self):
        """Enter the context, opening the XML tag."""
        if self.parent:
            self.parent.__enter__()
        self.out.begin(self.name, **self.kargs)

    def __exit__(self, type, value, tb):
        """Exit the context, closing the XML tag."""
        self.out.end(self.name)
        if self.parent:
            self.parent.__exit__(type, value, tb)

    def scope(self, s, **kargs):
        """
        Create a nested scope within this scope.
        
        Args:
            s: XML tag name for the nested scope
            **kargs: Attributes for the nested XML tag
            
        Returns:
            New xmlscope instance as a child of this scope
        """
        return xmlscope(self.out, s, kargs, self)


class XMLOutput(object):
    """
    XML output writer with convenient methods and operator overloads.
    
    Provides methods for writing XML tags, attributes, and content with
    automatic escaping. Tracks tag nesting to ensure proper closing.
    Supports operator overloads for convenience: << for writing, += for begin, -= for end.
    """
    def __init__(self, f):
        """
        Initialize XMLOutput with a file object.
        
        Args:
            f: File object to write XML to (must support write() method)
        """
        self.f = f
        self.tagStack = []

    def close(self):
        """Close the output by clearing the file reference."""
        self.f = None

    def __lshift__(self, s):
        """
        Operator overload: xml << "text" writes escaped text.
        
        Args:
            s: String to write (will be XML-escaped)
            
        Returns:
            Self for method chaining
        """
        return self.write(s)

    def __iadd__(self, s):
        """
        Operator overload: xml += "tag" opens a tag.
        
        Args:
            s: XML tag name to open
            
        Returns:
            Self for method chaining
        """
        return self.begin(s)

    def __isub__(self, s):
        """
        Operator overload: xml -= "tag" closes a tag.
        
        Args:
            s: XML tag name to close
            
        Returns:
            Self for method chaining
        """
        return self.end(s)

    def __out(self, s):
        """Internal method to write raw string to the file."""
        self.f.write(s)

    def write(self, s):
        """
        Write escaped text content.
        
        XML-escapes special characters before writing.
        
        Args:
            s: Text content to write (will be escaped)
            
        Returns:
            Self for method chaining
        """
        self.__out(content(s))
        return self

    def tag(self, s, **kargs):
        """
        Write a self-closing XML tag.
        
        Args:
            s: XML tag name
            **kargs: Tag attributes as keyword arguments
            
        Returns:
            Self for method chaining
            
        Example:
            xml.tag("br")
            xml.tag("img", src="image.png", alt="Image")
        """
        if kargs:
            args = " ".join(['%s="%s"' % (k, v) for k, v in kargs.items()])
            self.__out("<%s %s />" % (s, args))
        else:
            self.__out("<%s />" % s)
        return self

    def begin(self, s, **kargs):
        """
        Begin an XML tag (open tag, push to stack).
        
        Args:
            s: XML tag name
            **kargs: Tag attributes as keyword arguments
            
        Returns:
            Self for method chaining
            
        Example:
            xml.begin("div", class="container")
        """
        if kargs:
            args = " ".join(['%s="%s"' % (k, v) for k, v in kargs.items()])
            self.__out("<%s %s>" % (s, args))
        else:
            self.__out("<%s>" % s)
        self.tagStack.append(s)
        return self

    def end(self, s):
        """
        End an XML tag (close tag, pop from stack).
        
        Verifies that the tag being closed matches the most recently
        opened tag to catch nesting errors.
        
        Args:
            s: XML tag name to close (must match most recent begin)
            
        Returns:
            Self for method chaining
            
        Raises:
            AssertionError: If the tag doesn't match the expected closing tag
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
        Create a scope context manager for nested XML tags.
        
        Allows using 'with' statement for nested tags:
            with xml.scope("div", class="container"):
                xml.write("Content")
        
        Args:
            s: XML tag name
            **kargs: Tag attributes as keyword arguments
            
        Returns:
            xmlscope context manager instance
        """
        return xmlscope(self, s, kargs)

    def endl(self):
        """
        Write a newline character.
        
        Returns:
            Self for method chaining
        """
        self.__out("\n")
        return self

"""
Standardizes whitespace formatting for all Python source files in a directory.

This script performs the following formatting operations:
- Removes trailing whitespace from lines
- Removes trailing newlines at end of file
- Converts space-based indentation to tabs (when consistent)
- Detects and reports inconsistent indentation (mixing spaces and tabs)
- Normalizes line endings

Usage:
    python format.py [options]

Options:
    -d DIR: Root directory to process (default: current directory)
    -n: Dry run mode (don't write changes)
    --multiline-ok: Don't abort on multiline strings
    --convert-tabs: Convert space indentation to tabs when consistent
    -t TYPE: File type filter (default: py)
    -f FILTER: File name filter (regex)
    -g FILTER: Exclude file name filter (regex)
"""

import os.path
import optparse
import re


def check_directory(option, opt_str, value, parser):
    """
    Validate that the provided directory path exists.
    
    Args:
        option: The option object
        opt_str: The option string (e.g., '-d')
        value: The directory path
        parser: The option parser instance
        
    Raises:
        optparse.OptionValueError: If the directory does not exist
    """
    if not os.path.exists(value):
        raise optparse.OptionValueError("directory %r does not exist" % value)
    setattr(parser.values, option.dest, value)


def buildParser():
    """
    Build and configure the command-line option parser.
    
    Returns:
        optparse.OptionParser: Configured parser with all options
    """
    usage = "usage: %prog [options] textfilters"
    parser = optparse.OptionParser(usage)

    group = optparse.OptionGroup(parser, "Global Configuration")
    group.add_option(
        "-d",
        dest="directory",
        action="callback",
        type="string",
        callback=check_directory,
        default=".",
        help="the root directory",
    )
    group.add_option(
        "-n",
        dest="dryrun",
        action="store_true",
        default=False,
        help="modifications are not written to disk",
    )

    group.add_option(
        "--multiline-ok",
        dest="multiline_ok",
        action="store_true",
        default=False,
        help="don't abort if a multiline string is found",
    )
    group.add_option(
        "--convert-tabs",
        dest="convert_tabs",
        action="store_true",
        default=False,
        help="convert spacetabs if reasonably certain about the spacing",
    )

    parser.add_option_group(group)

    group = optparse.OptionGroup(parser, "File Filters")
    group.add_option(
        "-t",
        dest="filetypes",
        action="append",
        default=[],
        help="matches the file type",
        metavar="TYPE",
    )
    group.add_option(
        "-f",
        dest="filefilters",
        action="append",
        default=[],
        help="matches the file name",
        metavar="FILTER",
    )
    group.add_option(
        "-g",
        dest="excludefilefilters",
        action="append",
        default=[],
        help="excludes file name",
        metavar="FILTER",
    )
    parser.add_option_group(group)

    return parser


class CascadingMatcher(object):
    """
    A matcher that applies multiple positive and negative patterns.
    
    A string matches if it matches all positive patterns and none of the
    negative patterns.
    """
    def __init__(self):
        """Initialize an empty matcher with no patterns."""
        self.positivePatterns = []
        self.negativePatterns = []

    def require(self, p):
        """
        Add a required (positive) pattern.
        
        Args:
            p: Compiled regex pattern that must match
        """
        self.positivePatterns.append(p)

    def exclude(self, p):
        """
        Add an exclusion (negative) pattern.
        
        Args:
            p: Compiled regex pattern that must not match
        """
        self.negativePatterns.append(p)

    def matches(self, s):
        """
        Check if a string matches all requirements.
        
        Args:
            s: String to test
            
        Returns:
            bool: True if matches all positive patterns and no negative patterns
        """
        for p in self.positivePatterns:
            if not p.search(s):
                return False

        for p in self.negativePatterns:
            if p.search(s):
                return False

        return True


# Regex to find string/comment markers: #, escaped quotes, triple quotes, or quotes
stringMarkers = re.compile(r'#|\\[\\\'"]|\'\'\'|"""|[\'"]')
# Regex to match line continuation (backslash at end of line)
lineBreak = re.compile("\\\s*$")


class StringTracker(object):
    """
    Tracks whether we're currently inside a string literal.
    
    This is used to avoid modifying indentation inside string literals,
    which could break the code.
    """
    def __init__(self):
        """Initialize tracker - not in any string."""
        self.current = None  # Current string delimiter (None, '"', "'", '"""', "'''")

    def handleLine(self, line):
        """
        Process a line and update string state based on markers found.
        
        Args:
            line: Line of code to process
        """
        markers = stringMarkers.findall(line)
        for marker in markers:
            text = marker

            if self.current is None:
                # Not in a string - check what we found
                if text == "#":
                    # Comment starts - stop processing (comments can't contain strings)
                    break
                elif text == "\\\\":
                    # Escaped backslash - ignore
                    pass
                elif text[0] == "\\":
                    # Escaped quote - shouldn't happen outside string
                    assert False, "unescaped quote outside of a string?"
                else:
                    # Entering a string
                    self.current = text
            elif self.current == text:
                # Found matching closing delimiter
                self.current = None

        # Triple-quoted strings must span multiple lines
        if self.current and not lineBreak.search(line):
            assert self.current != '"' and self.current != "'", (line, markers)

    def inString(self):
        """
        Check if currently inside a string literal.
        
        Returns:
            bool: True if inside a string
        """
        return self.current is not None


def countSpaces(line):
    """
    Count leading spaces and detect tab/space mixing.
    
    Args:
        line: Line to analyze
        
    Returns:
        tuple: (count, inconsistent) where count is number of leading spaces
               and inconsistent is True if tabs are found mixed with spaces
    """
    count = 0
    inconsistent = False

    for c in line:
        if c == " ":
            count += 1
        elif c == "\t":
            inconsistent = True
            break
        else:
            # Non-whitespace character - stop counting
            break
    return count, inconsistent


def convSpacetabs(lines, size):
    """
    Convert space-based indentation to tabs.
    
    Args:
        lines: List of lines to convert
        size: Number of spaces per tab (typically 4 or 8)
        
    Returns:
        list: Lines with spaces converted to tabs (only outside strings)
    """
    tracker = StringTracker()

    result = []

    for line in lines:
        startInString = tracker.inString()
        tracker.handleLine(line)

        # Only convert indentation if not inside a string
        if not startInString:
            count, inconsistent = countSpaces(line)
            assert not inconsistent  # Should have been caught earlier
            if count:
                # Verify indentation is multiple of tab size
                assert count % size == 0
                # Convert spaces to tabs
                line = "\t" * (count / size) + line.lstrip()

        result.append(line)

    return result


def handleFile(fn):
    """
    Process a single file: normalize whitespace and optionally convert to tabs.
    
    Args:
        fn: File path to process
        
    Returns:
        bool: True if file was modified, False otherwise
    """
    f = open(fn)

    tracker = StringTracker()

    # Track space-based indentation
    spacetabs = False  # Whether file uses space indentation
    spacetabRanges = []  # Line ranges with space indentation
    spacetabStart = -1  # Start of current space-indented block
    spacetabEnd = -1  # End of current space-indented block
    blockEnd = -1  # End of current indentation block (may extend past empty lines)

    tabtabs = False  # Whether file uses tab indentation

    def logSpacetabs():
        """Record the current space-indented block range."""
        if spacetabStart != -1:
            if spacetabStart == spacetabEnd:
                spacetabRanges.append(str(spacetabStart))
            else:
                spacetabRanges.append("%d-%d" % (spacetabStart, spacetabEnd))

    changed = False  # Whether file was modified
    inconsistent = False  # Whether indentation is inconsistent

    lines = []  # Buffer for processed lines

    eolMod = 0  # Count of end-of-line modifications

    title = False  # Whether filename has been printed

    spaceDist = {}  # Distribution of indentation levels (space counts)

    # Process each line
    for line in f:
        startInString = tracker.inString()
        tracker.handleLine(line)
        endInString = tracker.inString()

        # Normalize line endings (removes trailing whitespace, adds single newline)
        # Note: this implicitly fixes inconsistent newline characters.
        original = line
        newline = line.rstrip() + "\n"

        lineNo = len(lines) + 1

        # Fix end-of-line whitespace (unless in multiline string)
        if not endInString or options.multiline_ok:
            if line != newline:
                if not title:
                    print(fn)
                    title = True
                print("EOL MOD", len(lines) + 1, repr(line))
                eolMod += 1
                changed = True
                line = newline

        # Analyze indentation (only outside strings)
        if not startInString:
            if newline[0] == " ":
                # Space-based indentation
                spacetabs = True
                count, lineInconsistent = countSpaces(newline)
                inconsistent |= lineInconsistent

                spaceDist[count] = spaceDist.get(count, 0) + 1
                # Track contiguous blocks of space-indented lines
                if blockEnd + 1 != lineNo:
                    logSpacetabs()
                    spacetabStart = lineNo
                spacetabEnd = lineNo
                blockEnd = lineNo
            elif newline[0] == "\t":
                # Tab-based indentation
                tabtabs = True
            else:
                # Empty line or no indentation - extend block if adjacent
                if blockEnd + 1 == lineNo:
                    blockEnd = lineNo  # Extend blocks past empty lines.

        lines.append(line)

    logSpacetabs()

    # Remove trailing newlines at end of file
    eofLines = False
    while lines and lines[-1] == "\n":
        lines.pop()
        changed = True
        eofLines = True

    if eofLines:
        if not title:
            print(fn)
            title = True
        print("EOF NEWLINES")

    # Analyze and convert space indentation if present
    if spacetabs:
        counts = list(spaceDist.keys())
        counts.sort()

        # Determine tab size (8, 4, or inconsistent)
        clean8 = all([c % 8 == 0 for c in counts])
        clean4 = all([c % 4 == 0 for c in counts])

        if clean8:
            sizeStr = "8"
            size = 8
        elif clean4:
            sizeStr = "4"
            size = 4
        else:
            sizeStr = "wierd"
            size = 0

        # Mixing tabs and spaces is inconsistent
        inconsistent |= tabtabs
        # Check if indentation follows standard pattern (4, 8, 12, ... or 8, 16, 24, ...)
        if size:
            for i, count in enumerate(counts):
                if count != (i + 1) * size:
                    inconsistent = True
                    break

        if inconsistent:
            sizeStr += "?"

        if not title:
            print(fn)
            title = True

        if inconsistent or not size:
            # Can't safely convert - warn user
            print("WARNING: spacetabs (%s)" % sizeStr, counts)
            print("lines", ",".join(spacetabRanges))
        else:
            # Safe to convert
            print("converting spacetabs (%d)" % size)
            lines = convSpacetabs(lines, size)
            changed = True

    f.close()

    if changed and not options.dryrun:
        f = open(fn, "w")
        for line in lines:
            f.write(line)
        f.close()

    if title:
        print
        return True
    else:
        return False


def run(dir, fileMatcher):
    """
    Walk a directory tree and process all matching files.
    
    Args:
        dir: Root directory to walk
        fileMatcher: CascadingMatcher instance to filter files
    """
    for path, dirs, files in os.walk(dir):
        for fn in files:
            fullname = os.path.join(path, fn)
            if fileMatcher.matches(fullname):
                handleFile(fullname)


def fileTypeExpression(options):
    """
    Build a regex pattern for matching file extensions.
    
    Args:
        options: Parsed command-line options
        
    Returns:
        str: Regex pattern matching the specified file types
    """
    # default filetype
    if not options.filetypes:
        options.filetypes.append("py")

    if len(options.filetypes) > 1:
        # Multiple extensions: create alternation pattern
        tf = "\.(%s)$" % "|".join(options.filetypes)
    else:
        # Single extension: simple pattern
        tf = "\.%s$" % options.filetypes[0]

    return tf


def makeFileMatcher(options, flags):
    """
    Build a file matcher from command-line options.
    
    Args:
        options: Parsed command-line options
        flags: Regex flags to use (e.g., re.I for case-insensitive)
        
    Returns:
        CascadingMatcher: Configured matcher for filtering files
    """
    fileMatcher = CascadingMatcher()

    # Match the filetype
    tf = fileTypeExpression(options)

    print("+file: %s" % tf)
    fileMatcher.require(re.compile(tf, flags))

    # Match the full file name (positive filters)
    for ff in options.filefilters:
        print("+file: %s" % ff)
        fileMatcher.require(re.compile(ff, flags))

    # Antimatch the full file name (negative filters)
    for ff in options.excludefilefilters:
        print("-file: %s" % ff)
        fileMatcher.exclude(re.compile(ff, flags))

    return fileMatcher


parser = buildParser()
options, args = parser.parse_args()

fileMatcher = makeFileMatcher(options, 0)
print

run(options.directory, fileMatcher)

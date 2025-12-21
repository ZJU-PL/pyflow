"""
A grep-like tool for searching and replacing text in files with advanced filtering.

This script provides a flexible grep utility that supports:
- File type and name filtering
- Text pattern matching with regular expressions
- Text replacement operations
- Case-insensitive matching
- Comment-aware searching (can ignore comments)
- Identifier-specific matching
- Dry-run mode for testing changes

Usage:
    python grep.py [options] textfilters

Examples:
    # Find all occurrences of 'import' in Python files
    python grep.py -d src "import"
    
    # Replace 'old_name' with 'new_name' in identifiers
    python grep.py --idr old_name new_name
    
    # Search only in imports
    python grep.py --import "from.*import"
"""

import os
import os.path

import optparse
import sys

import re


def check_directory(option, opt_str, value, parser):
	"""
	Callback function to validate that a directory path exists.
	
	Args:
		option: The option object
		opt_str: The option string (e.g., '-d')
		value: The directory path provided by the user
		parser: The option parser instance
		
	Raises:
		optparse.OptionValueError: If the directory does not exist
	"""
	if not os.path.exists(value):
		raise optparse.OptionValueError("directory %r does not exist" % value)
	setattr(parser.values, option.dest, value)

def replacesIDCallback(option, opt, value, parser):
	"""
	Callback function for --idr option to replace identifiers.
	
	Converts the match pattern to an identifier matcher and adds it to the
	replacement filters list.
	
	Args:
		option: The option object
		opt: The option string (e.g., '--idr')
		value: A tuple of (match_pattern, replace_string)
		parser: The option parser instance
	"""
	match, replace = value
	match = makeIDMatcher(match)

	parser.values.replaces.append((match, replace))

def matchIDCallback(option, opt, value, parser):
	"""
	Callback function for --id option to match identifiers.
	
	Converts the pattern to an identifier matcher and adds it to the
	text filters list.
	
	Args:
		option: The option object
		opt: The option string (e.g., '--id')
		value: The identifier pattern to match
		parser: The option parser instance
	"""
	parser.largs.append(makeIDMatcher(value))

def buildParser():
	"""
	Build and configure the command-line option parser.
	
	Returns:
		optparse.OptionParser: Configured parser with all options and groups
	"""
	usage = "usage: %prog [options] textfilters"
	parser = optparse.OptionParser(usage)

	group = optparse.OptionGroup(parser, "Global Configuration")
	group.add_option('-d', dest='directory',   action='callback',  type='string',  callback=check_directory,  default='.', help="the root directory")
	group.add_option('-i', dest='insensitive', action='store_true', default=False, help="filters are case insensitive")
	group.add_option('-n', dest='dryrun', action='store_true', default=False, help="modifications are not written to disk")

	group.add_option('--no-comments', dest='nocomments', action='store_true', default=False, help="text filters ignore comments")
	parser.add_option_group(group)

	group = optparse.OptionGroup(parser, "File Filters")
	group.add_option('-t', dest='filetypes', action='append', default=[], help="matches the file type", metavar="TYPE")
	group.add_option('-f', dest='filefilters', action='append', default=[], help="matches the file name", metavar="FILTER")
	group.add_option('-g', dest='excludefilefilters', action='append', default=[], help="excludes file name", metavar="FILTER")
	parser.add_option_group(group)

	group = optparse.OptionGroup(parser, "Text Filters")
	group.add_option('--id', dest='identifiers', action='callback', callback=matchIDCallback, type="str", metavar="FILTER", help="specialized text filter to find an identifier")

	group.add_option('-x', dest='excludes', action='append', default=[], help="excludes matching text", metavar="FILTER")
	group.add_option('--import', dest='imports', action='store_true', default=False, help="restricts search to imports")

	group.add_option('-r', dest='replaces', action='append', default=[], help="replaces matching text", nargs=2, metavar="MATCH SUB")
	group.add_option('--idr', dest='replaces', action='callback', callback=replacesIDCallback, help="replaces matching identifier", type='str', nargs=2, metavar="MATCH SUB")

	parser.add_option_group(group)

	return parser


def fileMatches(filename):
	"""
	Check if a filename matches all file filters and none of the exclude filters.
	
	Args:
		filename: The file path to check
		
	Returns:
		bool: True if the file matches all positive filters and no negative filters
	"""
	for f in fileFilters:
		if not f.search(filename):
			return False

	for f in excludeFileFilters:
		if f.search(filename):
			return False
	return True

def textMatches(text):
	"""
	Check if text matches all text filters and none of the exclude filters.
	
	Args:
		text: The text line to check
		
	Returns:
		bool: True if the text matches all positive filters and no negative filters
	"""
	for f in textFilters:
		if not f.search(text):
			return False

	for f in excludeFilters:
		if f.search(text):
			return False

	return True

def textReplace(text):
	"""
	Apply all replacement filters to the given text.
	
	Args:
		text: The text to process
		
	Returns:
		str: The text with all replacements applied
	"""
	for r, s in replaceFilters:
		text = r.sub(s, text)
	return text

def replaceActive():
	"""
	Check if any replacement filters are configured.
	
	Returns:
		bool: True if there are any replacement filters active
	"""
	return bool(replaceFilters)

def makeCommentRE():
	"""
	Create a regular expression to match and split Python code from comments.
	
	This regex handles:
	- Single and double quoted strings (with escape sequences)
	- Comments starting with #
	- Code before comments
	
	Note: This implementation cannot properly handle multi-line strings that
	span multiple lines (triple-quoted strings on a single line are handled).
	
	Returns:
		re.Pattern: Compiled regex that matches a line and captures (code, comment)
	"""
	# Match non-quote, non-comment characters
	simple       = r'[^\'"#]+'
	# Match double-quoted strings (handles escapes and line continuations)
	doubleQuoted = r'(?:"(?:[^"\\]|\\.|\\$)*(?:"|$))'
	# Match single-quoted strings (handles escapes and line continuations)
	singleQuoted = r"(?:'(?:[^'\\]|\\.|\\$)*(?:'|$))"
	# Match any combination of code and strings (but not comments)
	notComment   = r"(?:%s|%s|%s)+" % (simple, singleQuoted, doubleQuoted)

	# Match comments (everything after #)
	comment      = r"(?:#\s*(.+)?)"

	return re.compile(r"^(%s)?%s?$" % (notComment, comment))

commentRE = makeCommentRE()


def splitLine(line):
	"""
	Split a line into code and comment parts.
	
	Args:
		line: A line of Python source code
		
	Returns:
		list: A list containing [code_part, comment_part], where empty strings
		      are used if a part doesn't exist
	"""
	match = commentRE.match(line)
	assert match is not None, line
	return [('' if group==None else group.strip()) for group in match.groups()]



class StandardGrep(object):
	"""
	A grep-like tool for searching and replacing text in files.
	
	This class handles the core logic of:
	- Walking directory trees
	- Filtering files by name/type
	- Matching text patterns
	- Replacing text when requested
	- Tracking statistics about matches and changes
	"""
	def __init__(self, matchText):
		"""
		Initialize a StandardGrep instance.
		
		Args:
			matchText: If True, perform text matching; if False, only list files
		"""
		self.matchText = matchText
		# Statistics counters
		self.files = 0
		self.lines = 0
		self.occurances = 0
		self.fileOccurances = 0

		self.linesChanged = 0
		self.filesChanged = 0

		self.lastFile = None  # Track last file printed for formatting

	def displayMatch(self, fn, lineno, line):
		"""
		Display a matching line with file name and line number.
		
		Args:
			fn: The filename
			lineno: The line number
			line: The line content
		"""
		if fn != self.lastFile:
			if self.lastFile is not None:
				print()
			print(fn)
			self.lastFile = fn
		print("%d\t%s" % (lineno, line.strip()))

		self.occurances += 1

	def displayReplace(self, line, newline):
		"""
		Display a replacement operation showing the original and new line.
		
		Args:
			line: The original line
			newline: The line after replacement
		"""
		print("  ->\t%s" % (newline.strip(),))


	def handleLine(self, fn, lineno, line):
		"""
		Process a single line: check for matches and apply replacements if needed.
		
		Args:
			fn: The filename
			lineno: The line number
			line: The line content
		"""
		# Split line into code and comment parts
		code, comment =  splitLine(line)
		if code: self.lines += 1

		# Choose whether to match against code only or entire line
		if options.nocomments:
			matchline = code
		else:
			matchline = line

		matched = textMatches(matchline)

		self.matched |= matched

		if replaceActive():
			# Replacement mode: apply replacements and buffer lines
			if matched:
				newline = textReplace(line)
				if newline != line:
					self.callback(fn, lineno, line)
					self.displayReplace(line, newline)

					self.changed = True
					line = newline
					self.linesChanged += 1

			if not options.dryrun:
				self.lineBuffer.append(line)

		else:
			# Search mode: just display matches
			if matched:
				self.callback(fn, lineno, line)


	def handleFile(self, fn):
		"""
		Process a single file: read, match/replace, and optionally write back.
		
		Args:
			fn: The file path to process
		"""
		if self.matchText:
			# Read and process file line by line
			fh = open(fn)
			lineno = 1

			self.lineBuffer = []  # Buffer for replacement mode
			self.changed    = False  # Track if file was modified
			self.matched    = False  # Track if any matches found

			for line in fh:
				self.handleLine(fn, lineno, line)
				lineno += 1
			fh.close()

			if self.matched:
				self.fileOccurances += 1

			# Write back changes if in replace mode and file was modified
			if replaceActive() and self.changed and not options.dryrun:
				text = "".join(self.lineBuffer)
				fh = open(fn, 'w')
				fh.write(text)
				fh.close()
				self.filesChanged += 1
		else:
			# Just list the filename if not matching text
			print(fn)

		self.files += 1

	def walk(self, dn, callback):
		"""
		Walk a directory tree and process all matching files.
		
		Args:
			dn: The root directory to walk
			callback: Function to call when a match is found (e.g., displayMatch)
		"""
		self.callback = callback

		# Recursively walk the directory tree
		for path, dirs, files in os.walk(dn):
			for f in files:
				fn = os.path.join(path, f)
				if fileMatches(fn):
					self.handleFile(fn)

		# Print final newline if we printed any files
		if self.lastFile != None:
			print()

		# Print statistics
		if self.matchText:
			print("%7d occurances in %d file%s." % (self.occurances, self.fileOccurances, 's' if self.fileOccurances != 1 else ''))
			print("%7d lines." % self.lines)
		print("%7d files." % self.files)

		if replaceActive():
			print("%7d lines rewritten." % self.linesChanged)
			print("%7d files changed." % self.filesChanged)

def makeIDMatcher(s):
	"""
	Create a regular expression pattern that matches identifiers (word boundaries).
	
	This function wraps a pattern with word boundary assertions to ensure it only
	matches complete identifiers, not substrings within identifiers.
	
	The lookaheads/lookbehinds ensure that the expression starts and ends either
	with a non-word character, or adjacent to one. This allows expressions that
	can match non-word characters to behave in a reasonable way.
	
	Note: There are subtle semantic differences between positive and negative
	lookaheads/lookbehinds. Primarily, negative versions can match at the end
	of strings.
	
	Args:
		s: The pattern string to wrap as an identifier matcher
		
	Returns:
		str: A regex pattern that matches the identifier with word boundaries
	"""
	return '(?:(?<!\w)|(?=\W))(?:%s)(?:(?!\w)|(?<=\W))' % (s,)

if __name__ == '__main__':
	# Optional performance optimization (commented out)
	try:
		pass
		#import psyco
		#psyco.full()
	except ImportError:
		pass

	# Parse command-line arguments
	parser = buildParser()
	options, args = parser.parse_args()

	# If --import option is set, prepend import pattern to text filters
	if options.imports:
		args.insert(0, "^\s*(import|from)\s")

	# Determine if we're matching text or just listing files
	matchText = True
	if len(args) < 1 and len(options.replaces) < 1:
		matchText = False

	parser.destroy()

	# Set up regex flags
	flags = 0
	if options.insensitive: flags |= re.I

	# Build the regular expressions for filtering

	print()

	fileFilters = []

	# Match the filetype (default to .py if not specified)
	if not options.filetypes:
		# default filetype
		options.filetypes.append('py')

	# Build filetype pattern (single extension or alternation)
	if len(options.filetypes) > 1:
		tf = '\.(%s)$' % '|'.join(options.filetypes)
	else:
		tf = '\.%s$' % options.filetypes[0]

	print("+file: %s" % tf)
	fileFilters.append(re.compile(tf, flags))

	# Match the full file name (positive filters)
	for ff in options.filefilters:
		print("+file: %s" % ff)
		fileFilters.append(re.compile(ff, flags))

	# Antimatch the full file name (negative filters)
	excludeFileFilters = []
	for ff in options.excludefilefilters:
		print("-file: %s" % ff)
		excludeFileFilters.append(re.compile(ff, flags))

	# Match the text (positive text filters)
	textFilters = []
	for tf in args:
		print("+text: %s" % tf)
		textFilters.append(re.compile(tf, flags))

	# Antimatch the text (negative text filters)
	excludeFilters = []
	for ef in options.excludes:
		print("-text: %s" % ef)
		excludeFilters.append(re.compile(ef, flags))

	# Replace the text (replacement filters)
	replaceFilters = []
	for rf in options.replaces:
		print("!repl: %s -> %s" % rf)
		replaceFilters.append((re.compile(rf[0], flags), rf[1]))

	print()

	directoryName = options.directory

	# Search the files.
	sg = StandardGrep(matchText)
	sg.walk(directoryName, sg.displayMatch)

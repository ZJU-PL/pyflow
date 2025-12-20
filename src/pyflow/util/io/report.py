"""
Report generation utilities.

Provides classes for building formatted tables and pie charts for
documentation and reporting purposes. Supports LaTeX table output
and Ploticus pie chart generation.
"""


def reindex(indexes, l):
    """
    Reorder elements of a list based on index mapping.
    
    Args:
        indexes: List of indices specifying the new order
        l: List to reorder
        
    Returns:
        New list with elements in the order specified by indexes
        
    Example:
        reindex([2, 0, 1], ['a', 'b', 'c']) -> ['c', 'a', 'b']
    """
    return [l[i] for i in indexes]


# AST node types for coloring in reports
asts = (
    "CopyLocal",
    "Call",
    "MethodCall",
    "DirectCall",
    "Load",
    "ILoad",
    "Store",
    "IStore",
    "Allocate",
    "Check",
    "Is",
)
# Colors corresponding to AST node types for visualization
astColors = (
    "pink",
    "red",
    "gray",
    "orange",
    "yellow",
    "gray",
    "green",
    "gray",
    "teal",
    "blue",
    "purple",
)


class TableBuilder(object):
    """
    Build and format tables with customizable columns and formats.
    
    Supports adding rows, setting format strings for columns, and
    outputting tables in various formats (plain text, LaTeX).
    """
    def __init__(self, *columns):
        """
        Initialize a TableBuilder with column names.
        
        Args:
            *columns: Variable number of column name strings
        """
        self.columns = columns
        self.formats = ["%s" for c in columns]

        self.rows = []

    def setFormats(self, *formats):
        """
        Set format strings for each column.
        
        Args:
            *formats: Format strings (e.g., "%d", "%.2f", "%s") for each column
                    Must match the number of columns
                    
        Raises:
            AssertionError: If number of formats doesn't match number of columns
        """
        assert len(formats) == len(self.columns)
        self.formats = formats

    def row(self, name, *values):
        """
        Add a row to the table.
        
        Args:
            name: Row name/identifier (typically used as first column in output)
            *values: Values for each column (must match number of columns)
            
        Raises:
            AssertionError: If number of values doesn't match number of columns
        """
        assert len(values) == len(self.columns), (values, self.columns)
        self.rows.append((name, values))

    def formatRow(self, name, values):
        """
        Format a row's values using the column format strings.
        
        Args:
            name: Row name
            values: List of values to format
            
        Returns:
            Tuple of (name, list of formatted value strings)
        """
        return name, [format % value for value, format in zip(values, self.formats)]

    def dump(self):
        """Print all rows to stdout in a simple text format."""
        for row in self.rows:
            name, data = self.formatRow(*row)
            print(name, data)

    def rewrite(self, *indexes):
        """
        Reorder columns based on index mapping.
        
        Reorders columns, formats, and all row data according to the
        specified index sequence.
        
        Args:
            *indexes: Indices specifying the new column order
        """
        self.columns = reindex(indexes, self.columns)
        self.formats = reindex(indexes, self.formats)
        self.rows = [(name, reindex(indexes, data)) for name, data in self.rows]

    def dumpLatex(self, f, label):
        """
        Output table in LaTeX format.
        
        Generates a LaTeX subfloat table suitable for inclusion in LaTeX documents.
        
        Args:
            f: File object to write LaTeX code to
            label: Label identifier for the table (used in \\label{fig:label})
        """
        print(r"\subfloat[\label{fig:%s}]{" % label, file=f)
        print(
            r"\begin{tabular}{|c|%s|}" % "|".join(["c" for name in self.columns]),
            file=f,
        )
        print(r"\cline{2-%d}" % (len(self.columns) + 1), file=f)
        print(
            r"\multicolumn{1}{c|}{} & %s"
            % " & ".join([r"\textbf{%s}" % name for name in self.columns]),
            file=f,
        )
        print(r"\tabularnewline \hline", file=f)

        for row in self.rows:
            name, data = self.formatRow(*row)
            print(r"\textbf{%s} & %s" % (name, " & ".join(data)), file=f)
            print(r"\tabularnewline \hline", file=f)

        print(r"\end{tabular}", file=f)
        print("}", file=f)


class PieBuilder(object):
    """
    Build pie charts for visualization using Ploticus format.
    
    Accumulates pie slices with labels, colors, and values, then
    outputs them in Ploticus script format for rendering.
    """
    template = """
#proc getdata
data:
%s

#proc pie
//firstslice: 90
//explode: .2 0 0 0 0  .2 0
datafield: 2
labelfield: 1
labelmode: line+label
//labelmode: labelonly
center: 2 2
radius: 1
colors: %s
labelfarout: 1.3
"""

    def __init__(self):
        """Initialize an empty PieBuilder."""
        self.slices = []

    def slice(self, label, color, value):
        """
        Add a slice to the pie chart.
        
        Args:
            label: Label text for this slice
            color: Color name for this slice (Ploticus color name)
            value: Numeric value for this slice
        """
        self.slices.append((label, color, value))

    def dumpPloticus(self, f):
        """
        Output pie chart in Ploticus script format.
        
        Generates a complete Ploticus script that can be rendered
        to produce a pie chart visualization.
        
        Args:
            f: File object to write Ploticus script to
        """
        data = "\n".join(["%s %r" % (slice[0], slice[2]) for slice in self.slices])
        colors = " ".join([slice[1] for slice in self.slices])

        print(self.template % (data, colors), file=f)

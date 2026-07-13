QUOTE_MINIMAL = 0
QUOTE_ALL = 1
QUOTE_NONNUMERIC = 2
QUOTE_NONE = 3


class Dialect:
    delimiter = ','
    doublequote = True
    escapechar = None
    lineterminator = '\r\n'
    quotechar = '"'
    quoting = QUOTE_MINIMAL
    skipinitialspace = False
    strict = False


class excel(Dialect):
    pass


class excel_tab(Dialect):
    delimiter = '\t'


class unix_dialect(Dialect):
    lineterminator = '\n'
    quoting = QUOTE_ALL


class DictReader:
    def __init__(self, f, fieldnames=None, restkey=None, restval=None,
                 dialect='excel', *args, **kwds):
        self._reader = reader(f, dialect, *args, **kwds)
        self._fieldnames = fieldnames
        self.restkey = restkey
        self.restval = restval
        self.line_num = 0
        self._file = f

    @property
    def fieldnames(self):
        if self._fieldnames is None:
            self._fieldnames = next(self._reader)
        return self._fieldnames

    @fieldnames.setter
    def fieldnames(self, value):
        self._fieldnames = value

    def __iter__(self):
        return self

    def __next__(self):
        row = next(self._reader)
        self.line_num = self._reader.line_num
        d = {}
        for i, field in enumerate(self.fieldnames):
            if i < len(row):
                d[field] = row[i]
            else:
                d[field] = self.restval
        if len(row) > len(self.fieldnames) and self.restkey is not None:
            d[self.restkey] = row[len(self.fieldnames):]
        return d


class DictWriter:
    def __init__(self, f, fieldnames, restval='', extrasaction='raise',
                 dialect='excel', *args, **kwds):
        self.fieldnames = fieldnames
        self.restval = restval
        self.extrasaction = extrasaction
        self._writer = writer(f, dialect, *args, **kwds)
        self._file = f

    def writeheader(self):
        self._writer.writerow(self.fieldnames)

    def writerow(self, rowdict):
        row = [rowdict.get(field, self.restval) for field in self.fieldnames]
        return self._writer.writerow(row)

    def writerows(self, rowdicts):
        for rowdict in rowdicts:
            self.writerow(rowdict)


class _Reader:
    def __init__(self, csvfile, dialect, **fmtparams):
        self._file = csvfile
        self._dialect = dialect
        self._params = fmtparams
        self.line_num = 0

    def __iter__(self):
        return self

    def __next__(self):
        line = next(self._file)
        self.line_num += 1
        delimiter = self._params.get('delimiter', ',')
        return line.strip().split(delimiter)


class _Writer:
    def __init__(self, csvfile, dialect, **fmtparams):
        self._file = csvfile
        self._dialect = dialect
        self._params = fmtparams

    def writerow(self, row):
        delimiter = self._params.get('delimiter', ',')
        line = delimiter.join(str(item) for item in row)
        self._file.write(line + '\n')
        return len(line) + 1

    def writerows(self, rows):
        for row in rows:
            self.writerow(row)


def reader(csvfile, dialect='excel', **fmtparams):
    return _Reader(csvfile, dialect, **fmtparams)


def writer(csvfile, dialect='excel', **fmtparams):
    return _Writer(csvfile, dialect, **fmtparams)


def register_dialect(name, dialect=None, **fmtparams):
    pass


def unregister_dialect(name):
    pass


def get_dialect(name):
    return excel()


def list_dialects():
    return ['excel', 'excel-tab', 'unix']


def field_size_limit(new_limit=None):
    return 131072


class Error(Exception):
    pass


class Sniffer:
    def __init__(self):
        pass

    def sniff(self, sample, delimiters=None):
        return excel()

    def has_header(self, sample):
        return True

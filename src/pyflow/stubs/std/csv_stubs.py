from __future__ import absolute_import

from ..stubcollector import stubgenerator

import csv


@stubgenerator
def makeCSVStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### reader ###
    @export
    @attachPtr(csv, "reader")
    @llfunc
    def csv_reader(csvfile, dialect='excel', **fmtparams):
        return allocate(type(csv.reader([])))

    @attachPtr(type(csv.reader([])), "__iter__")
    @llfunc
    def csvreader__iter__(self):
        return self

    @attachPtr(type(csv.reader([])), "__next__")
    @llfunc
    def csvreader__next__(self):
        return allocate(list)

    ### writer ###
    @export
    @attachPtr(csv, "writer")
    @llfunc
    def csv_writer(csvfile, dialect='excel', **fmtparams):
        return allocate(type(csv.writer(open('test', 'w'))))

    @attachPtr(type(csv.writer(open('test', 'w'))), "writerow")
    @llfunc
    def csvwriter_writerow(self, row):
        return allocate(int)

    @attachPtr(type(csv.writer(open('test', 'w'))), "writerows")
    @llfunc
    def csvwriter_writerows(self, rows):
        return allocate(type(None))

    ### register_dialect ###
    @export
    @attachPtr(csv, "register_dialect")
    @llfunc
    def csv_register_dialect(name, dialect=None, **fmtparams):
        return allocate(type(None))

    ### unregister_dialect ###
    @export
    @attachPtr(csv, "unregister_dialect")
    @llfunc
    def csv_unregister_dialect(name):
        return allocate(type(None))

    ### get_dialect ###
    @export
    @attachPtr(csv, "get_dialect")
    @llfunc
    def csv_get_dialect(name):
        return allocate(csv.Dialect)

    ### list_dialects ###
    @export
    @attachPtr(csv, "list_dialects")
    @llfunc
    def csv_list_dialects():
        return allocate(list)

    ### field_size_limit ###
    @export
    @attachPtr(csv, "field_size_limit")
    @llfunc
    def csv_field_size_limit(new_limit=None):
        return allocate(int)

    ### Dialect ###
    @export
    @attachPtr(csv, "Dialect")
    @llfunc
    def csv_Dialect():
        return allocate(csv.Dialect)

    ### excel dialect ###
    @export
    @attachPtr(csv, "excel")
    @llfunc
    def csv_excel():
        return allocate(csv.excel)

    ### excel_tab dialect ###
    @export
    @attachPtr(csv, "excel_tab")
    @llfunc
    def csv_excel_tab():
        return allocate(csv.excel_tab)

    ### unix_dialect ###
    @export
    @attachPtr(csv, "unix_dialect")
    @llfunc
    def csv_unix_dialect():
        return allocate(csv.unix_dialect)

    ### Sniffer ###
    @export
    @attachPtr(csv, "Sniffer")
    @llfunc
    def csv_Sniffer():
        return allocate(csv.Sniffer)

    @attachPtr(csv.Sniffer, "sniff")
    @llfunc
    def sniffer_sniff(self, sample, delimiters=None):
        return allocate(csv.Dialect)

    @attachPtr(csv.Sniffer, "has_header")
    @llfunc
    def sniffer_has_header(self, sample):
        return allocate(bool)

    ### DictReader ###
    @export
    @attachPtr(csv, "DictReader")
    @llfunc
    def csv_DictReader(f, fieldnames=None, restkey=None, restval=None, dialect='excel', *args, **kwds):
        return allocate(csv.DictReader)

    @attachPtr(csv.DictReader, "__iter__")
    @llfunc
    def dictreader__iter__(self):
        return self

    @attachPtr(csv.DictReader, "__next__")
    @llfunc
    def dictreader__next__(self):
        return allocate(dict)

    @attachPtr(csv.DictReader, "fieldnames")
    @llfunc
    def dictreader_fieldnames_get(self):
        return allocate(list)

    @attachPtr(csv.DictReader, "line_num")
    @llfunc
    def dictreader_line_num_get(self):
        return allocate(int)

    ### DictWriter ###
    @export
    @attachPtr(csv, "DictWriter")
    @llfunc
    def csv_DictWriter(f, fieldnames, restval='', extrasaction='raise', dialect='excel', *args, **kwds):
        return allocate(csv.DictWriter)

    @attachPtr(csv.DictWriter, "writeheader")
    @llfunc
    def dictwriter_writeheader(self):
        return allocate(int)

    @attachPtr(csv.DictWriter, "writerow")
    @llfunc
    def dictwriter_writerow(self, rowdict):
        return allocate(int)

    @attachPtr(csv.DictWriter, "writerows")
    @llfunc
    def dictwriter_writerows(self, rowdicts):
        return allocate(type(None))

    @attachPtr(csv.DictWriter, "fieldnames")
    @llfunc
    def dictwriter_fieldnames_get(self):
        return allocate(list)

    ### Error ###
    @export
    @attachPtr(csv, "Error")
    @llfunc
    def csv_Error(*args):
        return allocate(csv.Error)

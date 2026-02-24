from __future__ import absolute_import

from ..stubcollector import stubgenerator

import logging


@stubgenerator
def makeLoggingStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    ### getLogger ###
    @export
    @attachPtr(logging, "getLogger")
    @llfunc
    def logging_getLogger(name=None):
        return allocate(logging.Logger)

    ### Logger ###
    @attachPtr(logging.Logger, "debug")
    @llfunc
    def logger_debug(self, msg, *args, **kwargs):
        return allocate(type(None))

    @attachPtr(logging.Logger, "info")
    @llfunc
    def logger_info(self, msg, *args, **kwargs):
        return allocate(type(None))

    @attachPtr(logging.Logger, "warning")
    @llfunc
    def logger_warning(self, msg, *args, **kwargs):
        return allocate(type(None))

    @attachPtr(logging.Logger, "error")
    @llfunc
    def logger_error(self, msg, *args, **kwargs):
        return allocate(type(None))

    @attachPtr(logging.Logger, "critical")
    @llfunc
    def logger_critical(self, msg, *args, **kwargs):
        return allocate(type(None))

    @attachPtr(logging.Logger, "exception")
    @llfunc
    def logger_exception(self, msg, *args, **kwargs):
        return allocate(type(None))

    @attachPtr(logging.Logger, "log")
    @llfunc
    def logger_log(self, level, msg, *args, **kwargs):
        return allocate(type(None))

    @attachPtr(logging.Logger, "setLevel")
    @llfunc
    def logger_setLevel(self, level):
        return allocate(type(None))

    @attachPtr(logging.Logger, "getEffectiveLevel")
    @llfunc
    def logger_getEffectiveLevel(self):
        return allocate(int)

    @attachPtr(logging.Logger, "isEnabledFor")
    @llfunc
    def logger_isEnabledFor(self, level):
        return allocate(bool)

    @attachPtr(logging.Logger, "addHandler")
    @llfunc
    def logger_addHandler(self, hdlr):
        return allocate(type(None))

    @attachPtr(logging.Logger, "removeHandler")
    @llfunc
    def logger_removeHandler(self, hdlr):
        return allocate(type(None))

    @attachPtr(logging.Logger, "hasHandlers")
    @llfunc
    def logger_hasHandlers(self):
        return allocate(bool)

    @attachPtr(logging.Logger, "name")
    @llfunc
    def logger_name_get(self):
        return allocate(str)

    @attachPtr(logging.Logger, "level")
    @llfunc
    def logger_level_get(self):
        return allocate(int)

    @attachPtr(logging.Logger, "parent")
    @llfunc
    def logger_parent_get(self):
        return allocate(logging.Logger)

    @attachPtr(logging.Logger, "propagate")
    @llfunc
    def logger_propagate_get(self):
        return allocate(bool)

    ### Handler ###
    @export
    @attachPtr(logging, "Handler")
    @llfunc
    def logging_Handler(level=0):
        return allocate(logging.Handler)

    @attachPtr(logging.Handler, "emit")
    @llfunc
    def handler_emit(self, record):
        return allocate(type(None))

    @attachPtr(logging.Handler, "handle")
    @llfunc
    def handler_handle(self, record):
        return allocate(type(None))

    @attachPtr(logging.Handler, "setLevel")
    @llfunc
    def handler_setLevel(self, level):
        return allocate(type(None))

    @attachPtr(logging.Handler, "setFormatter")
    @llfunc
    def handler_setFormatter(self, fmt):
        return allocate(type(None))

    @attachPtr(logging.Handler, "addFilter")
    @llfunc
    def handler_addFilter(self, filter):
        return allocate(type(None))

    @attachPtr(logging.Handler, "removeFilter")
    @llfunc
    def handler_removeFilter(self, filter):
        return allocate(type(None))

    @attachPtr(logging.Handler, "flush")
    @llfunc
    def handler_flush(self):
        return allocate(type(None))

    @attachPtr(logging.Handler, "close")
    @llfunc
    def handler_close(self):
        return allocate(type(None))

    ### StreamHandler ###
    @export
    @attachPtr(logging, "StreamHandler")
    @llfunc
    def logging_StreamHandler(stream=None):
        return allocate(logging.StreamHandler)

    ### FileHandler ###
    @export
    @attachPtr(logging, "FileHandler")
    @llfunc
    def logging_FileHandler(filename, mode='a', encoding=None, delay=False, errors=None):
        return allocate(logging.FileHandler)

    ### Formatter ###
    @export
    @attachPtr(logging, "Formatter")
    @llfunc
    def logging_Formatter(fmt=None, datefmt=None, style='%'):
        return allocate(logging.Formatter)

    @attachPtr(logging.Formatter, "format")
    @llfunc
    def formatter_format(self, record):
        return allocate(str)

    @attachPtr(logging.Formatter, "formatTime")
    @llfunc
    def formatter_formatTime(self, record, datefmt=None):
        return allocate(str)

    ### Filter ###
    @export
    @attachPtr(logging, "Filter")
    @llfunc
    def logging_Filter(name=''):
        return allocate(logging.Filter)

    @attachPtr(logging.Filter, "filter")
    @llfunc
    def filter_filter(self, record):
        return allocate(bool)

    ### LogRecord ###
    @export
    @attachPtr(logging, "LogRecord")
    @llfunc
    def logging_LogRecord(name, level, pathname, lineno, msg, args, exc_info, func=None, sinfo=None):
        return allocate(logging.LogRecord)

    @attachPtr(logging.LogRecord, "getMessage")
    @llfunc
    def logrecord_getMessage(self):
        return allocate(str)

    ### basicConfig ###
    @export
    @attachPtr(logging, "basicConfig")
    @llfunc
    def logging_basicConfig(filename=None, filemode='a', format=None, datefmt=None, style='%', level=None, stream=None, handlers=None, force=False):
        return allocate(type(None))

    ### log functions ###
    @export
    @attachPtr(logging, "debug")
    @llfunc
    def logging_debug(msg, *args, **kwargs):
        return allocate(type(None))

    @export
    @attachPtr(logging, "info")
    @llfunc
    def logging_info(msg, *args, **kwargs):
        return allocate(type(None))

    @export
    @attachPtr(logging, "warning")
    @llfunc
    def logging_warning(msg, *args, **kwargs):
        return allocate(type(None))

    @export
    @attachPtr(logging, "error")
    @llfunc
    def logging_error(msg, *args, **kwargs):
        return allocate(type(None))

    @export
    @attachPtr(logging, "critical")
    @llfunc
    def logging_critical(msg, *args, **kwargs):
        return allocate(type(None))

    @export
    @attachPtr(logging, "exception")
    @llfunc
    def logging_exception(msg, *args, **kwargs):
        return allocate(type(None))

    ### Level constants ###
    @llfunc
    def logging_DEBUG_get():
        return allocate(int)

    @llfunc
    def logging_INFO_get():
        return allocate(int)

    @llfunc
    def logging_WARNING_get():
        return allocate(int)

    @llfunc
    def logging_ERROR_get():
        return allocate(int)

    @llfunc
    def logging_CRITICAL_get():
        return allocate(int)

    @llfunc
    def logging_NOTSET_get():
        return allocate(int)

    ### root logger ###
    @llfunc
    def logging_root_get():
        return allocate(logging.Logger)

    ### shutdown ###
    @export
    @attachPtr(logging, "shutdown")
    @llfunc
    def logging_shutdown():
        return allocate(type(None))

    ### captureWarnings ###
    @export
    @attachPtr(logging, "captureWarnings")
    @llfunc
    def logging_captureWarnings(capture):
        return allocate(type(None))

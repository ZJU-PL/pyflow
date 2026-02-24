from __future__ import absolute_import

from ..stubcollector import stubgenerator

import time


@stubgenerator
def makeTimeStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr
    staticFold = collector.staticFold

    ### time() ###
    @export
    @attachPtr(time, "time")
    @llfunc
    def time_time():
        return allocate(float)

    ### time_ns() ###
    @export
    @attachPtr(time, "time_ns")
    @llfunc
    def time_time_ns():
        return allocate(int)

    ### sleep() ###
    @export
    @attachPtr(time, "sleep")
    @llfunc
    def time_sleep(seconds):
        return allocate(type(None))

    ### gmtime() ###
    @export
    @attachPtr(time, "gmtime")
    @llfunc
    def time_gmtime(secs=None):
        return allocate(time.struct_time)

    ### localtime() ###
    @export
    @attachPtr(time, "localtime")
    @llfunc
    def time_localtime(secs=None):
        return allocate(time.struct_time)

    ### mktime() ###
    @export
    @attachPtr(time, "mktime")
    @llfunc
    def time_mktime(t):
        return allocate(float)

    ### asctime() ###
    @export
    @attachPtr(time, "asctime")
    @llfunc
    def time_asctime(t=None):
        return allocate(str)

    ### ctime() ###
    @export
    @attachPtr(time, "ctime")
    @llfunc
    def time_ctime(secs=None):
        return allocate(str)

    ### strftime() ###
    @export
    @attachPtr(time, "strftime")
    @llfunc
    def time_strftime(format, t=None):
        return allocate(str)

    ### strptime() ###
    @export
    @attachPtr(time, "strptime")
    @llfunc
    def time_strptime(string, format="%a %b %d %H:%M:%S %Y"):
        return allocate(time.struct_time)

    ### clock() - deprecated ###
    @export
    @attachPtr(time, "clock")
    @llfunc
    def time_clock():
        return allocate(float)

    ### perf_counter() ###
    @export
    @attachPtr(time, "perf_counter")
    @llfunc
    def time_perf_counter():
        return allocate(float)

    ### perf_counter_ns() ###
    @export
    @attachPtr(time, "perf_counter_ns")
    @llfunc
    def time_perf_counter_ns():
        return allocate(int)

    ### process_time() ###
    @export
    @attachPtr(time, "process_time")
    @llfunc
    def time_process_time():
        return allocate(float)

    ### process_time_ns() ###
    @export
    @attachPtr(time, "process_time_ns")
    @llfunc
    def time_process_time_ns():
        return allocate(int)

    ### monotonic() ###
    @export
    @attachPtr(time, "monotonic")
    @llfunc
    def time_monotonic():
        return allocate(float)

    ### monotonic_ns() ###
    @export
    @attachPtr(time, "monotonic_ns")
    @llfunc
    def time_monotonic_ns():
        return allocate(int)

    ### thread_time() ###
    @export
    @attachPtr(time, "thread_time")
    @llfunc
    def time_thread_time():
        return allocate(float)

    ### thread_time_ns() ###
    @export
    @attachPtr(time, "thread_time_ns")
    @llfunc
    def time_thread_time_ns():
        return allocate(int)

    ### clock_gettime() ###
    @export
    @attachPtr(time, "clock_gettime")
    @llfunc
    def time_clock_gettime(clk_id):
        return allocate(float)

    ### clock_gettime_ns() ###
    @export
    @attachPtr(time, "clock_gettime_ns")
    @llfunc
    def time_clock_gettime_ns(clk_id):
        return allocate(int)

    ### clock_settime() ###
    @export
    @attachPtr(time, "clock_settime")
    @llfunc
    def time_clock_settime(clk_id, time):
        return allocate(type(None))

    ### clock_settime_ns() ###
    @export
    @attachPtr(time, "clock_settime_ns")
    @llfunc
    def time_clock_settime_ns(clk_id, time):
        return allocate(type(None))

    ### clock_getres() ###
    @export
    @attachPtr(time, "clock_getres")
    @llfunc
    def time_clock_getres(clk_id):
        return allocate(float)

    ### tzset() ###
    @export
    @attachPtr(time, "tzset")
    @llfunc
    def time_tzset():
        return allocate(type(None))

    ### struct_time ###
    @attachPtr(time.struct_time, "tm_year")
    @llfunc
    def struct_time_tm_year_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_mon")
    @llfunc
    def struct_time_tm_mon_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_mday")
    @llfunc
    def struct_time_tm_mday_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_hour")
    @llfunc
    def struct_time_tm_hour_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_min")
    @llfunc
    def struct_time_tm_min_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_sec")
    @llfunc
    def struct_time_tm_sec_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_wday")
    @llfunc
    def struct_time_tm_wday_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_yday")
    @llfunc
    def struct_time_tm_yday_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_isdst")
    @llfunc
    def struct_time_tm_isdst_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_gmtoff")
    @llfunc
    def struct_time_tm_gmtoff_get(self):
        return allocate(int)

    @attachPtr(time.struct_time, "tm_zone")
    @llfunc
    def struct_time_tm_zone_get(self):
        return allocate(str)

    @attachPtr(time.struct_time, "__getitem__")
    @llfunc
    def struct_time__getitem__(self, index):
        return allocate(int)

    @attachPtr(time.struct_time, "__len__")
    @llfunc
    def struct_time__len__(self):
        return allocate(int)

    ### timezone constants ###
    @llfunc
    def time_timezone_get():
        return allocate(int)

    @llfunc
    def time_altzone_get():
        return allocate(int)

    @llfunc
    def time_daylight_get():
        return allocate(int)

    @llfunc
    def time_tzname_get():
        return allocate(tuple)

    ### get_clock_info() ###
    @export
    @attachPtr(time, "get_clock_info")
    @llfunc
    def time_get_clock_info(name):
        return allocate(type(time.get_clock_info('time')))

    ### CLOCKS_PER_SEC ###
    @llfunc
    def time_CLOCKS_PER_SEC_get():
        return allocate(int)

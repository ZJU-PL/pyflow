class struct_time:
    def __init__(self, seq):
        self.tm_year = seq[0] if len(seq) > 0 else 0
        self.tm_mon = seq[1] if len(seq) > 1 else 0
        self.tm_mday = seq[2] if len(seq) > 2 else 0
        self.tm_hour = seq[3] if len(seq) > 3 else 0
        self.tm_min = seq[4] if len(seq) > 4 else 0
        self.tm_sec = seq[5] if len(seq) > 5 else 0
        self.tm_wday = seq[6] if len(seq) > 6 else 0
        self.tm_yday = seq[7] if len(seq) > 7 else 0
        self.tm_isdst = seq[8] if len(seq) > 8 else 0


def time():
    return 0.0


def sleep(secs):
    pass


def gmtime(secs=None):
    return struct_time([2024, 1, 1, 0, 0, 0, 0, 1, 0])


def localtime(secs=None):
    return struct_time([2024, 1, 1, 0, 0, 0, 0, 1, 0])


def strftime(format, t=None):
    return format


def strptime(string, format):
    return struct_time([2024, 1, 1, 0, 0, 0, 0, 1, 0])


def mktime(t):
    return 0.0


def asctime(t=None):
    return "Mon Jan  1 00:00:00 2024"


def ctime(secs=None):
    return "Mon Jan  1 00:00:00 2024"


def perf_counter():
    return 0.0


def process_time():
    return 0.0


def monotonic():
    return 0.0


timezone = 0
altzone = 0
daylight = 0
tzname = ("UTC", "UTC")

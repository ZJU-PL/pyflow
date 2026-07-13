class timedelta:
    def __init__(self, days=0, seconds=0, microseconds=0, milliseconds=0, minutes=0, hours=0, weeks=0):
        self.days = days
        self.seconds = seconds
        self.microseconds = microseconds

    def total_seconds(self):
        return self.days * 86400 + self.seconds + self.microseconds / 1000000

    def __add__(self, other):
        return timedelta(self.days + other.days, self.seconds + other.seconds)

    def __sub__(self, other):
        return timedelta(self.days - other.days, self.seconds - other.seconds)

    def __mul__(self, other):
        return timedelta(self.days * other, self.seconds * other)

    def __str__(self):
        return f"{self.days} days, {self.seconds} seconds"


class date:
    def __init__(self, year, month, day):
        self.year = year
        self.month = month
        self.day = day

    @classmethod
    def today(cls):
        return cls(2024, 1, 1)

    @classmethod
    def fromtimestamp(cls, timestamp):
        return cls(2024, 1, 1)

    @classmethod
    def fromordinal(cls, ordinal):
        return cls(2024, 1, 1)

    def replace(self, year=None, month=None, day=None):
        return date(
            year if year is not None else self.year,
            month if month is not None else self.month,
            day if day is not None else self.day
        )

    def strftime(self, fmt):
        return fmt

    def __str__(self):
        return f"{self.year}-{self.month:02d}-{self.day:02d}"

    def __sub__(self, other):
        return timedelta()


class time:
    def __init__(self, hour=0, minute=0, second=0, microsecond=0, tzinfo=None):
        self.hour = hour
        self.minute = minute
        self.second = second
        self.microsecond = microsecond
        self.tzinfo = tzinfo

    def replace(self, hour=None, minute=None, second=None, microsecond=None, tzinfo=None):
        return time(
            hour if hour is not None else self.hour,
            minute if minute is not None else self.minute,
            second if second is not None else self.second,
            microsecond if microsecond is not None else self.microsecond,
            tzinfo if tzinfo is not None else self.tzinfo
        )

    def strftime(self, fmt):
        return fmt

    def __str__(self):
        return f"{self.hour:02d}:{self.minute:02d}:{self.second:02d}"


class datetime(date):
    def __init__(self, year, month, day, hour=0, minute=0, second=0, microsecond=0, tzinfo=None):
        date.__init__(self, year, month, day)
        self.hour = hour
        self.minute = minute
        self.second = second
        self.microsecond = microsecond
        self.tzinfo = tzinfo

    @classmethod
    def now(cls, tz=None):
        return cls(2024, 1, 1, 0, 0, 0, 0, tz)

    @classmethod
    def utcnow(cls):
        return cls(2024, 1, 1, 0, 0, 0)

    @classmethod
    def today(cls):
        return cls(2024, 1, 1, 0, 0, 0)

    @classmethod
    def fromtimestamp(cls, timestamp, tz=None):
        return cls(2024, 1, 1, 0, 0, 0, 0, tz)

    @classmethod
    def utcfromtimestamp(cls, timestamp):
        return cls(2024, 1, 1, 0, 0, 0)

    @classmethod
    def combine(cls, date, time, tzinfo=None):
        return cls(date.year, date.month, date.day, time.hour, time.minute, time.second, time.microsecond, tzinfo)

    @classmethod
    def strptime(cls, date_string, format):
        return cls(2024, 1, 1)

    def date(self):
        return date(self.year, self.month, self.day)

    def time(self):
        return time(self.hour, self.minute, self.second, self.microsecond)

    def replace(self, year=None, month=None, day=None, hour=None, minute=None, second=None, microsecond=None, tzinfo=None):
        return datetime(
            year if year is not None else self.year,
            month if month is not None else self.month,
            day if day is not None else self.day,
            hour if hour is not None else self.hour,
            minute if minute is not None else self.minute,
            second if second is not None else self.second,
            microsecond if microsecond is not None else self.microsecond,
            tzinfo if tzinfo is not None else self.tzinfo
        )

    def timestamp(self):
        return 0.0

    def __sub__(self, other):
        return timedelta()

    def __str__(self):
        return f"{self.year}-{self.month:02d}-{self.day:02d} {self.hour:02d}:{self.minute:02d}:{self.second:02d}"


class tzinfo:
    def utcoffset(self, dt):
        return timedelta()

    def dst(self, dt):
        return timedelta()

    def tzname(self, dt):
        return ""


class timezone(tzinfo):
    def __init__(self, offset, name=None):
        self.offset = offset
        self.name = name

    def utcoffset(self, dt):
        return self.offset

    def tzname(self, dt):
        return self.name


MINYEAR = 1
MAXYEAR = 9999

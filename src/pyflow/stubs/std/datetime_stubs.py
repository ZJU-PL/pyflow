from __future__ import absolute_import

from ..stubcollector import stubgenerator

import datetime


@stubgenerator
def makeDateTimeStubs(collector):
    llfunc = collector.llfunc
    export = collector.export
    attachPtr = collector.attachPtr

    @export
    @attachPtr(datetime, "datetime")
    @llfunc
    def datetime_datetime(year, month, day, hour=0, minute=0, second=0, microsecond=0):
        # Create datetime object
        return allocate(datetime.datetime)

    @export
    @attachPtr(datetime.datetime, "now")
    @llfunc
    def datetime_now(tz=None):
        # Get current datetime
        return allocate(datetime.datetime)

    @export
    @attachPtr(datetime.datetime, "today")
    @llfunc
    def datetime_today():
        # Get current date as datetime
        return allocate(datetime.datetime)

    @export
    @attachPtr(datetime.datetime, "strftime")
    @llfunc
    def datetime_strftime(self, format):
        # Format datetime as string
        return allocate(str)

    @export
    @attachPtr(datetime.datetime, "timestamp")
    @llfunc
    def datetime_timestamp(self):
        # Get timestamp as float
        return allocate(float)

    @export
    @attachPtr(datetime, "date")
    @llfunc
    def datetime_date(year, month, day):
        # Create date object
        return allocate(datetime.date)

    @export
    @attachPtr(datetime, "time")
    @llfunc
    def datetime_time(hour=0, minute=0, second=0, microsecond=0):
        # Create time object
        return allocate(datetime.time)

    @export
    @attachPtr(datetime, "timedelta")
    @llfunc
    def datetime_timedelta(
        days=0, seconds=0, microseconds=0, milliseconds=0, minutes=0, hours=0, weeks=0
    ):
        # Create timedelta object
        return allocate(datetime.timedelta)

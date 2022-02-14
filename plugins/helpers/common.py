#
#    Copyright (c) 2021 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#

import datetime


def convert_apfs_time(timestamp):
    try:
        return datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=timestamp/1000)
    except Exception:
        return None


def get_timedelta(ts1, ts2):
    try:
        dt1 = datetime.datetime.strptime(ts1, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        dt1 = datetime.datetime.strptime(ts1 + '.000000', '%Y-%m-%d %H:%M:%S.%f')

    try:
        dt2 = datetime.datetime.strptime(ts2, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        dt2 = datetime.datetime.strptime(ts2 + '.000000', '%Y-%m-%d %H:%M:%S.%f')

    return abs(dt2 - dt1).total_seconds()


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

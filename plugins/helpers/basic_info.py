#
#    Copyright (c) 2021 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#
#    --------------------------------------------------
#    This code is based on mac_apt's macinfo.py
#

import datetime
import sqlite3
import sys
from enum import Enum, auto

import pytz
from plugins.helpers.writer import TLEventWriter


class MacAptDBType(Enum):
    MACAPT_DB = auto()
    UNIFIED_LOGS = auto()
    APFS_VOLUMES = auto()


class OutputParams:
    def __init__(self):
        self.logger_root = ''
        self.output_path = ''
        self.use_sqlite = False
        self.use_xlsx = False
        self.use_tsv = False


class MacAptDbs:
    def __init__(self, mac_apt_db='', unifiedlogs_db='', apfs_volumes_db=''):
        self.mac_apt_db_path = mac_apt_db
        self.mac_apt_db_conn = None
        self.mac_apt_db_cursor = None

        self.unifiedlogs_db_path = unifiedlogs_db
        self.unifiedlogs_db_conn = None
        self.unifiedlogs_db_cursor = None

        self.apfs_volumes_db_path = apfs_volumes_db
        self.apfs_volumes_db_conn = None
        self.apfs_volumes_db_cursor = None

    def open_dbs(self):
        self.mac_apt_db_conn = sqlite3.connect(self.mac_apt_db_path)
        self.mac_apt_db_conn.row_factory = sqlite3.Row
        self.mac_apt_db_cursor = self.mac_apt_db_conn.cursor()

        self.unifiedlogs_db_conn = sqlite3.connect(self.unifiedlogs_db_path)
        self.unifiedlogs_db_conn.row_factory = sqlite3.Row
        self.unifiedlogs_db_cursor = self.unifiedlogs_db_conn.cursor()

        self.apfs_volumes_db_conn = sqlite3.connect(self.apfs_volumes_db_path)
        self.apfs_volumes_db_conn.row_factory = sqlite3.Row
        self.apfs_volumes_db_cursor = self.apfs_volumes_db_conn.cursor()

    def close_dbs(self):
        self.mac_apt_db_path = ''
        self.mac_apt_db_conn.close()

        self.unifiedlogs_db_path = ''
        self.unifiedlogs_db_conn.close()

        self.apfs_volumes_db_path = ''
        self.apfs_volumes_db_conn.close()

    def run_query(self, db_type, query):
        if db_type == MacAptDBType.MACAPT_DB:
            cursor = self.mac_apt_db_cursor
        if db_type == MacAptDBType.UNIFIED_LOGS:
            cursor = self.unifiedlogs_db_cursor
        if db_type == MacAptDBType.APFS_VOLUMES:
            cursor = self.apfs_volumes_db_cursor

        return cursor.execute(query)

    def is_table_exist(self, db_type, table_name):
        if db_type == MacAptDBType.MACAPT_DB:
            cursor = self.mac_apt_db_cursor
        if db_type == MacAptDBType.UNIFIED_LOGS:
            cursor = self.unifiedlogs_db_cursor
        if db_type == MacAptDBType.APFS_VOLUMES:
            cursor = self.apfs_volumes_db_cursor

        cursor.execute(f'SELECT * FROM sqlite_master WHERE type="table" and name="{table_name}"')
        if cursor.fetchone():
            return True
        else:
            return False


class BasicInfo:
    def __init__(self, mac_apt_dbs, output_params, start_ts, end_ts, timezone='UTC'):
        self.mac_apt_dbs = mac_apt_dbs
        self.output_params = output_params
        self.data_writer = TLEventWriter(output_params, 'ma2tl', 'ma2tl', timezone)

        try:
            self.tzinfo_user = pytz.timezone(timezone)
            self.tzinfo_utc = pytz.timezone('UTC')
        except pytz.exceptions.UnknownTimeZoneError as ex:
            sys.exit(f"Unknown TimeZone: {ex}")

        self.start_dt_usertz = self._convert_ts_to_usertz(start_ts)
        self.end_dt_usertz = self._convert_ts_to_usertz(end_ts)
        self.start_dt_utc = self._convert_ts_to_utc(start_ts)
        self.end_dt_utc = self._convert_ts_to_utc(end_ts)

    def _convert_ts_to_usertz(self, ts):
        dt_naive = datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
        return self.tzinfo_user.normalize(self.tzinfo_user.localize(dt_naive))

    def _convert_ts_to_utc(self, ts):
        dt_aware_usertz = self._convert_ts_to_usertz(ts)
        return dt_aware_usertz.astimezone(pytz.timezone('UTC'))

    def get_between_dates_usertz(self):
        fmt = '%Y-%m-%d %H:%M:%S'
        return [self.start_dt_usertz.strftime(fmt), self.end_dt_usertz.strftime(fmt)]

    def get_between_dates_utc(self):
        fmt = '%Y-%m-%d %H:%M:%S'
        return [self.start_dt_utc.strftime(fmt), self.end_dt_utc.strftime(fmt)]


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

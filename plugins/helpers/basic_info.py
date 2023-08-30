#
#    Copyright (c) 2021-2023 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#
#    --------------------------------------------------
#    This code is based on mac_apt's macinfo.py
#

from __future__ import annotations

import datetime
import sqlite3
import sys
from enum import Enum, Flag, auto

import pytz

from plugins.helpers.writer import TLEventWriter


# class MacAptDBType(Enum):
class MacAptDBType(Flag):
    NONE = auto()
    MACAPT_DB = auto()
    UNIFIED_LOGS = auto()
    APFS_VOLUMES = auto()
    ALL = MACAPT_DB | UNIFIED_LOGS | APFS_VOLUMES


class OutputParams:
    def __init__(self):
        self.logger_root = ''
        self.output_path = ''
        self.use_sqlite = False
        self.use_xlsx = False
        self.use_tsv = False


class ExistDbs(Flag):
    NONE = auto()
    MACAPT_DB = auto()
    UNIFIED_LOGS = auto()
    APFS_VOLUMES = auto()
    ALL = MACAPT_DB | UNIFIED_LOGS | APFS_VOLUMES


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

        self.has_mac_apt_db = False
        self.has_unifiedlogs_db = False
        self.has_apfs_volumes_db = False

    def open_dbs(self):
        if self.mac_apt_db_path:
            # self.mac_apt_db_conn = sqlite3.connect(self.mac_apt_db_path)
            self.mac_apt_db_conn = sqlite3.connect(f"file:{self.mac_apt_db_path}?mode=ro", uri=True)
            self.mac_apt_db_conn.row_factory = sqlite3.Row
            self.mac_apt_db_cursor = self.mac_apt_db_conn.cursor()
            self.has_mac_apt_db = True

        if self.unifiedlogs_db_path:
            # self.unifiedlogs_db_conn = sqlite3.connect(self.unifiedlogs_db_path)
            self.unifiedlogs_db_conn = sqlite3.connect(f"file:{self.unifiedlogs_db_path}?mode=ro", uri=True)
            self.unifiedlogs_db_conn.row_factory = sqlite3.Row
            self.unifiedlogs_db_cursor = self.unifiedlogs_db_conn.cursor()
            self.has_unifiedlogs_db = True

        if self.apfs_volumes_db_path:
            # self.apfs_volumes_db_conn = sqlite3.connect(self.apfs_volumes_db_path)
            self.apfs_volumes_db_conn = sqlite3.connect(f"file:{self.apfs_volumes_db_path}?mode=ro", uri=True)
            self.apfs_volumes_db_conn.row_factory = sqlite3.Row
            self.apfs_volumes_db_cursor = self.apfs_volumes_db_conn.cursor()
            self.has_apfs_volumes_db = True

    def close_dbs(self):
        if self.mac_apt_db_conn:
            self.mac_apt_db_path = ''
            self.mac_apt_db_conn.close()
            self.has_mac_apt_db = False

        if self.unifiedlogs_db_conn:
            self.unifiedlogs_db_path = ''
            self.unifiedlogs_db_conn.close()
            self.has_unifiedlogs_db = False

        if self.apfs_volumes_db_conn:
            self.apfs_volumes_db_path = ''
            self.apfs_volumes_db_conn.close()
            self.has_apfs_volumes_db = False

    def has_dbs(self, db_type: MacAptDBType) -> MacAptDBType:
        result = MacAptDBType.NONE
        if db_type | MacAptDBType.MACAPT_DB and self.has_mac_apt_db:
            result = MacAptDBType.MACAPT_DB
        if db_type | MacAptDBType.UNIFIED_LOGS and self.has_unifiedlogs_db:
            if result == MacAptDBType.NONE:
                result = MacAptDBType.UNIFIED_LOGS
            else:
                result |= MacAptDBType.UNIFIED_LOGS
        if db_type | MacAptDBType.APFS_VOLUMES and self.has_apfs_volumes_db:
            if result == MacAptDBType.NONE:
                result = MacAptDBType.APFS_VOLUMES
            else:
                result |= MacAptDBType.APFS_VOLUMES

        if db_type == result:
            return True
        else:
            return False

    def run_query(self, db_type: MacAptDBType, query: str) -> sqlite3.Row | tuple:
        cursor = None
        if db_type == MacAptDBType.MACAPT_DB and self.has_mac_apt_db:
            cursor = self.mac_apt_db_cursor
        if db_type == MacAptDBType.UNIFIED_LOGS and self.has_unifiedlogs_db:
            cursor = self.unifiedlogs_db_cursor
        if db_type == MacAptDBType.APFS_VOLUMES and self.has_apfs_volumes_db:
            cursor = self.apfs_volumes_db_cursor

        if cursor:
            return cursor.execute(query)
        else:
            return tuple()

    def is_table_exist(self, db_type: MacAptDBType, table_name: str) -> bool:
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
    def __init__(self, mac_apt_dbs: MacAptDbs, output_params, start_ts, end_ts, timezone='UTC'):
        self.mac_apt_dbs = mac_apt_dbs
        self.output_params = output_params
        # self.analyzing_unifiedlogs_only = False
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

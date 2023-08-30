#
#    Copyright (c) 2021-2023 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#

from __future__ import annotations

import datetime
import logging
import os

from plugins.helpers.basic_info import BasicInfo, MacAptDBType
from plugins.helpers.common import convert_apfs_time

PLUGIN_NAME = os.path.splitext(os.path.basename(__file__))[0].upper()
PLUGIN_DESCRIPTION = "Extract persistence settings."
PLUGIN_ACTIVITY_TYPE = "Persistence"
PLUGIN_VERSION = "20230830"
PLUGIN_AUTHOR = "Minoru Kobayashi"
PLUGIN_AUTHOR_EMAIL = "unknownbit@gmail.com"

log = None

# TODO
# Resolve symbolic link in AppPath.

std_apppath_system_vol = (
    '/System/Applications/',
    '/System/Library/CoreServices/',
    '/System/Library/Extensions/',
    '/System/Library/Frameworks/',
    '/System/Library/PrivateFrameworks/',
    '/System/Library/CryptoTokenKit/',
    '/System/Library/Filesystems/',
    '/System/Library/Image Capture/',
    '/System/Library/Input Methods/',
    '/System/Library/PreferencePanes/',
    '/System/Library/Services/',
    '/System/iOSSupport/',
    '/System/Installation/',
    '/usr/libexec/',
    '/usr/bin/',
    '/usr/sbin/',
    '/bin/',
    '/sbin/'
)

std_persistence_system_vol = (
    '/System/Library/LaunchDaemons/',
    '/System/Library/LaunchAgents/'
)

std_apppath_data_vol = (
    '/Applications/',
    '/Library/Apple/',
    '/Library/Application Support/',
    '/Library/Extensions/'
)


def _check_between_ts(check_ts, start_ts, end_ts):
    check_dt = datetime.datetime.strptime(check_ts, '%Y-%m-%d %H:%M:%S.%f')
    start_dt = datetime.datetime.strptime(start_ts, '%Y-%m-%d %H:%M:%S')
    end_dt = datetime.datetime.strptime(end_ts, '%Y-%m-%d %H:%M:%S')

    if start_dt <= check_dt and check_dt <= end_dt:
        return True
    else:
        return False


def extract_autostart(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.MACAPT_DB | MacAptDBType.APFS_VOLUMES):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql_users = 'SELECT Username, UID FROM Users;'
    sql = 'SELECT * FROM AutoStart WHERE AppPath != "";'
    sql_combined = 'SELECT * FROM Combined_Paths LEFT JOIN Combined_Inodes \
                    ON Combined_Paths.CNID = Combined_Inodes.CNID \
                    WHERE Combined_Paths.Path = "{}" LIMIT 1;'

    users = {}
    for row in run_query(MacAptDBType.MACAPT_DB, sql_users):
        users[row['Username']] = int(row['UID'])

    persistence_entries = []
    for row in basic_info.mac_apt_dbs.run_query(MacAptDBType.MACAPT_DB, sql):
        skip_flag = False
        for apppath_prefix in std_apppath_system_vol:
            if row['AppPath'].startswith(apppath_prefix):
                skip_flag = True
                break

        for persistence_prefix in std_persistence_system_vol:
            if row['Source'].startswith(persistence_prefix):
                skip_flag = True
                break

        if skip_flag:
            continue

        persistence_entries.append({'Source': row['Source'], 'AppPath': row['AppPath']})

    for persistence_entry in persistence_entries:
        persistence_file = persistence_entry['Source']
        persistence_app = persistence_entry['AppPath']

        non_std_apppath = True
        for apppath_prefix in std_apppath_data_vol:
            if persistence_app.startswith(apppath_prefix):
                log.debug(f"AppPath: {persistence_app} , Prefix: {apppath_prefix}")
                non_std_apppath = False
                break

        ts_app_create_utc = ''
        msg = ''
        event_persistence_app = None
        for row in run_query(MacAptDBType.APFS_VOLUMES, sql_combined.format(persistence_app)):
            ts_app_create_utc = convert_apfs_time(row['Created']).strftime('%Y-%m-%d %H:%M:%S.%f')
            msg = persistence_app
            if non_std_apppath:
                msg = '[Non-standard AppPath] ' + msg
            event_persistence_app = [ts_app_create_utc, PLUGIN_ACTIVITY_TYPE + ' App Creation', msg, PLUGIN_NAME]

        ts_file_create_utc = ''
        msg = ''
        event_persistence_file = None
        for row in run_query(MacAptDBType.APFS_VOLUMES, sql_combined.format(persistence_file)):
            ts_file_create_utc = convert_apfs_time(row['Created']).strftime('%Y-%m-%d %H:%M:%S.%f')
            msg = f"{persistence_file} (AppPath: {persistence_app})"
            if non_std_apppath:
                msg = '[Non-standard AppPath] ' + msg
            event_persistence_file = [ts_file_create_utc, PLUGIN_ACTIVITY_TYPE + ' File Creation', msg, PLUGIN_NAME]

        if event_persistence_app and event_persistence_file and \
           (_check_between_ts(ts_app_create_utc, start_ts, end_ts) or _check_between_ts(ts_file_create_utc, start_ts, end_ts)):
            timeline_events.append(event_persistence_app)
            timeline_events.append(event_persistence_file)

    return True


def run(basic_info: BasicInfo) -> bool:
    global log
    log = logging.getLogger(basic_info.output_params.logger_root + '.PLUGINS.' + PLUGIN_NAME)
    timeline_events = []
    extract_autostart(basic_info, timeline_events)

    log.info(f"Detected {len(timeline_events)} events.")
    if len(timeline_events) > 0:
        basic_info.data_writer.write_data_rows(timeline_events)
        return True

    return False


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

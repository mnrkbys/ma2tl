#
#    Copyright (c) 2021 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#

import datetime
import logging
import os
import re

from plugins.helpers.basic_info import MacAptDBType
from plugins.helpers.common import get_timedelta

PLUGIN_NAME = os.path.splitext(os.path.basename(__file__))[0].upper()
PLUGIN_DESCRIPTION = "Extract program execution activities."
PLUGIN_ACTIVITY_TYPE = "Program Execution"
PLUGIN_AUTHOR = "Minoru Kobayashi"
PLUGIN_AUTHOR_EMAIL = "unknownbit@gmail.com"

log = None
ignore_processes = ('activateSettings', 'QuickLookUIService', 'com.apple.dock.extra')


class ProgExecEvent:
    def __init__(self, ts, app_name, app_path, other_info=''):
        self.ts = ts
        self.app_name = app_name
        self.app_path = app_path
        self.other_info = other_info


def extract_program_exec_spotlightshortcuts(basic_info, timeline_events):
    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM SpotlightShortcuts WHERE LastUsed BETWEEN "{start_ts}" AND "{end_ts}" ORDER BY LastUsed;'

    for row in run_query(MacAptDBType.MACAPT_DB, sql):
        ts = row['LastUsed']
        user_typed = row['UserTyped']
        display_name = row['DisplayName']
        app_path = row['URL']

        event = [ts, PLUGIN_ACTIVITY_TYPE, f"{display_name} ({app_path}) , Typed in: \"{user_typed}\"", PLUGIN_NAME]
        timeline_events.append(event)

    return True


# Extract program execution logs with "LAUNCHING:0x" or "LAUNCH: 0x"
def extract_program_exec_logs_launch(basic_info, timeline_events):
    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (SenderName == "LaunchServices" AND (Message LIKE "LAUNCHING:0x%" OR Message LIKE "LAUNCH: 0x%")) \
            ORDER BY TimeUtc;'
    sql_null = 'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{}" AND "{}" AND \
            ProcessName = "lsd" AND Message LIKE "Non-fatal error enumerating %" \
            ORDER BY TimeUtc DESC LIMIT 1;'

    # macOS 10.15.7 : ^LAUNCHING:0x.+ (.+) foreground=(\d) bringForward=(\d) .+
    # macOS 11/12   : ^LAUNCH: 0x.+ (.+) .+
    regex = r'^(LAUNCHING:|LAUNCH: )0x.+-0x.+? (.+) (foreground=\d|starting) .+'

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        result = re.match(regex, row['Message'])
        if result:
            if result.group(2) not in ignore_processes:
                app_name = result.group(2)
                parent_app = row['ProcessImagePath']
            else:
                continue

            # If an application bundle ID does not have
            if app_name == '(null)':
                regex_null = r'^Non-fatal error enumerating .+ file://(.+)/Contents/, .+'
                delta_ts = (datetime.datetime.strptime(row['TimeUtc'], '%Y-%m-%d %H:%M:%S.%f') - datetime.timedelta(microseconds=100000)).strftime('%Y-%m-%d %H:%M:%S.%f')
                for row_null in run_query(MacAptDBType.UNIFIED_LOGS, sql_null.format(delta_ts, row['TimeUtc'])):
                    result_null = re.match(regex_null, row_null['Message'])
                    if result_null:
                        app_name = result_null.group(1)

            msg = f"{app_name} (Launched from {parent_app})"
            event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
            timeline_events.append(event)

    return True


# Extract program execution logs with "temporarySigning" (checked by Gatekeeper)
def extract_program_exec_logs_tempsign(basic_info, timeline_events):
    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (Category == "gk" AND Message LIKE "temporarySigning %") \
            ORDER BY TimeUtc;'
    regex = r'^temporarySigning .+ path=(.+)'

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        result = re.match(regex, row['Message'])
        if result:
            if result.group(1) not in ignore_processes:
                msg = result.group(1)
            else:
                continue

            event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
            timeline_events.append(event)

    return True


def extract_program_exec_logs_adhoc(basic_info, timeline_events):
    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
        (ProcessName = "kernel" AND Message LIKE "AMFI: % is %") OR (ProcessName = "amfid" and Message LIKE "/% signature %") \
        ORDER BY TimeUtc;'
    regex_kernel = r'^AMFI: \'(.+)\' is (.+)'
    regex_amfid = r'^(/.+) (signature .+): .+'
    prog_exec_events = []

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        row_msg = row['Message'].strip()
        log.debug(f"REGEX: {regex_kernel} , ROW: {row_msg}")
        result = re.match(regex_kernel, row_msg)
        if result:
            ts = row['TimeUtc']
            app_name = result.group(1)
            app_path = app_name
            other_info = result.group(2)
            prog_exec_events.append(ProgExecEvent(ts, app_name, app_path, other_info))
            continue

        log.debug(f"REGEX: {regex_amfid} , ROW: {row_msg}")
        result = re.match(regex_amfid, row_msg)
        if result:
            ts = row['TimeUtc']
            app_path = result.group(1)
            other_info = result.group(2)
            for event in prog_exec_events:
                if event.app_path == app_path and get_timedelta(event.ts, ts) <= 0.1:
                    event.other_info += ' ' + other_info + '.'
                    break

    for event in prog_exec_events:
        msg = f"{event.app_path} ({event.other_info})"
        event = [event.ts, PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
        timeline_events.append(event)

    return True


# Extract program execution logs with "Resolved pid"
def extract_program_exec_logs_resolved_pid(basic_info, timeline_events):
    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (Category == "process" AND Message LIKE "Resolved pid %" AND Message LIKE "%[executable<%") \
            ORDER BY TimeUtc;'
    regex_executable = r'^Resolved pid (\d+) to \[executable<(.+)\(\d+\)>:\d+\]'

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        result = re.match(regex_executable, row['Message'])
        if result and result.group(2) not in ignore_processes:
            event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, f"{result.group(2)}, PID={result.group(1)}", PLUGIN_NAME]
            timeline_events.append(event)

    return True


# Extract security policy would not allow logs
def extract_program_exec_logs_sec_pol_not_allow(basic_info, timeline_events):
    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            ProcessName = "kernel" AND SenderName = "AppleSystemPolicy" AND \
            Message LIKE "Security policy would not allow process:%" \
            ORDER BY TimeUtc;'
    regex_sec_pol_not_allow = r'.*Security policy would not allow process: \d+, (.+)'

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        result = re.match(regex_sec_pol_not_allow, row['Message'])
        if result:
            event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE + ' (refused)', f"{result.group(1)}", PLUGIN_NAME]
            timeline_events.append(event)

    return True


def run(basic_info):
    global log
    log = logging.getLogger(basic_info.output_params.logger_root + '.PLUGINS.' + PLUGIN_NAME)
    timeline_events = []
    extract_program_exec_spotlightshortcuts(basic_info, timeline_events)
    extract_program_exec_logs_launch(basic_info, timeline_events)
    extract_program_exec_logs_tempsign(basic_info, timeline_events)
    extract_program_exec_logs_adhoc(basic_info, timeline_events)
    extract_program_exec_logs_resolved_pid(basic_info, timeline_events)
    extract_program_exec_logs_sec_pol_not_allow(basic_info, timeline_events)

    log.info(f"Detected {len(timeline_events)} events.")
    if len(timeline_events) > 0:
        basic_info.data_writer.write_data_rows(timeline_events)
        return True

    return False


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

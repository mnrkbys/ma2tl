#
#    Copyright (c) 2023 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#

from __future__ import annotations

import logging
import os
import re

from plugins.helpers.basic_info import BasicInfo, MacAptDBType

PLUGIN_NAME = os.path.splitext(os.path.basename(__file__))[0].upper()
PLUGIN_DESCRIPTION = "Extract local login activities."
PLUGIN_ACTIVITY_TYPE = "Local Login"
PLUGIN_VERSION = "20230830"
PLUGIN_AUTHOR = "Minoru Kobayashi"
PLUGIN_AUTHOR_EMAIL = "unknownbit@gmail.com"

log = None


# Extract local authentication, OS restart, and OS shutdown logs
# This function is confirmed to work correctly for macOS 13+
def extract_local_authentication(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName == "loginwindow" AND \
                Message LIKE "-[SessionAgentNotificationCenter %" AND \
                Message LIKE "%sendDistributedNotification%" AND \
                NOT (\
                    Message LIKE "%com.apple.system.sessionagent.sessionstatechanged%" OR \
                    Message LIKE "%com.apple.system.loginwindow.likely%"\
                )\
            ) \
            ORDER BY TimeUtc;'
    regex = r'^-\[SessionAgentNotificationCenter .+ \| .+: (?P<notified_action>.+), with userID:(?P<uid>\d+)'
    actions = {
        'sessionDidLogin': 'Logged in',
        'screenIsLocked': 'Screen is locked',
        'screenIsUnlocked': 'Screen is unlocked',
        'sessionDidMoveOffConsole': 'Moved to Fast User Switching mode',
        'sessionDidMoveOnConsole': 'Moved from Fast User Switching mode',
        'logoutInitiated': 'Logout initiated',
        'restartInitiated': 'OS restart initiated',
        'shutdownInitiated': 'OS shutdown initiated',
        'logoutCancelled': 'Cancelled',
        'logoutContinued': 'Continued'
    }

    state = ""
    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        if result := re.match(regex, row['Message']):
            for action in actions.keys():
                msg = ""
                if result['notified_action'].endswith(action):
                    if action == 'logoutInitiated':
                        state = 'logout'
                    elif action == 'restartInitiated':
                        state = 'OS restart'
                    elif action == 'shutdownInitiated':
                        state = 'OS shutdown'

                    if state and action in ('logoutCancelled', 'logoutContinued'):
                        msg = f"{actions[action]} {state} with uid={result['uid']}"
                        state = ""
                    else:
                        msg = f"{actions[action]} with uid={result['uid']}"

                    event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
                    timeline_events.append(event)
                    break

    return True


def run(basic_info: BasicInfo) -> bool:
    global log
    log = logging.getLogger(basic_info.output_params.logger_root + '.PLUGINS.' + PLUGIN_NAME)
    timeline_events = []
    extract_local_authentication(basic_info, timeline_events)

    log.info(f"Detected {len(timeline_events)} events.")
    if len(timeline_events) > 0:
        basic_info.data_writer.write_data_rows(timeline_events)
        return True

    return False


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

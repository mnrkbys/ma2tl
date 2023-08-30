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
PLUGIN_DESCRIPTION = "Extract remote login activities."
PLUGIN_ACTIVITY_TYPE = "Remote Login"
PLUGIN_VERSION = "20230830"
PLUGIN_AUTHOR = "Minoru Kobayashi"
PLUGIN_AUTHOR_EMAIL = "unknownbit@gmail.com"

log = None


# Extract sshd authentication logs
# This function is confirmed to work correctly for macOS 13+
def extract_remote_authentication_sshd(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    # sshd log samples
    ### accepted login and logout
    # [Default] fatal: Timeout before authentication for 172.16.114.1 port 62211
    # [Info] Accepted keyboard-interactive/pam for macforensics from 172.16.114.1 port 60341 ssh2
    # [Info] Received disconnect from 172.16.114.1 port 60341:11: disconnected by user
    # [Info] Disconnected from user macforensics 172.16.114.1 port 60341
    ### user is existing but not valid password
    # [Default] error: PAM: authentication error for macforensics from 172.16.114.1
    # [Info] Failed none for macforensics from 172.16.114.1 port 62312 ssh2
    # [Info] Failed password for macforensics from 172.16.114.1 port 59703 ssh2
    # [Info] Connection closed by authenticating user macforensics 172.16.114.1 port 59703 [preauth]
    # [Default] error: maximum authentication attempts exceeded for macforensics from 172.16.114.1 port 62312 ssh2 [preauth]
    # [Info] Disconnecting authenticating user macforensics 172.16.114.1 port 62312: Too many authentication failures [preauth]
    ### invalid user
    # [Info] Invalid user ZZZZZ from 172.16.114.1 port 59701
    # [Info] Postponed keyboard-interactive for invalid user ZZZZZ from 172.16.114.1 port 59701 ssh2 [preauth]
    # [Default] error: PAM: unknown user for illegal user ZZZZZ from 172.16.114.1
    # [Info] Failed keyboard-interactive/pam for invalid user ZZZZZ from 172.16.114.1 port 59701 ssh2
    # [Info] Failed none for invalid user ZZZZZ from 172.16.114.1 port 59701 ssh2
    # [Info] Failed password for invalid user ZZZZZ from 172.16.114.1 port 59701 ssh2
    # [Info: Connection closed by invalid user ZZZZZ 172.16.114.1 port 62588 [preauth]]
    # [Default] error: maximum authentication attempts exceeded for invalid user ZZZZZ from 172.16.114.1 port 59701 ssh2 [preauth]
    # [Info] Disconnecting invalid user ZZZZZ 172.16.114.1 port 59701: Too many authentication failures [preauth]
    sql_loginout = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName == "sshd" AND SenderName == "sshd" AND \
                (Message LIKE "fatal: Timeout before authentication for %" OR \
                Message LIKE "Accepted % for % from %" OR \
                Message LIKE "Disconnected from %"\
                )\
            ) \
            ORDER BY TimeUtc;'
    sql_invalid_password = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName == "sshd" AND SenderName == "sshd" AND \
                (Message LIKE "error: PAM: authentication error for %" OR \
                Message LIKE "Failed password for % from % port %" OR \
                Message LIKE "Connection closed by authenticating user %"\
                )\
            ) \
            ORDER BY TimeUtc;'
    sql_invalid_user = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName == "sshd" AND SenderName == "sshd" AND \
                (Message LIKE "Invalid user %" OR \
                Message LIKE "error: PAM: unknown user for illegal user %" OR \
                Message LIKE "Failed % for invalid user % from % port %" OR \
                Message LIKE "Connection closed by invalid user %" OR \
                Message LIKE "error: maximum authentication attempts %" OR \
                Message LIKE "Disconnecting invalid user %"\
                )\
            ) \
            ORDER BY TimeUtc;'

    regex_loginout = (
        r'^fatal: Timeout before authentication for (?P<address>.+) port (?P<port>.+)',
        r'^Accepted .+ for (?P<username>.+) from (?P<address>.+) port (?P<port>.+) .+',
        r'^Disconnected from user (?P<username>.+) (?P<address>.+) port (?P<port>.+)'
    )
    regex_invalid_password = (
        r'^error: PAM: authentication error for (?P<username>.+) from (?P<address>.+)',
        r'^Failed password for (?P<username>\w+) from (?P<address>.+) port (?P<port>.+)',
        r'^Connection closed by authenticating user (?P<username>.+) (?P<address>.+) port (?P<port>.+) .+',
        r'^error: maximum authentication attempts exceeded for (?P<username>\w+) from (?P<address>.+) port (?P<port>.+) .+',
        r'^Disconnecting authenticating user (?P<username>.+) (?P<address>.+) port (?P<port>.+): Too many authentication failures .+'
    )
    regex_invalid_user = (
        r'^Invalid user (?P<username>.+) from (?P<address>.+) port (?P<port>.+)',
        r'^error: PAM: unknown user for illegal user (?P<username>.+) from (?P<address>.+)',
        r'^Failed password for invalid user (?P<username>.+) from (?P<address>.+) port (?P<port>.+)',
        r'^Connection closed by invalid user (?P<username>.+) (?P<address>.+) port (?P<port>.+) .+',
        r'^error: maximum authentication attempts exceeded for invalid user (?P<username>.+) from (?P<address>.+) port (?P<port>.+) .+',
        r'^Disconnecting invalid user (?P<username>.+) (?P<address>.+) port (?P<port>.+): Too many authentication failures .+'
    )

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql_loginout):
        for idx, regex in enumerate(regex_loginout):
            if result := re.match(regex, row['Message']):
                msg = ""
                if idx == 0:
                    msg = f"SSHD: Authentication timeout addr={result['address']}, port={result['port']}"
                elif idx == 1:
                    msg = f"SSHD: Accepted user={result['username']}, addr={result['address']}, port={result['port']}"
                elif idx == 2:
                    msg = f"SSHD: Disconnected user={result['username']}, addr={result['address']}, port={result['port']}"

                if msg:
                    event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
                    timeline_events.append(event)

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql_invalid_password):
        for idx, regex in enumerate(regex_invalid_password):
            if result := re.match(regex, row['Message']):
                msg = ""
                if idx == 0:
                    msg = f"SSHD: Authentication error user={result['username']}, addr={result['address']}"
                elif idx == 1:
                    msg = f"SSHD: Failed password user={result['username']}, addr={result['address']}, port={result['port']}"
                elif idx == 2:
                    msg = f"SSHD: Connection closed user={result['username']}, addr={result['address']}, port={result['port']}"
                elif idx == 3:
                    msg = f"SSHD: Maximum authentication attempts exceeded user={result['username']}, addr={result['address']}, port={result['port']}"
                elif idx == 4:
                    msg = f"SSHD: Disconnecting user={result['username']}, addr={result['address']}, port={result['port']}"

                if msg:
                    event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
                    timeline_events.append(event)

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql_invalid_user):
        for idx, regex in enumerate(regex_invalid_user):
            if result := re.match(regex, row['Message']):
                msg = ""
                if idx == 0:
                    msg = f"SSHD: Invalid user={result['username']}, addr={result['address']}, port={result['port']}"
                elif idx == 1:
                    msg = f"SSHD: Authentication error invalid user={result['username']}, addr={result['address']}"
                elif idx == 2:
                    msg = f"SSHD: Failed password invalid user={result['username']}, addr={result['address']}, port={result['port']}"
                elif idx == 3:
                    msg = f"SSHD: Connection closed invalid user={result['username']}, addr={result['address']}, port={result['port']}"
                elif idx == 4:
                    msg = f"SSHD: Maximum authentication attempts exceeded invalid user={result['username']}, addr={result['address']}, port={result['port']}"
                elif idx == 5:
                    msg = f"SSHD: Disconnecting invalid user={result['username']}, addr={result['address']}, port={result['port']}"

                if msg:
                    event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
                    timeline_events.append(event)

    return True


# Extract screensharingd authentication logs
# This function is confirmed to work correctly for macOS 13+
def extract_remote_authentication_screensharing(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName == "screensharingd" AND \
                Message LIKE "Authentication: %"\
            ) \
            ORDER BY TimeUtc;'
    regex = r'^Authnetication: (?P<auth_result>.+) :: (?P<auth_result>.+) :: User Name: (?P<username>.+) :: Viewer Address: (?P<address>.+) :: Type: (?P<type>.+)'

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        if result := re.match(regex, row['Message']):
            msg = f"Screen Sharing: authentication={result['auth_result']}, user={result['username']}, addr={result['address']}, type={result['type']}"
            event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
            timeline_events.append(event)

    return True


def run(basic_info: BasicInfo) -> bool:
    global log
    log = logging.getLogger(basic_info.output_params.logger_root + '.PLUGINS.' + PLUGIN_NAME)
    timeline_events = []
    extract_remote_authentication_sshd(basic_info, timeline_events)
    extract_remote_authentication_screensharing(basic_info, timeline_events)

    log.info(f"Detected {len(timeline_events)} events.")
    if len(timeline_events) > 0:
        basic_info.data_writer.write_data_rows(timeline_events)
        return True

    return False


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

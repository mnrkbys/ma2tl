#
#    Copyright (c) 2021-2023 Minoru Kobayashi
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
PLUGIN_DESCRIPTION = "Extract volume mount/unmount activities."
PLUGIN_ACTIVITY_TYPE = "Volume Mount"
PLUGIN_VERSION = "20230830"
PLUGIN_AUTHOR = "Minoru Kobayashi"
PLUGIN_AUTHOR_EMAIL = "unknownbit@gmail.com"

log = None


# Extract volume mount/unmount logs
def extract_volume_mount_logs_hfs_apfs(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName = "kernel" AND \
                (Message LIKE "%mounted%" OR \
                Message LIKE "%unmount%" OR \
                Message LIKE "%mounting volume%" OR \
                Message LIKE "%unmounting volume%"\
                )\
            ) \
            ORDER BY TimeUtc;'

    # ignore_volumes = ('Macintosh HD', 'Macintosh HD - Data', 'VM', 'Update', 'Preboot', 'Recovery', 'Boot OS X', 'macOS Base System', 'com.apple.TimeMachine.')
    ignore_volumes = ('Macintosh HD', 'Macintosh HD - Data', 'VM', 'Update', 'Preboot', 'Recovery', 'Boot OS X', 'macOS Base System')

    # macOS 13+ APFS mount: apfs_log_mount_unmount:2039: disk5s1 mounting volume Mount Test, requested by: mount_apfs (pid 52313); parent: mount (pid 52312)
    #              unmount: apfs_log_mount_unmount:2039: disk5s1 unmounting volume Mount Test, requested by: diskarbitrationd (pid 122); parent: launchd (pid 1)
    regex_dic = {
        'mount_hfs': r'hfs: mounted (.+) on device (.+)',                                    # macOS 10.15+
        'unmount_hfs': r'hfs: unmount initiated on (.+) on device (.+)',                     # macOS 10.15+
        'mount_apfs': r'apfs_vfsop_mount:\d+: .+: mounted volume: (.+)',                     # macOS 10.15 - 12
        'unmount_apfs': r'apfs_vfsop_unmount:\d+: .+: unmounting volume (.+)',               # macOS 10.15 - 12
        'mount_apfs_13': r'apfs_log_.+:\d+: disk.+ mounting volume (.+), requested by:',     # macOS 13+
        'unmount_apfs_13': r'apfs_log_.+:\d+: disk.+ unmounting volume (.+), requested by:'  # macOS 13+
    }

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        for reg_type, regex in regex_dic.items():
            result = re.match(regex, row['Message'])
            if result:
                volume = result.group(1)
                # ignore_flag = False
                # for ignore_volume in ignore_volumes:
                #     if volume.startswith(ignore_volume):
                #         ignore_flag = True
                #         break

                # if ignore_flag:
                #     break

                if volume in ignore_volumes or volume.startswith("com.apple.TimeMachine."):
                    break

                if reg_type.startswith('mount'):
                    mount_status = 'Volume Mount'
                elif reg_type.startswith('unmount'):
                    mount_status = 'Volume Unmount'

                if reg_type.endswith('hfs'):
                    fs = 'hfs'
                elif reg_type.endswith('apfs') or reg_type.endswith('apfs_13'):
                    fs = 'apfs'

                event = [row['TimeUtc'], mount_status, f"{result.group(1)} ({fs})", PLUGIN_NAME]
                timeline_events.append(event)
                break

    return True


def extract_volume_mount_smbfs(basic_info):
    pass
    # start_ts, end_ts = basic_info.get_between_dates_utc()
    # sql = 'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{}" AND "{}" AND \
    #         (ProcessName = "NetAuthSysAgent" and Category = "NetFS" and Message like "%URL = %") \
    #         ORDER BY TimeUtc;'.format(start_ts, end_ts)
    # regex_smbfs = r'\s+URL = (.+)'


# Extract msdos(fat32)/exfat volume mount logs
def extract_volume_mount_fat(basic_info):
    pass
    # start_ts, end_ts = basic_info.get_between_dates_utc()
    # sql = 'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{}" AND "{}" AND \
    #         (ProcessName = "deleted" AND Message like "totalAvailable thresholds for %") AND \
    #         (Message like "%[msdos]%" or Message like "%[exfat]%") \
    #         ORDER BY TimeUtc;'.format(start_ts, end_ts)
    # regex_fat = r'.+PRIMARY at: (.+) \[(.+)\] .+'


def extract_volume_mount_ntfs(basic_info):
    pass
    # start_ts, end_ts = basic_info.get_between_dates_utc()
    # sql = 'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{}" AND "{}" AND \
    #         (ProcessName = "kernel" AND SenderName = "ntfs" AND Message like "NTFS volume name %") \
    #         ORDER BY TimeUtc;'.format(start_ts, end_ts)
    # regex_ntfs = r'NTFS volume name (.+), .+'


def extract_volume_unmount(basic_info):
    pass


def run(basic_info: BasicInfo) -> bool:
    global log
    log = logging.getLogger(basic_info.output_params.logger_root + '.PLUGINS.' + PLUGIN_NAME)
    timeline_events = []
    extract_volume_mount_logs_hfs_apfs(basic_info, timeline_events)

    log.info(f"Detected {len(timeline_events)} events.")
    if len(timeline_events) > 0:
        basic_info.data_writer.write_data_rows(timeline_events)
        return True

    return False


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

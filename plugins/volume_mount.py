#
#    Copyright (c) 2021 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#

import logging
import os
import re

from plugins.helpers.basic_info import MacAptDBType

PLUGIN_NAME = os.path.splitext(os.path.basename(__file__))[0].upper()
PLUGIN_DESCRIPTION = "Extract volume mount/unmount activities."
PLUGIN_ACTIVITY_TYPE = "Volume Mount"
PLUGIN_AUTHOR = "Minoru Kobayashi"
PLUGIN_AUTHOR_EMAIL = "unknownbit@gmail.com"

log = None


# Extract volume mount/unmount logs
def extract_volume_mount_logs_hfs_apfs(basic_info, timeline_events):
    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName = "kernel" AND (Message like "%mounted%" OR Message like "%unmount%")) \
            ORDER BY TimeUtc;'

    ignore_volumes = ('Preboot', 'Recovery', 'Boot OS X', 'macOS Base System', 'com.apple.TimeMachine.')

    regex_dic = {
        'mount_hfs': r'hfs: mounted (.+) on device (.+)',
        'unmount_hfs': r'hfs: unmount initiated on (.+) on device (.+)',
        'mount_apfs': r'apfs_vfsop_mount:\d+: mounted volume: (.+)',
        'unmount_apfs': r'apfs_vfsop_unmount:\d+: .+: unmounting volume \'(.+)\''
    }

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        for reg_type, regex in regex_dic.items():
            result = re.match(regex, row['Message'])
            if result:
                volume = result.group(1)
                ignore_flag = False
                for ignore_volume in ignore_volumes:
                    if volume.startswith(ignore_volume):
                        ignore_flag = True
                        break

                if ignore_flag:
                    break

                if reg_type.startswith('mount'):
                    mount_status = 'Volume Mount'
                elif reg_type.startswith('unmount'):
                    mount_status = 'Volume Unmount'

                if reg_type.endswith('hfs'):
                    fs = 'hfs'
                elif reg_type.endswith('apfs'):
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


def run(basic_info):
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

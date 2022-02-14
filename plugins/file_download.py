#
#    Copyright (c) 2021 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#

import logging
import os

from plugins.helpers.basic_info import MacAptDBType
from plugins.helpers.common import get_timedelta

PLUGIN_NAME = os.path.splitext(os.path.basename(__file__))[0].upper()
PLUGIN_DESCRIPTION = "Extract file download activities."
PLUGIN_ACTIVITY_TYPE = "File Download"
PLUGIN_AUTHOR = "Minoru Kobayashi"
PLUGIN_AUTHOR_EMAIL = "unknownbit@gmail.com"

log = None


class FileDownloadEvent:
    def __init__(self, ts, data_url, origin_url, local_path, agent=''):
        self.ts = ts
        self.data_url = data_url
        self.origin_url = origin_url
        self.local_path = local_path
        self.agent = agent


def extract_spotlight_dataview_file_download(basic_info, filedownload_events):
    run_query = basic_info.mac_apt_dbs.run_query
    sql = 'SELECT * FROM "{}" WHERE kMDItemDownloadedDate BETWEEN "{}" AND "{}" \
            ORDER BY kMDItemDownloadedDate;'
    sql_tableinfo = 'PRAGMA table_info("{}");'
    tables = {
        'SpotlightDataView-1-store': False,
        'SpotlightDataView-1-.store-DIFF': False
    }

    for table in tables.keys():
        for column in run_query(MacAptDBType.MACAPT_DB, sql_tableinfo.format(table)).fetchall():
            if column[1] == 'kMDItemDownloadedDate':
                tables[table] = True
                break

    start_ts, end_ts = basic_info.get_between_dates_utc()
    for table, has_downloaddeddate in tables.items():
        if has_downloaddeddate:
            for row in run_query(MacAptDBType.MACAPT_DB, sql.format(table, start_ts, end_ts)):
                skip_flag = False
                ts = row['kMDItemDownloadedDate']
                data_url = row['kMDItemWhereFroms']  # If this column have multiple URLs, it should be split with comma(,). First one is DataUrl, second one is OriginUrl.
                local_path = row['FullPath']
                agent = 'N/A'

                if len(data_url.split(', ')) == 2:
                    data_url, origin_url = data_url.split(', ')
                else:
                    data_url = data_url.split(', ')[0]
                    origin_url = 'N/A'

                for event in filedownload_events:
                    if event.ts == ts and event.data_url == data_url and event.origin_url == origin_url and event.local_path == local_path:
                        skip_flag = True
                        break

                if not skip_flag:
                    filedownload_events.append(FileDownloadEvent(ts, data_url, origin_url, local_path, agent))

    return True


def extract_safari_quarantine_file_download(basic_info, filedownload_events):
    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT Quarantine.TimeStamp, Quarantine.AgentName, Quarantine.DataUrl, Quarantine.OriginUrl, Safari.Other_Info FROM Quarantine \
            INNER JOIN Safari ON Safari.Type = "DOWNLOAD" AND Quarantine.DataUrl = Safari.URL \
            WHERE Quarantine.TimeStamp BETWEEN "{start_ts}" AND "{end_ts}" AND \
            Quarantine.AgentName = "Safari" \
            ORDER BY TimeStamp;'

    for row in run_query(MacAptDBType.MACAPT_DB, sql):
        skip_flag = False
        ts = row['TimeStamp']
        data_url = row['DataUrl']
        origin_url = row['OriginUrl']
        local_path = row['Other_Info']
        agent = row['AgentName']

        for event in filedownload_events:
            if event.data_url == data_url and event.local_path == local_path and get_timedelta(event.ts, ts) <= 1:
                log.debug(f"{event.ts}, {event.data_url}, {event.origin_url}, {event.local_path}, {event.agent}")
                log.debug(f"{ts}, {data_url}, {origin_url}, {local_path}, {agent}")
                if event.agent in (None, '', 'N/A'):
                    event.agent = agent
                skip_flag = True
                break

        if not skip_flag:
            filedownload_events.append(FileDownloadEvent(ts, data_url, origin_url, local_path, agent))

    return True


def extract_chrome_file_download(basic_info, filedownload_events):
    table_name = 'Chrome'
    if not basic_info.mac_apt_dbs.is_table_exist(MacAptDBType.MACAPT_DB, table_name):
        log.info(f"{table_name} table does not exist.")
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM Chrome WHERE Type = "DOWNLOAD" AND Date BETWEEN "{start_ts}" AND "{end_ts}" ORDER BY Date;'

    for row in run_query(MacAptDBType.MACAPT_DB, sql):
        ts = row['Date']
        data_url = row['URL']
        origin_url = row['Referrer or Previous Page']
        local_path = row['Local Path']
        agent = 'Chrome'
        filedownload_events.append(FileDownloadEvent(ts, data_url, origin_url, local_path, agent))

    return True


def extract_quarantine_file_download(basic_info, filedownload_events):
    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT TimeStamp, AgentName, DataUrl, OriginUrl FROM Quarantine \
            WHERE TimeStamp BETWEEN "{start_ts}" AND "{end_ts}" \
            ORDER BY TimeStamp;'

    for row in run_query(MacAptDBType.MACAPT_DB, sql):
        skip_flag = False
        ts = row['TimeStamp']
        data_url = row['DataUrl']
        origin_url = row['OriginUrl']
        local_path = 'N/A'
        agent = row['AgentName']

        for event in filedownload_events:
            if event.data_url == data_url and get_timedelta(event.ts, ts) <= 1:
                log.debug(f"{event.ts}, {event.data_url}, {event.origin_url}, {event.local_path}, {event.agent}")
                log.debug(f"{ts}, {data_url}, {origin_url}, {local_path}, {agent}")
                if event.agent in (None, '', 'N/A'):
                    event.agent = agent + '?'
                skip_flag = True
                break

        if not skip_flag:
            filedownload_events.append(FileDownloadEvent(ts, data_url, origin_url, local_path, agent))

    return True


def run(basic_info):
    global log
    log = logging.getLogger(basic_info.output_params.logger_root + '.PLUGINS.' + PLUGIN_NAME)
    timeline_events = []
    filedownload_events = []
    extract_spotlight_dataview_file_download(basic_info, filedownload_events)
    extract_safari_quarantine_file_download(basic_info, filedownload_events)
    extract_chrome_file_download(basic_info, filedownload_events)
    extract_quarantine_file_download(basic_info, filedownload_events)

    for event in filedownload_events:
        if event.local_path in (None, '', 'N/A'):
            event = [event.ts, PLUGIN_ACTIVITY_TYPE, f"From {event.data_url} , Origin: {event.origin_url} , Agent: {event.agent})", PLUGIN_NAME]
        else:
            event = [event.ts, PLUGIN_ACTIVITY_TYPE, f"{event.local_path} (From {event.data_url} , Origin: {event.origin_url} , Agent: {event.agent})", PLUGIN_NAME]
        timeline_events.append(event)

    log.info(f"Detected {len(timeline_events)} events.")
    if len(timeline_events) > 0:
        basic_info.data_writer.write_data_rows(timeline_events)
        return True

    return False


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

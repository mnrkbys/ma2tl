#!/usr/bin/env python3
#
# Copyright 2023 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from typing import NoReturn

import ndjson


class UnifiedLogsDbWriter:
    def __init__(self) -> None:
        self.db_path: str = ""
        self.conn: sqlite3.Connection = None
        self.cursor: sqlite3.Cursor = None
        self.table_name: str = ""
        self.column_list: list[dict] = None
        self.sql_executemany: str = ""

    def open_db(self, db_path: str) -> bool | NoReturn:
        self.db_path = db_path
        try:
            if self.db_path and not os.path.exists(self.db_path):
                self.conn = sqlite3.connect(self.db_path)
                self.conn.execute("PRAGMA journal_mode=WAL")
                return True
            else:
                print(f"Specified SQLite file has been existed: {self.db_path}")
                return False

        except (OSError, sqlite3.Error) as ex:
            print(f"Failed to open/create sqlite db at path {self.db_path}")
            print(f"Error details: {str(ex)}")
            raise ex

    def close_db(self) -> NoReturn:
        if self.conn:
            self.conn.close()
            self.conn = None

    def _build_create_table_query(self) -> str:
        sql = 'CREATE TABLE "' + self.table_name + '" ('
        # for column_name in self.column_list:
        #     sql += f'"{column_name}" TEXT,'
        for column_pair in self.column_list:
            for column_name, column_type in column_pair.items():
                sql += f'"{column_name}" {column_type},'

        sql = sql[:-1]  # remove the last comma
        sql += ")"
        return sql

    def create_table(self, table_name="UnifiedLogs", column_list: list[dict] = list()) -> bool | NoReturn:
        try:
            self.table_name = table_name
            self.column_list = column_list
            if not self.column_list:
                self.column_list = [
                    {"File": "TEXT"},
                    {"DecompFilePos": "INTEGER"},
                    {"ContinuousTime": "TEXT"},
                    {"TimeUtc": "TEXT"},
                    {"Thread": "INTEGER"},
                    {"Type": "TEXT"},
                    {"ActivityID": "INTEGER"},
                    {"ParentActivityID": "INTEGER"},
                    {"ProcessID": "INTEGER"},
                    {"EffectiveUID": "INTEGER"},
                    {"TTL": "INTEGER"},
                    {"ProcessName": "TEXT"},
                    {"SenderName": "TEXT"},
                    {"Subsystem": "TEXT"},
                    {"Category": "TEXT"},
                    {"SignpostName": "TEXT"},
                    {"SignpostInfo": "TEXT"},
                    {"ImageOffset": "INTEGER"},
                    {"SenderUUID": "TEXT"},
                    {"ProcessImageUUID": "TEXT"},
                    {"SenderImagePath": "TEXT"},
                    {"ProcessImagePath": "TEXT"},
                    {"Message": "TEXT"},
                ]
            self.cursor = self.conn.cursor()
            self.cursor.execute(self._build_create_table_query())
            self.conn.commit()
            self.sql_executemany = (
                'INSERT INTO "' + self.table_name + '" VALUES (?' + ",?" * (len(self.column_list) - 1) + ")"
            )
            return True

        except sqlite3.Error as ex:
            print(f"Error creating SQLite table: {self.table_name}")
            print(f"Error details: {str(ex)}")
            raise ex

    def write_rows(self, rows: list[list | tuple]) -> bool | NoReturn:
        try:
            self.cursor.executemany(self.sql_executemany, rows)
            self.conn.commit()
            return True

        except sqlite3.Error as ex:
            print(f"Error writing to SQLite table: {self.table_name}")
            print(f"Error details: {str(ex)}")
            raise ex


def parse_arguments() -> argparse.ArgumentParser:
    epilog = (
        "[Exporting Unified Logs Tips]\n"
        + "Exporting all entries of Unified Logs takes a lot of disk space. I recommend using zip command along with to reduce the file size.\n"
        + "% log show --info --debug --style ndjson --timezone 'UTC' | zip ~/Desktop/unifiedlogs_ndjson.zip -\n\n"
        + "Zipped file can be converted to a database like below:\n"
        + "% unzip -q -c ~/Desktop/unifiedlogs_ndjson.zip | python3 ./ndjson2ma.py -o ./UnifiedLogs.db\n"
        + "\n\n"
        + "[Timezone]\n"
        + "This script does NOT consider timezone. So, you need to run the log command like below:\n"
        + "% log show --info --debug --style ndjson --timezone 'UTC' > /path/to/unifiedlogs.ndjson"
    )

    parser = argparse.ArgumentParser(
        description="Convert the exported Unified Logs with ndjson style to mac_apt UnifiedLogs.db.\n",
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-i", "--input", action="store", default="-", help="Path to an exported Unified Logs file (Default: - (STDIN))"
    )
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        default="UnifiedLogs.db",
        required=True,
        help="Path to an output database file (Default: UnifiedLogs.db)",
    )
    return parser.parse_args()


def parse_log_entry(log_entry: dict) -> list:
    file = ""
    decomp_file_pos = 0
    continuous_time = "0"
    # time_utc: str = log_entry.get('machTimestamp', '0000-00-00 00:00:00.000000+0000')
    time_utc: str = log_entry.get("timestamp", "0000-00-00 00:00:00.000000+0000")
    thread = log_entry.get("threadID", 0)
    type = log_entry.get("messageType", "")
    activity_id = log_entry.get("activityIdentifier", 0)
    parent_activity_id = log_entry.get("parentActivityIdentifier", 0)
    process_id = log_entry.get("processID", 0)
    effective_uid = 0
    ttl = 0
    process_name: str = log_entry.get("processImagePath", "")
    sender_name: str = log_entry.get("senderImagePath", "")
    subsystem = log_entry.get("subsystem", "")
    category = log_entry.get("category", "")
    signpost_name = ""
    signpost_info = ""
    image_offset = 0
    sender_uuid = log_entry.get("senderImageUUID", "")
    process_image_uuid = log_entry.get("processImageUUID", "")
    sender_image_path = log_entry.get("senderImagePath", "")
    process_image_path = log_entry.get("processImagePath", "")
    message = log_entry.get("eventMessage", "")

    time_utc = time_utc.split("+")[0]
    process_name = process_name.split("/")[-1]
    sender_name = sender_name.split("/")[-1]

    unifiedlogs_db_entry = [
        file,
        decomp_file_pos,
        continuous_time,
        time_utc,
        thread,
        type,
        activity_id,
        parent_activity_id,
        process_id,
        effective_uid,
        ttl,
        process_name,
        sender_name,
        subsystem,
        category,
        signpost_name,
        signpost_info,
        image_offset,
        sender_uuid,
        process_image_uuid,
        sender_image_path,
        process_image_path,
        message,
    ]

    return unifiedlogs_db_entry


def main():
    args = parse_arguments()

    if os.path.exists(args.output):
        print("{} is already exist.".format(args.output))
        sys.exit(1)

    db_writer = UnifiedLogsDbWriter()
    if not db_writer.open_db(args.output):
        sys.exit(1)
    db_writer.create_table()

    if args.input == "-":
        f = sys.stdin
    else:
        f = open(args.input, "rt")

    log_reader = ndjson.reader(f)
    unifiedlogs_db_entries = list()

    for log_entry in log_reader:
        parsed_entry = parse_log_entry(log_entry)
        unifiedlogs_db_entries.append(parsed_entry)
        if len(unifiedlogs_db_entries) == 1000:
            db_writer.write_rows(unifiedlogs_db_entries)
            unifiedlogs_db_entries = list()

    if args.input != "-":
        f.close()

    if len(unifiedlogs_db_entries) > 0:
        db_writer.write_rows(unifiedlogs_db_entries)
    db_writer.close_db()


if __name__ == "__main__":
    main()

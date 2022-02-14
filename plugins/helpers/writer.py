#
#    Copyright (c) 2021 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#
#    --------------------------------------------------
#    This code is based on mac_apt's writer.py
#

import csv
import datetime
import logging
import os
import sqlite3

import pytz
import xlsxwriter

log = logging.getLogger('MA2TL.HELPERS.WRITER')


class TLEventWriter:
    def __init__(self, output_params, base_name, table_name, timezone):
        self.output_path = output_params.output_path
        self.table_name = table_name
        self.tzinfo_user_str = timezone
        self.use_sqlite = False
        self.sqlite_writer = None
        self.sqlite_db_path = os.path.join(self.output_path, base_name + '.db')
        self.use_xlsx = False
        self.xlsx_writer = None
        self.xlsx_file_path = os.path.join(self.output_path, base_name + '.xlsx')
        self.use_tsv = False
        self.tsv_writer = None
        self.tsv_file_path = os.path.join(self.output_path, base_name + '.tsv')

        if output_params.use_sqlite:
            self.use_sqlite = True
            self.sqlite_writer = SqliteWriter()
            self.sqlite_writer.open_db(self.sqlite_db_path)
        if output_params.use_xlsx:
            self.use_xlsx = True
            self.xlsx_writer = XlsxWriter()
            self.xlsx_writer.create_xlsx_file(self.xlsx_file_path)
        if output_params.use_tsv:
            self.use_tsv = True
            self.tsv_writer = TsvWriter()
            self.tsv_writer.create_tsv_file(self.tsv_file_path)

    def write_data_header(self, header_list):
        if self.use_sqlite:
            self.sqlite_writer.create_table(self.table_name, header_list)
        if self.use_xlsx:
            self.xlsx_writer.create_sheet(self.table_name)
            self.xlsx_writer.add_header_row(header_list)
        if self.use_tsv:
            self.tsv_writer.write_rows(header_list, header=True)

    def _convert_ts_microsec_to_usertz(self, ts_with_microsecond):
        try:
            dt_naive = datetime.datetime.strptime(ts_with_microsecond, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError as ex:
            dt_naive = datetime.datetime.strptime(ts_with_microsecond + '.000000', '%Y-%m-%d %H:%M:%S.%f')
        tzinfo_utc = pytz.timezone('UTC')
        dt_aware_utc = tzinfo_utc.localize(dt_naive)
        return dt_aware_utc.astimezone(pytz.timezone(self.tzinfo_user_str)).strftime('%Y-%m-%d %H:%M:%S.%f')

    def write_data_rows(self, rows):
        if len(rows) == 0:
            return

        # Insert user timezone timestamp.
        for row in rows:
            row.insert(1, self._convert_ts_microsec_to_usertz(row[0]))

        if self.use_sqlite:
            self.sqlite_writer.write_rows(rows)
        if self.use_xlsx:
            self.xlsx_writer.write_rows(rows)
        if self.use_tsv:
            self.tsv_writer.write_rows(rows)

    def close_writer(self):
        if self.use_sqlite:
            self.sqlite_writer.close_db()
        if self.use_xlsx:
            self.xlsx_writer.close_xlsx_file()
        if self.use_tsv:
            self.tsv_writer.close_tsv_file()


class SqliteWriter:
    def __init__(self):
        self.db_path = ''
        self.conn = None
        self.cursor = None
        self.table_name = ''
        self.column_list = None
        self.sql_executemany = ''

    def open_db(self, db_path):
        self.db_path = db_path
        try:
            if self.db_path and not os.path.exists(self.db_path):
                self.conn = sqlite3.connect(self.db_path)
                return True
            else:
                log.error(f"Specified SQLite files has been existed: {self.db_path}")
                return False

        except (OSError, sqlite3.Error) as ex:
            log.error(f"Failed to open/create sqlite db at path {self.db_path}")
            log.exception(f"Error details: {str(ex)}")
            raise ex

    def close_db(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def _build_create_table_query(self):
        sql = 'CREATE TABLE "' + self.table_name + '" ('
        for column_name in self.column_list:
            sql += f'"{column_name}" TEXT,'

        sql = sql[:-1]  # remove the last comma
        sql += ')'
        return sql

    def create_table(self, table_name, column_list):
        try:
            self.table_name = table_name
            self.column_list = column_list
            self.cursor = self.conn.cursor()
            self.cursor.execute(self._build_create_table_query())
            self.conn.commit()
            self.sql_executemany = 'INSERT INTO "' + self.table_name + '" VALUES (?' + ',?'*(len(self.column_list) - 1) + ')'
            return True

        except sqlite3.Error as ex:
            log.error(f"Error creating SQLite table: {self.table_name}")
            log.exception(f"Error details: {str(ex)}")
            raise ex

    def write_rows(self, rows):
        try:
            self.cursor.executemany(self.sql_executemany, rows)
            self.conn.commit()
            return True

        except sqlite3.Error as ex:
            log.error(f"Error writing to SQLite table: {self.table_name}")
            log.exception(f"Error details: {str(ex)}")
            raise ex


class XlsxWriter:
    def __init__(self):
        self.file_path = ''
        self.workbook = None
        self.sheet = None
        self.max_allowed_rows = 1000000
        self.row_index = 0
        self.sheet_name = ''
        self.max_row_index = 0
        self.max_col_index = 0
        self.col_width_list = None

    def create_xlsx_file(self, file_path):
        self.file_path = file_path
        try:
            self.workbook = xlsxwriter.Workbook(self.file_path, {'strings_to_urls': False, 'constant_memory': True})
        except (xlsxwriter.exceptions.XlsxWriterException, OSError) as ex:
            log.error(f"Failed to create xlsx file at path {self.file_path}")
            log.exception(f"Error details: {str(ex)}")
            raise ex

    def _beautify_columns(self):
        sheet = self.workbook.get_worksheet_by_name(self.sheet_name)
        sheet.freeze_panes(1, 0)  # Freeze 1st row
        # Set column widths
        col_index = 0
        for col_width in self.col_width_list:
            if col_index == 0 or col_index == 1:
                col_width = 25
            if col_width > 100:
                col_width = 100
            sheet.set_column(col_index, col_index, col_width)
            col_index += 1
        # Autofilter
        sheet.autofilter(0, 0, self.max_row_index, self.max_col_index)

    def close_xlsx_file(self):
        self._beautify_columns()
        if self.workbook:
            self.workbook.close()
            self.workbook = None
            self.file_path = ''

    def create_sheet(self, sheet_name):
        if len(sheet_name) > 31:
            log.warning(f"Sheet name \"{sheet_name}\" is longer than the Excel limit of 31 char. It will be truncated to 31 char!")
            sheet_name = sheet_name[0:31]
        try:
            self.sheet = self.workbook.add_worksheet(sheet_name)
        except xlsxwriter.exceptions.XlsxWriterException as ex:
            log.exception(f"Unknown error while adding sheet {sheet_name}")
            raise ex
        self.row_index = 0
        self.sheet_name = sheet_name

    def add_header_row(self, header_list):
        column_index = 0
        for column_name in header_list:
            column_width = 8.43
            self.sheet.write_string(self.row_index, column_index, column_name, self.workbook.add_format({'bold': True}))
            self.sheet.set_column(column_index, column_index, column_width)
            column_index += 1
        self.row_index += 1
        self.max_col_index = column_index - 1
        self.max_row_index = self.row_index - 1
        self.col_width_list = [len(col_name)+3 for col_name in header_list]

    def _store_column_width(self, row):
        column_index = 0
        for item in row:
            width = len(item) + 1
            if width > self.col_width_list[column_index]:
                self.col_width_list[column_index] = width
            column_index += 1

    def _write_row(self, row):
        column_index = 0
        if self.row_index > self.max_allowed_rows:
            log.exception("Error trying to add sheet for overflow data (>1 million rows)")
            raise xlsxwriter.exceptions.XlsxWriterException

        try:
            row_str = tuple(map(str, row))
            for item in row_str:
                try:
                    self.sheet.write(self.row_index, column_index, item)
                except (TypeError, ValueError, xlsxwriter.exceptions.XlsxWriterException):
                    log.exception(f"Error writing data:{item} of type:{type(row[column_index])} in excel row:{self.row_index}")
                column_index += 1

            self.row_index += 1
            self.max_row_index = self.row_index - 1
            self._store_column_width(row_str)
        except xlsxwriter.exceptions.XlsxWriterException as ex:
            log.exception(f"Error writing excel row {self.row_index}")

    def write_rows(self, rows):
        for row in rows:
            self._write_row(row)


class TsvWriter:
    def __init__(self):
        self.file_path = ''
        self.file_handle = None
        self.tsv_writer = None

    def create_tsv_file(self, file_path):
        try:
            self.file_handle = open(file_path, 'wt', encoding='UTF-8', newline='')
            self.tsv_writer = csv.writer(self.file_handle, delimiter='\t')
        except (OSError, csv.Error) as ex:
            log.error(f"Failed to create file at path {self.file_path}")
            log.exception(f"Error details: {str(ex)}")
            raise ex

    def close_tsv_file(self):
        if self.tsv_writer:
            self.file_handle.close()
            self.tsv_writer = None
            self.file_path = ''

    def write_rows(self, rows, header=False):
        if header:
            self.tsv_writer.writerow(rows)
        else:
            self.tsv_writer.writerows(rows)


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

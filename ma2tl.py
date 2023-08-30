#!/usr/bin/env python3
#
# ma2tl.py
# Generate a forensic timeline form the result DBs of mac_apt analysis.
#
#
# MIT License
#
# Copyright (c) 2021-2023 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

from __future__ import annotations

import argparse
import glob
import logging
import os
import re
import sys
import textwrap
import time

import tzlocal

import plugins.helpers.basic_info as basicinfo
from plugins.helpers.plugin import (check_user_specified_plugin_name,
                                    import_plugins, setup_logger)

log = None
MA2TL_VERSION = '20230830'


def parse_arguments(plugins: list) -> argparse.ArgumentParser:
    plugin_name_list = ['ALL']
    plugins_info = f"The following {len(plugins)} plugins are available:"

    for plugin in plugins:
        plugins_info += "\n    {:<20}{}".format(plugin.PLUGIN_NAME, textwrap.fill(plugin.PLUGIN_DESCRIPTION, subsequent_indent=' '*24, initial_indent=' '*24, width=80)[24:])
        plugin_name_list.append(plugin.PLUGIN_NAME)

    plugins_info += "\n    " + "-"*76 + "\n" +\
                    " "*4 + "ALL" + " "*17 + "Run all plugins"

    parser = argparse.ArgumentParser(
                                    description='Forensic timeline generator using mac_apt analysis results. Supports only SQLite DBs.',
                                    epilog=plugins_info, formatter_class=argparse.RawTextHelpFormatter
                                    )
    parser.add_argument('-i', '--input', action='store', default=None, help='Path to a folder that contains mac_apt DBs')
    parser.add_argument('-o', '--output', action='store', default=None, help='Path to a folder to save ma2tl result')
    parser.add_argument('-ot', '--output_type', action='store', default='SQLITE', help='Specify the output file type: SQLITE, XLSX, TSV (Default: SQLITE)')
    # parser.add_argument('-f', '--force', action='store_true', default=False, help='Overwrite an output file.')
    # parser.add_argument('-u', '--unifiedlogs_only', action='store_true', default=False, help='Analyze UnifiedLogs.db only (Default: False)')
    parser.add_argument('-s', '--start', action='store', default=None, help='Specify start timestamp (ex. 2021-11-05 08:30:00)')
    parser.add_argument('-e', '--end', action='store', default=None, help='Specify end timestamp')
    parser.add_argument('-t', '--timezone', action='store', default=None, help='Specify Timezone: "UTC", "Asia/Tokyo", "US/Eastern", etc (Default: System Local Timezone)')
    parser.add_argument('-l', '--log_level', action='store', default='INFO', help='Specify log level: INFO, DEBUG, WARNING, ERROR, CRITICAL (Default: INFO)')
    parser.add_argument('plugin', nargs="+", help="Plugins to run (space separated).")
    return parser.parse_args()


def expand_to_abspath(path):
    if path.startswith('~/') or path == '~':
        path = os.path.expanduser(path)
    return os.path.abspath(path)


def check_input_path(input_path: str, macapt_dbs: basicinfo.MacAptDbs) -> bool:
    try:
        if os.path.isdir(input_path):
            db_list = glob.glob(os.path.join(input_path, '*.db'))
            for db_path in db_list:
                if os.path.isfile(db_path):
                    if os.path.basename(db_path) == 'mac_apt.db':
                        macapt_dbs.mac_apt_db_path = db_path
                    elif os.path.basename(db_path) == 'UnifiedLogs.db':
                        macapt_dbs.unifiedlogs_db_path = db_path
                    elif re.match(r'APFS_Volumes_\w{8}-\w{4}-\w{4}-\w{4}-\w{12}\.db', os.path.basename(db_path)):
                        macapt_dbs.apfs_volumes_db_path = db_path
                # if macapt_dbs.mac_apt_db_path and macapt_dbs.unifiedlogs_db_path and macapt_dbs.apfs_volumes_db_path:
                if macapt_dbs.mac_apt_db_path or macapt_dbs.unifiedlogs_db_path or macapt_dbs.apfs_volumes_db_path:
                    return True
            # else:
            print("Error: mac_apt analysis result DBs are insufficient.")
            return False
        else:
            print("Error: the input path is not a directory.")
            return False

    except Exception as ex:
        print(f"Error: Unknown exception, error details are: {str(ex)}")
        return False


def check_output_path(output_path, force_flag=False):
    try:
        if os.path.isdir(output_path):
            for filename in os.listdir(output_path):
                if filename.startswith('ma2tl.'):
                    print(f"Error: There is already a file that starts with \"ma2tl.\" : {filename}")
                    return False
            return True

        else:
            if os.path.isfile(output_path):
                print(f"Error: The file already exists : {output_path}")
                return False

            else:
                try:
                    os.makedirs(output_path)
                    return True
                except Exception as ex:
                    print(f"Error: Cannot create an output folder : {output_path}\nError Details: {str(ex)}")
                    return False

    except Exception as ex:
        print(f"Exception occurred: {str(ex)}")
        return False


def exit_(message=''):
    global log
    if log and (len(message) > 0):
        log.info(message)
        sys.exit()
    else:
        sys.exit(message)


def main():
    global log
    plugins = []
    if import_plugins(plugins) == 0:
        exit_("Error: No plugins could be added.")

    #
    # Check arguments
    #
    args = parse_arguments(plugins)

    if args.output:
        args.output = expand_to_abspath(args.output)
        print(f"Output path: {args.output}")
        if not check_output_path(args.output):
            exit_()
    else:
        exit_('Specify a folder path to store ma2tl result files.')

    args.log_level = args.log_level.upper()
    if args.log_level not in ('INFO', 'DEBUG', 'WARNING', 'ERROR', 'CRITICAL'):
        exit_("Invalid input type for log level. Valid values are INFO, DEBUG, WARNING, ERROR, CRITICAL")
    else:
        if args.log_level == "INFO":
            args.log_level = logging.INFO
        elif args.log_level == "DEBUG":
            args.log_level = logging.DEBUG
        elif args.log_level == "WARNING":
            args.log_level = logging.WARNING
        elif args.log_level == "ERROR":
            args.log_level = logging.ERROR
        elif args.log_level == "CRITICAL":
            args.log_level = logging.CRITICAL

    #
    # Start analysis
    #
    started_time = time.time()
    logger_root = os.path.splitext(os.path.basename(__file__))[0].upper()
    log = setup_logger(os.path.join(args.output, f"ma2tl_log_{time.strftime('%Y%m%d-%H%M%S')}.txt"), logger_root, args.log_level)
    log.setLevel(args.log_level)
    log.info(f"ma2tl (mac_apt to timeline) ver.{MA2TL_VERSION}: Started at {time.strftime('%H:%M:%S', time.localtime(started_time))}")
    log.info(f"Command line: {' '.join(sys.argv)}")

    plugins_to_run = [x.upper() for x in args.plugin]
    if 'ALL' in plugins_to_run:
        process_all = True
    else:
        process_all = False

    if not process_all:
        if not check_user_specified_plugin_name(plugins_to_run, plugins):
            exit_("Error: Specified plugin name is not found.")

    output_params = basicinfo.OutputParams()
    output_params.logger_root = logger_root
    output_params.output_path = args.output
    if args.output_type:
        args.output_type = args.output_type.upper()
        if args.output_type not in ('SQLITE', 'XLSX', 'TSV'):
            exit_(f"Error: Unsupported output type: {args.output_type}")

        if args.output_type == 'SQLITE':
            output_params.use_sqlite = True
        elif args.output_type == 'XLSX':
            output_params.use_xlsx = True
        elif args.output_type == 'TSV':
            output_params.use_tsv = True

    macapt_dbs = basicinfo.MacAptDbs()
    if args.input:
        args.input = expand_to_abspath(args.input)
        log.info(f"Input path : {args.input}")
        if not check_input_path(args.input, macapt_dbs):
            exit_()
    else:
        exit_('Error: Specify mac_apt result DBs folder.')

    if args.start and args.end:
        regex_ts = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
        if not (re.match(regex_ts, args.start) and re.match(regex_ts, args.end)):
            exit_('Error: Start timestamp or end timestamp cannot be recognized.')
    else:
        exit_('Error: Specify both start and end timestamp.')

    #
    # Prepare BasicInfo object
    #
    if args.timezone:
        tz = args.timezone
    else:
        tz = str(tzlocal.get_localzone())
    basic_info = basicinfo.BasicInfo(macapt_dbs, output_params, args.start, args.end, tz)
    basic_info.mac_apt_dbs.open_dbs()

    #
    # Write data header
    #
    header_list = ['Timestamp (UTC)', f"Timestamp ({tz})", 'ActivityType', 'Message', 'PluginName']
    basic_info.data_writer.write_data_header(header_list)

    #
    # Run plugins!!
    #
    for plugin in plugins:
        if process_all or (plugin.PLUGIN_NAME in plugins_to_run):
            log.info("-"*50)
            log.info(f"Running plugin - {plugin.PLUGIN_NAME}")
            try:
                plugin.run(basic_info)
            except Exception:
                log.exception(f"An exception occurred while running plugin - {plugin.PLUGIN_NAME}")

    #
    # Close mac_apt DBs
    #
    basic_info.mac_apt_dbs.close_dbs()

    #
    # Close TLEventWriter object
    #
    basic_info.data_writer.close_writer()

    ended_time = time.time()
    log.info("Finished.")
    log.info(f"Processing time: {time.strftime('%H:%M:%S', time.gmtime(ended_time - started_time))}")


if __name__ == "__main__":
    if sys.version_info.major >= 3 and sys.version_info.minor >= 7:
        main()
    else:
        sys.exit('Need to install Python 3.7.0 or later to run this script.')

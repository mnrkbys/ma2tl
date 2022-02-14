#
#    Copyright (c) 2021 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#
#    --------------------------------------------------
#    This code is based on mac_apt's plugin.py
#

import logging
import os
import sys
import traceback
from importlib import import_module


def import_plugins(plugins):
    plugin_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), "plugins")
    sys.path.append(plugin_path)
    imported_plugin_name = []

    try:
        dir_list = os.listdir(plugin_path)
        for filename in dir_list:
            if filename.endswith(".py") and not filename.startswith("_"):
                try:
                    plugin = import_module(filename.replace(".py", ""))
                    if _check_plugin_validation(plugin):
                        if plugin.PLUGIN_NAME not in imported_plugin_name:
                            plugins.append(plugin)
                            imported_plugin_name.append(plugin.PLUGIN_NAME)
                        else:
                            print(f"Failed to import plugin - {filename} : Plugin name {plugin.PLUGIN_NAME} is already in use. This plugin is skipped.")
                    else:
                        print(f"Failed to import plugin - {filename} : Plugin is missing a required variable")

                except Exception as ex:
                    print(f"Failed to import plugin - {filename}")
                    print(f"Plugin import exception details: {str(ex)}")
                    continue

    except Exception as ex:
        print("Error: Does plugin directory exist?")
        print(f"Exception details: {str(ex)}")

    plugins.sort(key=lambda plugin: plugin.PLUGIN_NAME)
    return len(plugins)


def _check_plugin_validation(plugin):
    for attr in ('PLUGIN_NAME', 'PLUGIN_DESCRIPTION', 'PLUGIN_ACTIVITY_TYPE', 'PLUGIN_AUTHOR', 'PLUGIN_AUTHOR_EMAIL'):
        try:
            _ = getattr(plugin, attr)
        except Exception:
            print(f"Plugin {plugin} does not have {attr}.")
            return False

    return True


def check_user_specified_plugin_name(plugins_to_run, plugins):
    for user_specified_plugin in plugins_to_run:
        found = False
        for plugin in plugins:
            if plugin.PLUGIN_NAME == user_specified_plugin:
                found = True
                break

        if not found:
            print(f"Error: Plugin name not found : {user_specified_plugin}")
            return False

    return True


def setup_logger(log_file_path, name, log_level=logging.INFO):
    try:
        logger = logging.getLogger(name)

        log_file_handler = logging.FileHandler(log_file_path, encoding='UTF-8')
        log_file_format = logging.Formatter('%(asctime)s|%(name)s|%(levelname)s|%(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        log_file_handler.setFormatter(log_file_format)
        logger.addHandler(log_file_handler)

        log_console_handler = logging.StreamHandler()
        log_console_handler.setLevel(log_level)
        log_console_format = logging.Formatter('%(name)s-%(levelname)s-%(message)s')
        log_console_handler.setFormatter(log_console_format)
        logger.addHandler(log_console_handler)

    except Exception as ex:
        print("Error while trying to create log file\nError Details:\n")
        traceback.print_exc()
        sys.exit("Program aborted..could not create log file!")

    return logger


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

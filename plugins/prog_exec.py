#
#    Copyright (c) 2021-2023 Minoru Kobayashi
#
#    This file is part of ma2tl.
#    Usage or distribution of this code is subject to the terms of the MIT License.
#

from __future__ import annotations

import datetime
import json
import logging
import os
import re

from plugins.helpers.basic_info import BasicInfo, MacAptDBType
from plugins.helpers.common import get_timedelta

PLUGIN_NAME = os.path.splitext(os.path.basename(__file__))[0].upper()
PLUGIN_DESCRIPTION = "Extract program execution activities."
PLUGIN_ACTIVITY_TYPE = "Program Execution"
PLUGIN_VERSION = "20230830"
PLUGIN_AUTHOR = "Minoru Kobayashi"
PLUGIN_AUTHOR_EMAIL = "unknownbit@gmail.com"

log = None
ignore_processes = ('activateSettings', 'QuickLookUIService', 'com.apple.dock.extra')
ignore_tccd_processes = (
    '/Library/Application Support/VMware Tools/vmware-tools-daemon',
    '/usr/libexec/UserEventAgent',
    '/System/Library/CoreServices/Installer Progress.app/Contents/MacOS/Installer Progress',
    '/System/Library/PreferencePanes/Displays.prefPane/Contents/Resources/MirrorDisplays.app/Contents/MacOS/MirrorDisplays',
    '/System/Library/PrivateFrameworks/AmbientDisplay.framework/Versions/A/XPCServices/com.apple.AmbientDisplayAgent.xpc/Contents/MacOS/com.apple.AmbientDisplayAgent',
    '/System/Library/Frameworks/Security.framework/Versions/A/MachServices/SecurityAgent.bundle/Contents/MacOS/SecurityAgent',
    '/System/Library/PrivateFrameworks/SystemAdministration.framework/Versions/A/Resources/activateSettings',
    '/System/Library/CoreServices/SystemUIServer.app/Contents/MacOS/SystemUIServer',
    '/System/Library/CoreServices/talagent',
    '/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter',
    '/System/Library/CoreServices/CoreLocationAgent.app/Contents/MacOS/CoreLocationAgent',
    '/System/Library/PrivateFrameworks/DoNotDisturbServer.framework/Support/donotdisturbd',
    '/System/Library/CoreServices/Dock.app/Contents/XPCServices/com.apple.dock.extra.xpc/Contents/MacOS/com.apple.dock.extra',
    '/System/Library/CoreServices/Spotlight.app/Contents/MacOS/Spotlight',
    '/usr/sbin/cfprefsd',
    '/System/Library/Frameworks/QuickLookUI.framework/Versions/A/XPCServices/QuickLookUIService.xpc/Contents/MacOS/QuickLookUIService',
    '/System/Library/CoreServices/TextInputMenuAgent.app/Contents/MacOS/TextInputMenuAgent',
    '/System/Library/CoreServices/AirPlayUIAgent.app/Contents/MacOS/AirPlayUIAgent',
    '/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/corespotlightd',
    '/System/Library/PrivateFrameworks/CalendarDaemon.framework/Support/calaccessd',
    '/usr/libexec/sharingd',
    '/System/Library/PrivateFrameworks/CoreSuggestions.framework/Versions/A/Support/suggestd',
    '/usr/sbin/universalaccessd',
    '/System/Library/PrivateFrameworks/AppSSO.framework/Support/AppSSOAgent.app/Contents/MacOS/AppSSOAgent',
    '/System/Applications/Calendar.app/Contents/PlugIns/CalendarWidgetExtension.appex/Contents/MacOS/CalendarWidgetExtension',
    '/System/Library/PrivateFrameworks/TelephonyUtilities.framework/callservicesd',
    '/usr/libexec/knowledge-agent',
    '/System/Applications/Stocks.app/Contents/PlugIns/StocksWidget.appex/Contents/MacOS/StocksWidget',
    '/System/Applications/Weather.app/Contents/PlugIns/WeatherWidget.appex/Contents/MacOS/WeatherWidget',
    '/System/Library/PrivateFrameworks/iCloudNotification.framework/iCloudNotificationAgent',
    '/usr/libexec/rapportd',
    '/System/Library/PrivateFrameworks/AssistantServices.framework/Versions/A/Support/assistantd',
    '/usr/libexec/ContinuityCaptureAgent',
    '/System/Library/PrivateFrameworks/AOSKit.framework/Versions/A/Helpers/AOSHeartbeat.app/Contents/MacOS/AOSHeartbeat',
    '/System/Library/CoreServices/Keychain Circle Notification.app/Contents/MacOS/Keychain Circle',
    '/usr/libexec/studentd',
    '/System/Library/Frameworks/AddressBook.framework/Versions/A/Helpers/AddressBookManager.app/Contents/MacOS/AddressBookManager',
    '/usr/libexec/routined',
    '/System/Library/PrivateFrameworks/ContactsDonation.framework/Versions/A/Support/contactsdonationagent',
    '/System/Library/PrivateFrameworks/HearingCore.framework/heard',
    '/System/Library/PrivateFrameworks/IDS.framework/identityservicesd.app/Contents/MacOS/identityservicesd',
    '/System/Applications/Clock.app/Contents/PlugIns/WorldClockWidget.appex/Contents/MacOS/WorldClockWidget',
    '/System/Library/CoreServices/CoreServicesUIAgent.app/Contents/MacOS/CoreServicesUIAgent',
    '/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder',
    '/System/Library/CoreServices/Keychain Circle Notification.app/Contents/MacOS/Keychain Circle Notification',
    '/System/Library/CoreServices/Screen Time.app/Contents/PlugIns/ScreenTimeWidgetExtension.appex/Contents/MacOS/ScreenTimeWidgetExtension',
    '/System/Library/CoreServices/UIKitSystem.app/Contents/MacOS/UIKitSystem',
    '/System/Library/CoreServices/UserNotificationCenter.app/Contents/MacOS/UserNotificationCenter',
    '/System/Library/CoreServices/WiFiAgent.app/Contents/MacOS/WiFiAgent',
    '/System/Library/CoreServices/diagnostics_agent',
    '/System/Library/Frameworks/AddressBook.framework/Versions/A/Helpers/AddressBookSourceSync.app/Contents/MacOS/AddressBookSourceSync',
    '/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/com.apple.appkit.xpc.openAndSavePanelService.xpc/Contents/MacOS/com.apple.appkit.xpc.openAndSavePanelService',
    '/System/Library/PrivateFrameworks/AMPLibrary.framework/Versions/A/Support/AMPLibraryAgent',
    '/System/Library/PrivateFrameworks/AppSSO.framework/Support/AppSSODaemon',
    '/System/Library/PrivateFrameworks/AppStoreDaemon.framework/Support/appstoreagent',
    '/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/Resources/amsaccountsd',
    '/System/Library/PrivateFrameworks/AskPermission.framework/Versions/A/Resources/askpermissiond',
    '/System/Library/PrivateFrameworks/BookKit.framework/Versions/A/XPCServices/com.apple.BKAgentService.xpc/Contents/MacOS/com.apple.BKAgentService',
    '/System/Library/PrivateFrameworks/CallHistory.framework/Support/CallHistoryPluginHelper',
    '/System/Library/PrivateFrameworks/DataAccess.framework/Support/dataaccessd',
    '/System/Library/PrivateFrameworks/ExchangeSync.framework/Versions/A/exchangesyncd',
    '/System/Library/PrivateFrameworks/FamilyCircle.framework/Versions/A/Resources/familycircled',
    '/System/Library/PrivateFrameworks/IMCore.framework/imagent.app/Contents/MacOS/imagent',
    '/System/Library/PrivateFrameworks/IMDPersistence.framework/XPCServices/IMDPersistenceAgent.xpc/Contents/MacOS/IMDPersistenceAgent',
    '/System/Library/PrivateFrameworks/MediaAnalysis.framework/Versions/A/mediaanalysisd',
    '/System/Library/PrivateFrameworks/NewDeviceOutreach.framework/ndoagent',
    '/System/Library/PrivateFrameworks/Noticeboard.framework/Versions/A/Resources/nbagent.app/Contents/MacOS/nbagent',
    '/System/Library/PrivateFrameworks/PassKitCore.framework/passd',
    '/System/Library/PrivateFrameworks/People.framework/peopled',
    '/System/Library/PrivateFrameworks/PhotoAnalysis.framework/Versions/A/Support/photoanalysisd',
    '/System/Library/PrivateFrameworks/PhotoLibraryServices.framework/Versions/A/Support/photolibraryd',
    '/System/Library/PrivateFrameworks/SafariSafeBrowsing.framework/Versions/A/com.apple.Safari.SafeBrowsing.Service',
    '/System/Library/PrivateFrameworks/SoftwareUpdate.framework/Versions/A/Resources/SoftwareUpdateNotificationManager.app/Contents/MacOS/SoftwareUpdateNotificationManager',
    '/System/Library/PrivateFrameworks/Translation.framework/translationd',
    '/System/Library/PrivateFrameworks/VoiceShortcuts.framework/Versions/A/Support/siriactionsd',
    '/System/Library/PrivateFrameworks/iTunesCloud.framework/Support/itunescloudd',
    '/System/Library/Services/AppleSpell.service/Contents/MacOS/AppleSpell',
    '/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/MacOS/Safari',
    '/System/Volumes/Preboot/Cryptexes/App/System/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker.xpc/Contents/MacOS/com.apple.Safari.SandboxBroker',
    '/System/Volumes/Preboot/Cryptexes/Incoming/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.GPU.xpc/Contents/MacOS/com.apple.WebKit.GPU',
    '/usr/libexec/AssetCache/AssetCache',
    '/usr/libexec/DataDetectorsLocalSources',
    '/usr/libexec/biomesyncd',
    '/usr/libexec/periodic-wrapper',
    '/usr/libexec/siriknowledged',
    '/usr/libexec/tipsd',
    '/System/Library/Frameworks/CoreMediaIO.framework/Versions/A/Resources/VDC.plugin/Contents/Resources/VDCAssistant',
    '/System/Library/CoreServices/NotificationCenter.app/Contents/MacOS/NotificationCenter',
    '/System/Library/CoreServices/Software Update.app/Contents/Resources/softwareupdated',
    '/System/Library/CoreServices/cloudpaird',
    '/System/Library/PrivateFrameworks/MediaRemote.framework/Support/mediaremoted',
    '/usr/libexec/PerfPowerServices',
    '/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/WindowServer',
    '/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/Metadata.framework/Versions/A/Support/mds',
    '/System/Library/Frameworks/Contacts.framework/Support/contactsd',
    '/System/Applications/FindMy.app/Contents/PlugIns/FindMyWidgetIntentsPeople.appex/Contents/MacOS/FindMyWidgetIntentsPeople',
    '/System/Library/ExtensionKit/Extensions/UsersGroups.appex/Contents/MacOS/UsersGroups',
    '/System/Library/PrivateFrameworks/IntelligencePlatformCore.framework/Versions/A/knowledgeconstructiond',
    '/usr/sbin/bluetoothd',
    '/System/Applications/FindMy.app/Contents/PlugIns/FindMyWidgetItems.appex/Contents/MacOS/FindMyWidgetItems',
    '/System/Applications/FindMy.app/Contents/PlugIns/FindMyWidgetPeople.appex/Contents/MacOS/FindMyWidgetPeople',
    '/System/Applications/Notes.app/Contents/PlugIns/com.apple.Notes.IntentsExtension.appex/Contents/MacOS/com.apple.Notes.IntentsExtension',
    '/System/Applications/Photos.app/Contents/PlugIns/PhotosReliveWidget.appex/Contents/MacOS/PhotosReliveWidget',
    '/System/Applications/Reminders.app/Contents/PlugIns/RemindersIntentsExtension.appex/Contents/MacOS/RemindersIntentsExtension',
    '/System/Library/CoreServices/mapspushd',
    '/System/Library/ExtensionKit/Extensions/Appearance.appex/Contents/MacOS/Appearance',
    '/System/Library/ExtensionKit/Extensions/CDs & DVDs Settings Extension.appex/Contents/MacOS/CDs & DVDs Settings Extension',
    '/System/Library/ExtensionKit/Extensions/ClassKitSettings.appex/Contents/MacOS/ClassKitSettings',
    '/System/Library/ExtensionKit/Extensions/ClassroomSettings.appex/Contents/MacOS/ClassroomSettings',
    '/System/Library/ExtensionKit/Extensions/ControlCenterSettings.appex/Contents/MacOS/ControlCenterSettings',
    '/System/Library/ExtensionKit/Extensions/FamilySettings.appex/Contents/MacOS/FamilySettings',
    '/System/Library/ExtensionKit/Extensions/FollowUpSettingsExtension.appex/Contents/MacOS/FollowUpSettingsExtension',
    '/System/Library/ExtensionKit/Extensions/GameControllerMacSettings.appex/Contents/MacOS/GameControllerMacSettings',
    '/System/Library/ExtensionKit/Extensions/HeadphoneSettingsExtension.appex/Contents/MacOS/HeadphoneSettingsExtension',
    '/System/Library/ExtensionKit/Extensions/MouseExtension.appex/Contents/MacOS/MouseExtension',
    '/System/Library/ExtensionKit/Extensions/PowerPreferences.appex/Contents/MacOS/PowerPreferences',
    '/System/Library/ExtensionKit/Extensions/Touch ID & Password.appex/Contents/MacOS/Touch ID & Password',
    '/System/Library/ExtensionKit/Extensions/AppleIDSettings.appex/Contents/MacOS/AppleIDSettings',
    '/System/Library/ExtensionKit/Extensions/WalletSettingsExtension.appex/Contents/MacOS/WalletSettingsExtension',
    '/System/Library/ExtensionKit/Extensions/TrackpadExtension.appex/Contents/MacOS/TrackpadExtension',
    '/System/Library/ExtensionKit/Extensions/VPN.appex/Contents/MacOS/VPN',
    '/System/Library/ExtensionKit/Extensions/LoginItems.appex/Contents/MacOS/LoginItems',
    '/System/iOSSupport/System/Library/PrivateFrameworks/AvatarUI.framework/PlugIns/AvatarPickerMemojiPicker.appex/Contents/MacOS/AvatarPickerMemojiPicker',
    '/System/Library/PrivateFrameworks/EFILogin.framework/Versions/A/Resources/efilogin-helper',
    '/System/Library/PrivateFrameworks/HomeKitDaemon.framework/Support/homed',
    '/usr/libexec/fmfd',
    '/System/Library/PrivateFrameworks/ScreenTimeCore.framework/Versions/A/ScreenTimeAgent',
    '/System/Library/CoreServices/Setup Assistant.app/Contents/MacOS/Setup Assistant',
    '/System/Library/CoreServices/Setup Assistant.app/Contents/Resources/mbuseragent',
    '/System/Applications/System Settings.app/Contents/PlugIns/GeneralSettings.appex/Contents/MacOS/GeneralSettings',
    '/System/Applications/Notes.app/Contents/PlugIns/com.apple.Notes.WidgetExtension.appex/Contents/MacOS/com.apple.Notes.WidgetExtension',
    '/System/Library/ExtensionKit/Extensions/WiFiSettings.appex/Contents/MacOS/WiFiSettings',
    '/System/Library/ExtensionKit/Extensions/Network.appex/Contents/MacOS/Network',
    '/usr/sbin/spindump',
    '/System/Library/CoreServices/Install in Progress.app/Contents/MacOS/Install in Progress',
)

TccAuthValue = {
    0: "Denied",
    1: "Unknown",
    2: "Allowed",
    3: "Limited"
}

TccAuthReason = {
    0: "None",
    1: "Error",
    2: "User Consent",
    3: "User Set",
    4: "System Set",
    5: "Service Policy",
    6: "MDM Policy",
    7: "Override Policy",
    8: "Missing Usage String",
    9: "Prompt Timeout",
    10: "Preflight Unknown",
    11: "Entitled",
    12: "App Type Policy"
}


class ProgExecEvent:
    def __init__(self, ts, app_name, app_path, other_info=''):
        self.ts = ts
        self.app_name = app_name
        self.app_path = app_path
        self.other_info = other_info


class TccAuthreqEvent:
    def __init__(self, timeutc="", msg_id="", service="", attribution="", auth_value=0, auth_reason=0, auth_version=0) -> None:
        self.timeutc = timeutc
        self.msg_id = msg_id
        self.service = service
        self.attribution = attribution
        self.attribution_dict: dict[str, dict] = dict()
        self.auth_value = auth_value
        self.auth_reason = auth_reason
        self.auth_version = auth_version

    def get_auth_value(self) -> str:
        return TccAuthValue[self.auth_value]

    def get_auth_reason(self) -> str:
        return TccAuthReason[self.auth_reason]


def extract_program_exec_spotlightshortcuts(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.MACAPT_DB):
        return False

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
# This function will work for macOS 10.15+
def extract_program_exec_logs_launch(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (SenderName == "LaunchServices" AND (Message LIKE "LAUNCHING:0x%" OR Message LIKE "LAUNCH: 0x%")) \
            ORDER BY TimeUtc;'
    sql_null = 'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{}" AND "{}" AND \
            ProcessName = "lsd" AND Message LIKE "Non-fatal error enumerating %" \
            ORDER BY TimeUtc DESC LIMIT 1;'

    # macOS 10.15.7    : ^LAUNCHING:0x.+ (.+) foreground=(\d) bringForward=(\d) .+
    # macOS 11+        : ^LAUNCH: 0x.+ (.+) starting stopped process.
    # macOS 11+ (Info) : ^LAUNCH: 0x.+ (.+) launched with launchInStoppedState=true, and not starting the application.
    # macOS 11+ (Info) : LAUNCH: 0x0-0xa00a0 com.ridiculousfish.HexFiend launched with launchInQuarantine == true, so not starting the application.
    regex = r'^(LAUNCHING:|LAUNCH: )0x.+-0x.+ (.+) (foreground=\d bringForward=\d|starting stopped process|launched with )'

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        result = re.match(regex, row['Message'])
        if result:
            if result.group(2) not in ignore_processes:
                app_name = result.group(2)
                parent_app = row['ProcessImagePath']
            else:
                continue

            # If the application bundle ID is "(null)"
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


# Extract unsigned program execution logs with "temporarySigning" message (checked by Gatekeeper)
# This function will work up to macOS 12
# However, it is only for Intel Macs, and AppleSilicon Macs require at least an adhoc signature to the program.
# If an unsigned program is run on macOS 13/14, it will not be logged at all in Unified Logs.
def extract_program_exec_logs_tempsign(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

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


# Extract adhoc signed program execution logs
# This function will work for macOS 10.15+
def extract_program_exec_logs_adhoc(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    # sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
    #     (ProcessName = "kernel" AND Message LIKE "AMFI: % is %") OR (ProcessName = "amfid" and Message LIKE "% signature %") \
    #     ORDER BY TimeUtc;'
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
        (ProcessName = "kernel" AND Message LIKE "AMFI: % is %") OR (ProcessName = "amfid" and Message LIKE "% not valid: %") \
        ORDER BY TimeUtc;'
    regex_kernel = r'^AMFI: \'(.+)\' is (.+)'
    # regex_amfid = r'^(/.+) (signature .+): .+'
    regex_amfid = r'^(/.+) not valid: .+'
    prog_exec_events: list[ProgExecEvent] = []

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        row_msg = row['Message'].strip()
        log.debug(f"REGEX: {regex_kernel} , ROW: {row_msg}")
        result = re.match(regex_kernel, row_msg)
        if result:
            ts = row['TimeUtc']
            app_name = result.group(1)
            app_path = app_name
            if app_path.startswith("/System/Volumes/Preboot/Cryptexes/"):
                continue
            other_info = result.group(2)
            prog_exec_events.append(ProgExecEvent(ts, app_name, app_path, other_info))
            continue

        log.debug(f"REGEX: {regex_amfid} , ROW: {row_msg}")
        result = re.match(regex_amfid, row_msg)
        if result:
            ts = row['TimeUtc']
            app_name = result.group(1)
            app_path = app_name
            if app_path.startswith("/System/Volumes/Preboot/Cryptexes/"):
                continue
            # other_info = result.group(2)
            other_info = "The file does not have a valid signature."
            found_pair = False
            for event in prog_exec_events:
                if event.app_path == app_path and get_timedelta(event.ts, ts) <= 0.1:
                    # event.other_info += ' ' + other_info + '.'
                    event.other_info += ' ' + other_info
                    found_pair = True
                    break

            if not found_pair:
                prog_exec_events.append(ProgExecEvent(ts, app_name, app_path, other_info))

    for event in prog_exec_events:
        msg = f"{event.app_path} ({event.other_info})"
        event = [event.ts, PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
        timeline_events.append(event)

    return True


# Extract program execution logs with "Resolved pid"
# This function will work correctly for macOS 10.15 only
def extract_program_exec_logs_resolved_pid(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

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
# This function will work for macOS 10.15+
def extract_program_exec_logs_sec_pol_not_allow(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

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
            event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, f"{result.group(1)} would not allow to execute", PLUGIN_NAME]
            timeline_events.append(event)

    return True


# Extract sudo logs
# This function will work for macOS 10.15+
def extract_program_exec_logs_sudo(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName == "sudo" AND Message LIKE "%COMMAND=%") \
            ORDER BY TimeUtc;'
    regex_sudo_succeeded = r'^(?P<exec_user>.+) : TTY=(?P<tty>.+) ; PWD=(?P<pwd>.+) ; USER=(?P<user>.+) ; COMMAND=(?P<command>.+)'
    regex_sudo_failed = r'^(?P<exed_user>.+) : (?P<attempts>\d+) incorrect password attempts ; TTY=(?P<tty>.+) ; PWD=(?P<pwd>.+) ; USER=(?P<user>.+) ; COMMAND=(?P<command>.+)'

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        if result := re.match(regex_sudo_succeeded, row['Message']):
            msg = f"{result['exec_user']} executed {result['command']} as {result['user']} on {result['pwd']} ({result['tty']})"
            event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
            timeline_events.append(event)

        elif result := re.match(regex_sudo_failed, row['Message']):
            msg = f"{result['exec_user']} failed to execute {result['command']} as {result['user']} on {result['pwd']} ({result['tty']})"
            event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
            timeline_events.append(event)

    return True


# Extract tccd's AUTHREQ_* logs
# This function is confirmed to work correctly for macOS 13+
def extract_program_exec_logs_tccd(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName == "tccd" AND \
                (Message LIKE "AUTHREQ_CTX: %" OR \
                Message LIKE "AUTHREQ_ATTRIBUTION: %" OR \
                Message LIKE "AUTHREQ_RESULT: %" OR \
                Message LIKE "AUTHREQ_PROMPTING: %"\
                )\
            ) \
            ORDER BY TimeUtc;'
    regex_ctx = r'^AUTHREQ_CTX: msgID=(?P<msg_id>[\d\.]+), function=.+, service=(?P<service>.+?), .+'
    regex_attrib = r'^AUTHREQ_ATTRIBUTION: msgID=(?P<msg_id>[\d\.]+), attribution={(?P<attribution>.+)},'
    regex_result = r'^AUTHREQ_RESULT: msgID=(?P<msg_id>[\d\.]+), authValue=(?P<auth_value>\d+), authReason=(?P<auth_reason>\d+), authVersion=(?P<auth_version>\d+), error=.+'

    tcc_authreq_events: dict[str, TccAuthreqEvent] = dict()
    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        if result := re.match(regex_ctx, row['Message']):
            if result['msg_id'] in tcc_authreq_events.keys():
                tcc_authreq_events[result['msg_id']].msg_id = result['msg_id']
                tcc_authreq_events[result['msg_id']].service = result['service']
            else:
                tcc_authreq_events[result['msg_id']] = TccAuthreqEvent(timeutc=row['TimeUtc'], msg_id=result['msg_id'], service=result['service'])

        elif result := re.match(regex_attrib, row['Message']):
            if result['msg_id'] in tcc_authreq_events.keys():
                tcc_authreq_events[result['msg_id']].attribution = result['attribution']
            else:
                tcc_authreq_events[result['msg_id']] = TccAuthreqEvent(timeutc=row['TimeUtc'], msg_id=result['msg_id'], attribution=result['attribution'])

        elif result := re.match(regex_result, row['Message']):
            if result['msg_id'] in tcc_authreq_events.keys():
                tcc_authreq_events[result['msg_id']].auth_value = int(result['auth_value'])
                tcc_authreq_events[result['msg_id']].auth_reason = int(result['auth_reason'])
                tcc_authreq_events[result['msg_id']].auth_version = int(result['auth_version'])
            else:
                tcc_authreq_events[result['msg_id']] = TccAuthreqEvent(timeutc=row['TimeUtc'], msg_id=result['msg_id'],
                                                                       auth_value=int(result['auth_value']),
                                                                       auth_reason=int(result['auth_reason']),
                                                                       auth_version=int(result['auth_version']))

    ignore_events = list()
    for msg_id, event in tcc_authreq_events.items():
        for attr in event.attribution.split("}, "):
            attr_items = attr.split("={")
            if len(attr_items) == 2:
                attr_name = attr_items[0]
                attr_items[1] = attr_items[1][len("TCCDProcess: "):]
                element_dict = dict()
                for elements in attr_items[1].split(", "):
                    element_name, element_value = elements.split("=")
                    element_dict[element_name] = element_value
                    if attr_name in ("responsible", "accessing", "requesting") and element_name == "binary_path":
                        if element_value in ignore_tccd_processes or \
                           element_value.startswith('/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtectRemediator'):
                        # if element_value in ignore_tccd_processes:
                            ignore_events.append(msg_id)

                event.attribution_dict[attr_name] = element_dict

    for msg_id, tcc_event in tcc_authreq_events.items():
        if msg_id not in ignore_events:
            msg = "TCC authreq: "
            if tcc_event.attribution_dict.get('accessing'):
                if msg == "TCC authreq: ":
                    msg += f"service={tcc_event.service}, "
                msg += f"accessing={tcc_event.attribution_dict['accessing']['binary_path']} ({tcc_event.attribution_dict['accessing']['identifier']}) "
                msg += f"pid={tcc_event.attribution_dict['accessing']['pid']}, auid={tcc_event.attribution_dict['accessing']['auid']}, euid={tcc_event.attribution_dict['accessing']['euid']}, "

            if tcc_event.attribution_dict.get('responsible'):
                if msg == "TCC authreq: ":
                    msg += f"service={tcc_event.service}, "
                msg += f"responsible={tcc_event.attribution_dict['responsible']['binary_path']} ({tcc_event.attribution_dict['responsible']['identifier']}) "
                msg += f"pid={tcc_event.attribution_dict['responsible']['pid']}, auid={tcc_event.attribution_dict['responsible']['auid']}, euid={tcc_event.attribution_dict['responsible']['euid']}, "

            if tcc_event.attribution_dict.get('requesting'):
                if msg == "TCC authreq: ":
                    msg += f"service={tcc_event.service}, "
                msg += f"requesting={tcc_event.attribution_dict['requesting']['binary_path']} ({tcc_event.attribution_dict['requesting']['identifier']}) "
                msg += f"pid={tcc_event.attribution_dict['requesting']['pid']}, auid={tcc_event.attribution_dict['requesting']['auid']}, euid={tcc_event.attribution_dict['requesting']['euid']}, "

            if msg != "TCC authreq: ":
                msg += f"Result: authValue={tcc_event.get_auth_value()}({tcc_event.auth_value}), authReason={tcc_event.get_auth_reason()}({tcc_event.auth_reason}), authVersion={tcc_event.auth_version}"
                event = [tcc_event.timeutc, PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
                timeline_events.append(event)

    return True


# Extract TCC violation logs
# This function is confirmed to work correctly for macOS 13+
def extract_program_exec_logs_sandbox_violation(basic_info: BasicInfo, timeline_events: list) -> bool:
    if not basic_info.mac_apt_dbs.has_dbs(MacAptDBType.UNIFIED_LOGS):
        return False

    run_query = basic_info.mac_apt_dbs.run_query
    start_ts, end_ts = basic_info.get_between_dates_utc()
    sql = f'SELECT * FROM UnifiedLogs WHERE TimeUtc BETWEEN "{start_ts}" AND "{end_ts}" AND \
            (ProcessName == "sandboxd" AND Subsystem == "com.apple.sandbox.reporting" AND Category == "violation") \
            ORDER BY TimeUtc;'
    regex_metadata = r'^MetaData: (?P<metadata>.+)'

    for row in run_query(MacAptDBType.UNIFIED_LOGS, sql):
        for msg_line in row['Message'].splitlines():
            if result := re.match(regex_metadata, msg_line):
                data = json.loads(result['metadata'])
                msg = f"Sandbox violation: summary={data['summary']}, process={data['process-path']}, responsible-process={data['responsible-process-path']}"
                event = [row['TimeUtc'], PLUGIN_ACTIVITY_TYPE, msg, PLUGIN_NAME]
                timeline_events.append(event)
                break

    return True


def run(basic_info: BasicInfo) -> bool:
    global log
    log = logging.getLogger(basic_info.output_params.logger_root + '.PLUGINS.' + PLUGIN_NAME)
    timeline_events = []
    extract_program_exec_spotlightshortcuts(basic_info, timeline_events)
    extract_program_exec_logs_launch(basic_info, timeline_events)
    extract_program_exec_logs_tempsign(basic_info, timeline_events)
    extract_program_exec_logs_adhoc(basic_info, timeline_events)
    extract_program_exec_logs_resolved_pid(basic_info, timeline_events)
    extract_program_exec_logs_sec_pol_not_allow(basic_info, timeline_events)
    extract_program_exec_logs_sudo(basic_info, timeline_events)
    extract_program_exec_logs_tccd(basic_info, timeline_events)
    extract_program_exec_logs_sandbox_violation(basic_info, timeline_events)

    log.info(f"Detected {len(timeline_events)} events.")
    if len(timeline_events) > 0:
        basic_info.data_writer.write_data_rows(timeline_events)
        return True

    return False


if __name__ == '__main__':
    print('This file is part of forensic timeline generator "ma2tl". So, it cannot run separately.')

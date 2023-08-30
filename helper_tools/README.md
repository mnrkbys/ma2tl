# ma2tl Helper Tools

Unfortunately, the current version of mac_apt is not able to parse Unified Logs correctly since macOS 11. However, there are several measures against this problem.

## Measure 1 (aul2madb)

As mentioned above, the current version of mac_apt cannot parse Unified Logs. On the other hand, exporting Unified Logs can be done correctly. So, we can parse the exported Unified Logs with other tools. For example, [macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs) can parse them which come from macOS 10.12 or later.

aul2madb uses macos-UnifiedLogs as a library and can convert the exported Unified Logs by mac_apt to the database in the same format as mac_apt. macos-UnifiedLogs is written in Rust. Therefore, this tool is also written in Rust, not Python.

### Building aul2madb

```zsh
% cd aul2madb
% cargo build --release
```

### Help of aul2madb

```zsh
% ./target/release/aul2madb -h
Unified Logs converter for ma2tl

Usage: aul2madb [OPTIONS] --input <INPUT>

Options:
  -i, --input <INPUT>                  Path to a logarchive or to a directory that contains exported Unified Logs
  -f, --output-format <OUTPUT_FORMAT>  Output format [default: sqlite] [possible values: sqlite, tsv]
  -o, --output <OUTPUT>                Path to output file [default: ./UnifiedLogs.db]
  -h, --help                           Print help
  -V, --version                        Print version
```

### How to run aul2madb

```zsh
% ./target/release/aul2madb --input ~/Desktop/system_logs.logarchive --output-format sqlite --output UnifiedLogs.db
Staring Unified Logs converter...
Processing as a logarchive.
Parsing: /Users/macforensics/Desktop/system_logs.logarchive/Persist/0000000000000fbf.tracev3
Parsing: /Users/macforensics/Desktop/system_logs.logarchive/Persist/0000000000000fcf.tracev3
Parsing: /Users/macforensics/Desktop/system_logs.logarchive/Persist/0000000000000fa9.tracev3
Parsing: /Users/macforensics/Desktop/system_logs.logarchive/Persist/0000000000000fd4.tracev3
Parsing: /Users/macforensics/Desktop/system_logs.logarchive/Persist/0000000000000fb6.tracev3
(snip)
```

## Measure 2 (ndjson2madb.py)

Actually, the log command of macOS can display log entries as ndjson with a lot of attributions. The ndjson data contains almost the same information as the database created by mac_apt. Therefore, ndjson2madb.py can convert the ndjson data to the database in the same format as mac_apt.

### Installing required packages

```zsh
% pip3 install ndjson
```

### Help of ndjson2madb.py

```zsh
% python3 ./ndjson2madb.py -h
usage: ndjson2madb.py [-h] [-i INPUT] -o OUTPUT

Convert the exported Unified Logs with ndjson style to mac_apt UnifiedLogs.db.

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Path to an exported Unified Logs file (Default: - (STDIN))
  -o OUTPUT, --output OUTPUT
                        Path to an output database file (Default: UnifiedLogs.db)

[Exporting Unified Logs Tips]
Exporting all entries of Unified Logs takes a lot of disk space. I recommend using zip command along with to reduce the file size.
% log show --info --debug --style ndjson --timezone 'UTC' | zip ~/Desktop/unifiedlogs_ndjson.zip -

Zipped file can be converted to a database like below:
% unzip -q -c ~/Desktop/unifiedlogs_ndjson.zip | python3 ./ndjson2ma.py -o ./UnifiedLogs.db

[Timezone]
This script does NOT consider timezone. So, you need to run the log command like below:
% log show --info --debug --style ndjson --timezone 'UTC' > /path/to/unifiedlogs.ndjson
```

### How to run ndjson2madb.py

```
% log show --info --debug --style ndjson --timezone 'UTC' | zip ~/Desktop/unifiedlogs_ndjson.zip -
% unzip -q -c ~/Desktop/unifiedlogs_ndjson.zip | python3 ./ndjson2ma.py -o ./UnifiedLogs.db
```

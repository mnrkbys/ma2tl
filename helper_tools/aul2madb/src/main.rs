//
// Copyright 2023 Minoru Kobayashi <unknownbit@gmail.com> (@unkn0wnbit)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//
// parse_log_archive() and parse_trace_file() are borrowed from macos-UnifiedLogs' unifiedlog_parser.
// https://github.com/mandiant/macos-UnifiedLogs/blob/main/examples/unifiedlog_parser/src/main.rs
//

use chrono::{SecondsFormat, TimeZone, Utc};
use clap::{Parser, ValueEnum};
use csv::Writer;
use macos_unifiedlogs::dsc::SharedCacheStrings;
use macos_unifiedlogs::parser::{
    build_log, collect_shared_strings, collect_strings, collect_timesync, parse_log,
};
use macos_unifiedlogs::timesync::TimesyncBoot;
use macos_unifiedlogs::unified_log::{LogData, UnifiedLogData};
use macos_unifiedlogs::uuidtext::UUIDText;
use rusqlite::{params, Connection, Result};
use simplelog::{Config, SimpleLogger};
use std::error::Error;
use std::fs;
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::process;
// use log::LevelFilter;

#[derive(Parser, Debug)]
// #[clap(version, about, long_about = None)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to a logarchive or to a directory that contains exported Unified Logs
    #[clap(short, long)]
    input: String,

    /// Output format
    // #[arg(short = 'f', long, default_value = "sqlite")]
    #[clap(short = 'f', long, default_value = "sqlite")]
    output_format: OutputFormat,

    /// Path to output file
    #[clap(short, long, default_value = "./UnifiedLogs.db")]
    output: String,
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    SQLITE,
    // CSV,
    TSV,
}

fn main() {
    SimpleLogger::init(simplelog::LevelFilter::Warn, Config::default())
        .expect("Failed to initialize simple logger");

    let _args = Args::parse();

    // let input_path = Path::new(&_args.input).canonicalize().unwrap();
    let input_path = dunce::canonicalize(Path::new(&_args.input)).unwrap();
    let output_path = Path::new(&_args.output);

    if !input_path.is_dir() {
        println!(
            "{} is not a logarchive or a directory.",
            &input_path.display()
        );
        process::exit(1);
    }

    if output_path.is_file() {
        println!("{} has been exist.", &output_path.display());
        process::exit(1);
    }

    println!("Staring Unified Logs converter...");

    output_header().unwrap();

    if input_path.display().to_string().ends_with(".logarchive") {
        println!("Processing as a logarchive.");
        parse_log_archive(&input_path.display().to_string());
    } else {
        println!("Processing as exported Unified Logs.");
        parse_exported_logs(&input_path.display().to_string());
    }

    println!(
        "\nFinished parsing Unified Log data. Saved results to: {}",
        &output_path.display()
    );
}

fn parse_exported_logs(path: &str) {
    let mut exported_path = PathBuf::from(path);

    exported_path.push("uuidtext");
    let string_results = collect_strings(&exported_path.display().to_string()).unwrap();

    exported_path.push("dsc");
    let shared_strings_result =
        collect_shared_strings(&exported_path.display().to_string()).unwrap();
    exported_path.pop();
    exported_path.pop();

    exported_path.push("diagnostics");
    exported_path.push("timesync");
    let timesync_data = collect_timesync(&exported_path.display().to_string()).unwrap();
    exported_path.pop();

    parse_trace_file(
        &string_results,
        &shared_strings_result,
        &timesync_data,
        &exported_path.display().to_string(),
    );
}

// Parse a provided directory path. Currently expect the path to follow macOS log collect structure
fn parse_log_archive(path: &str) {
    let mut archive_path = PathBuf::from(path);

    // Parse all UUID files which contain strings and other metadata
    let string_results = collect_strings(&archive_path.display().to_string()).unwrap();

    archive_path.push("dsc");
    // Parse UUID cache files which also contain strings and other metadata
    let shared_strings_results =
        collect_shared_strings(&archive_path.display().to_string()).unwrap();
    archive_path.pop();

    archive_path.push("timesync");
    // Parse all timesync files
    let timesync_data = collect_timesync(&archive_path.display().to_string()).unwrap();
    archive_path.pop();

    // Keep UUID, UUID cache, timesync files in memory while we parse all tracev3 files
    // Allows for faster lookups
    parse_trace_file(
        &string_results,
        &shared_strings_results,
        &timesync_data,
        path,
    );

    // println!("\nFinished parsing Unified Log data. Saved results to: output.csv");
}

// Use the provided strings, shared strings, timesync data to parse the Unified Log data at provided path.
// Currently expect the path to follow macOS log collect structure
fn parse_trace_file(
    string_results: &[UUIDText],
    shared_strings_results: &[SharedCacheStrings],
    timesync_data: &[TimesyncBoot],
    path: &str,
) {
    // We need to persist the Oversize log entries (they contain large strings that don't fit in normal log entries)
    // Some log entries have Oversize strings located in different tracev3 files.
    // This is very rare. Seen in ~20 log entries out of ~700,000. Seen in ~700 out of ~18 million
    let mut oversize_strings = UnifiedLogData {
        header: Vec::new(),
        catalog_data: Vec::new(),
        oversize: Vec::new(),
    };

    // Exclude missing data from returned output. Keep separate until we parse all oversize entries.
    // Then at end, go through all missing data and check all parsed oversize entries again
    let mut exclude_missing = true;
    let mut missing_data: Vec<UnifiedLogData> = Vec::new();

    let mut archive_path = PathBuf::from(path);
    archive_path.push("Persist");

    let mut log_count = 0;
    if archive_path.exists() {
        let paths = fs::read_dir(&archive_path).unwrap();

        // Loop through all tracev3 files in Persist directory
        for log_path in paths {
            let data = log_path.unwrap();
            let full_path = data.path().display().to_string();
            println!("Parsing: {}", full_path);

            let log_data = if data.path().exists() {
                parse_log(&full_path).unwrap()
            } else {
                println!("File {} no longer on disk", full_path);
                continue;
            };

            // Get all constructed logs and any log data that failed to get constrcuted (exclude_missing = true)
            let (results, missing_logs) = build_log(
                &log_data,
                string_results,
                shared_strings_results,
                timesync_data,
                exclude_missing,
            );
            // Track Oversize entries
            oversize_strings
                .oversize
                .append(&mut log_data.oversize.to_owned());

            // Track missing logs
            missing_data.push(missing_logs);
            log_count += results.len();
            output(&results).unwrap();
        }
    }

    archive_path.pop();
    archive_path.push("Special");

    if archive_path.exists() {
        let paths = fs::read_dir(&archive_path).unwrap();

        // Loop through all tracev3 files in Special directory
        for log_path in paths {
            let data = log_path.unwrap();
            let full_path = data.path().display().to_string();
            println!("Parsing: {}", full_path);

            let mut log_data = if data.path().exists() {
                parse_log(&full_path).unwrap()
            } else {
                println!("File {} no longer on disk", full_path);
                continue;
            };

            // Append our old Oversize entries in case these logs point to other Oversize entries the previous tracev3 files
            log_data.oversize.append(&mut oversize_strings.oversize);
            let (results, missing_logs) = build_log(
                &log_data,
                string_results,
                shared_strings_results,
                timesync_data,
                exclude_missing,
            );
            // Track Oversize entries
            oversize_strings.oversize = log_data.oversize;
            // Track missing logs
            missing_data.push(missing_logs);
            log_count += results.len();

            output(&results).unwrap();
        }
    }

    archive_path.pop();
    archive_path.push("Signpost");

    if archive_path.exists() {
        let paths = fs::read_dir(&archive_path).unwrap();

        // Loop through all tracev3 files in Signpost directory
        for log_path in paths {
            let data = log_path.unwrap();
            let full_path = data.path().display().to_string();
            println!("Parsing: {}", full_path);

            let log_data = if data.path().exists() {
                parse_log(&full_path).unwrap()
            } else {
                println!("File {} no longer on disk", full_path);
                continue;
            };

            let (results, missing_logs) = build_log(
                &log_data,
                string_results,
                shared_strings_results,
                timesync_data,
                exclude_missing,
            );

            // Signposts have not been seen with Oversize entries
            missing_data.push(missing_logs);
            log_count += results.len();

            output(&results).unwrap();
        }
    }
    archive_path.pop();
    archive_path.push("HighVolume");

    if archive_path.exists() {
        let paths = fs::read_dir(&archive_path).unwrap();

        // Loop through all tracev3 files in HighVolume directory
        for log_path in paths {
            let data = log_path.unwrap();
            let full_path = data.path().display().to_string();
            println!("Parsing: {}", full_path);

            let log_data = if data.path().exists() {
                parse_log(&full_path).unwrap()
            } else {
                println!("File {} no longer on disk", full_path);
                continue;
            };
            let (results, missing_logs) = build_log(
                &log_data,
                string_results,
                shared_strings_results,
                timesync_data,
                exclude_missing,
            );

            // Oversize entries have not been seen in logs in HighVolume
            missing_data.push(missing_logs);
            log_count += results.len();

            output(&results).unwrap();
        }
    }
    archive_path.pop();

    archive_path.push("logdata.LiveData.tracev3");

    // Check if livedata exists. We only have it if 'log collect' was used
    if archive_path.exists() {
        println!("Parsing: logdata.LiveData.tracev3");
        let mut log_data = parse_log(&archive_path.display().to_string()).unwrap();
        log_data.oversize.append(&mut oversize_strings.oversize);
        let (results, missing_logs) = build_log(
            &log_data,
            string_results,
            shared_strings_results,
            timesync_data,
            exclude_missing,
        );
        // Track missing data
        missing_data.push(missing_logs);
        log_count += results.len();

        output(&results).unwrap();
        // Track oversize entries
        oversize_strings.oversize = log_data.oversize;
        archive_path.pop();
    }

    exclude_missing = false;

    // Since we have all Oversize entries now. Go through any log entries that we were not able to build before
    for mut leftover_data in missing_data {
        // Add all of our previous oversize data to logs for lookups
        leftover_data
            .oversize
            .append(&mut oversize_strings.oversize.to_owned());

        // Exclude_missing = false
        // If we fail to find any missing data its probably due to the logs rolling
        // Ex: tracev3A rolls, tracev3B references Oversize entry in tracev3A will trigger missing data since tracev3A is gone
        let (results, _) = build_log(
            &leftover_data,
            string_results,
            shared_strings_results,
            timesync_data,
            exclude_missing,
        );
        log_count += results.len();

        output(&results).unwrap();
    }
    println!("Parsed {} log entries", log_count);
}

// Create csv file and create headers
fn output_header() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    match args.output_format {
        OutputFormat::SQLITE => {
            output_header_sqlite(&args.output)?;
        }
        // OutputFormat::CSV => {
        //     let csv_file = OpenOptions::new()
        //         .append(true)
        //         .create(true)
        //         .open(args.output)?;
        //     let writer = csv::Writer::from_writer(csv_file);
        //     output_header_csv(writer)?;
        // }
        OutputFormat::TSV => {
            let csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(args.output)?;
            let writer = csv::WriterBuilder::new()
                .delimiter(b'\t')
                .from_writer(csv_file);
            output_header_csv(writer)?;
        }
    }
    Ok(())
}

fn output_header_sqlite(path: &str) -> Result<(), Box<dyn Error>> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", &"WAL")?;
    conn.execute(
        "CREATE TABLE UnifiedLogs (
            File    TEXT,
            DecompFilePos   INTEGER,
            ContinuousTime  TEXT,
            TimeUtc TEXT,
            Thread  INTEGER,
            Type    TEXT,
            ActivityID  INTEGER,
            ParentActivityID    INTEGER,
            ProcessID   INTEGER,
            EffectiveUID INTEGER,
            TTL INTEGER,
            ProcessName TEXT,
            SenderName  TEXT,
            Subsystem   TEXT,
            Category    TEXT,
            SignpostName    TEXT,
            SignpostInfo    TEXT,
            ImageOffset INTEGER,
            SenderUUID  TEXT,
            ProcessImageUUID    TEXT,
            SenderImagePath TEXT,
            ProcessImagePath    TEXT,
            Message TEXT
        );",
        params![],
    )?;
    Ok(())
}

fn output_header_csv(mut writer: Writer<std::fs::File>) -> Result<(), Box<dyn Error>> {
    writer.write_record(&[
        "File",
        "DecompFilePos",
        "ContinuousTime",
        "TimeUTC",
        "Thread",
        "Type",
        "ActivityID",
        "ParentActivityID",
        "ProcessID",
        "EffectiveUID",
        "TTL",
        "ProcessName",
        "SenderName",
        "Subsystem",
        "Category",
        "SignpostName",
        "SignpostInfo",
        "ImageOffset",
        "SenderUUID",
        "ProcessImageUUID",
        "SenderImagePath",
        "ProcessImagePath",
        "Message",
    ])?;
    Ok(())
}

// Append or create csv file
fn output(results: &Vec<LogData>) -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    match args.output_format {
        OutputFormat::SQLITE => {
            // writer = csv::Writer::from_writer(csv_file);
            output_sqlite(&args.output, results)?;
        }
        // OutputFormat::CSV => {
        //     let csv_file = OpenOptions::new()
        //         .append(true)
        //         .create(true)
        //         .open(args.output)?;
        //     // let mut writer = csv::Writer::from_writer(csv_file);
        //     let writer = csv::Writer::from_writer(csv_file);
        //     output_csv(writer, results)?;
        // }
        OutputFormat::TSV => {
            let csv_file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(args.output)?;
            // let mut writer = csv::WriterBuilder::new()
            let writer = csv::WriterBuilder::new()
                .delimiter(b'\t')
                .from_writer(csv_file);
            output_csv(writer, results)?;
        }
    }
    Ok(())
}

fn output_sqlite(path: &str, results: &Vec<LogData>) -> Result<(), Box<dyn Error>> {
    let conn = Connection::open(path)?;
    let mut stmt = conn.prepare("INSERT INTO UnifiedLogs (
                                                File, \
                                                DecompFilePos, \
                                                ContinuousTime, \
                                                TimeUtc, \
                                                Thread, \
                                                Type, \
                                                ActivityID, \
                                                ParentActivityID, \
                                                ProcessID, \
                                                EffectiveUID, \
                                                TTL, \
                                                ProcessName, \
                                                SenderName, \
                                                Subsystem, \
                                                Category, \
                                                SignpostName, \
                                                SignpostInfo, \
                                                ImageOffset, \
                                                SenderUUID, \
                                                ProcessImageUUID, \
                                                SenderImagePath, \
                                                ProcessImagePath, \
                                                Message
                                                )
                                                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, \
                                                        ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, \
                                                        ?20, ?21, ?22, ?23);")?;

    for data in results {
        let date_time = Utc.timestamp_nanos(data.time as i64);

        let process_path = data.process.split("/").collect::<Vec<_>>();
        let process_name = process_path.last().unwrap().to_string();

        let library_path = data.library.split("/").collect::<Vec<_>>();
        let library_name = library_path.last().unwrap().to_string();

        let mut library_uuid = String::new();
        if !data.library_uuid.is_empty() {
            library_uuid = String::from(&data.library_uuid[0..8])
                + "-"
                + &data.library_uuid[8..12]
                + "-"
                + &data.library_uuid[12..16]
                + "-"
                + &data.library_uuid[16..20]
                + "-"
                + &data.library_uuid[20..];
        }

        let mut process_uuid = String::new();
        if !data.process_uuid.is_empty() {
            process_uuid = String::from(&data.process_uuid[0..8])
                + "-"
                + &data.process_uuid[8..12]
                + "-"
                + &data.process_uuid[12..16]
                + "-"
                + &data.process_uuid[16..20]
                + "-"
                + &data.process_uuid[20..];
        }

        stmt.execute(params![
            "".to_string(),
            0.to_string(),
            "0".to_string(),
            date_time.to_rfc3339_opts(SecondsFormat::Micros, true),
            data.thread_id.to_string(),
            data.log_type.to_owned(),
            data.activity_id.to_string(),
            0.to_string(),
            data.pid.to_string(),
            data.euid.to_string(),
            0.to_string(),
            process_name,
            library_name,
            data.subsystem.to_owned(),
            data.category.to_owned(),
            "".to_string(),
            "".to_string(),
            0.to_string(),
            library_uuid.to_string(),
            process_uuid.to_string(),
            data.library.to_owned(),
            data.process.to_owned(),
            data.message.to_owned(),
        ])?;
    }
    stmt.finalize()?;
    conn.close().unwrap();
    Ok(())
}

fn output_csv(
    mut writer: Writer<std::fs::File>,
    results: &Vec<LogData>,
) -> Result<(), Box<dyn Error>> {
    for data in results {
        let date_time = Utc.timestamp_nanos(data.time as i64);

        let process_path = data.process.split("/").collect::<Vec<_>>();
        let process_name = process_path.last().unwrap().to_string();

        let library_path = data.library.split("/").collect::<Vec<_>>();
        let library_name = library_path.last().unwrap().to_string();

        let mut library_uuid = String::new();
        if !data.library_uuid.is_empty() {
            library_uuid = String::from(&data.library_uuid[0..8])
                + "-"
                + &data.library_uuid[8..12]
                + "-"
                + &data.library_uuid[12..16]
                + "-"
                + &data.library_uuid[16..20]
                + "-"
                + &data.library_uuid[20..];
        }

        let mut process_uuid = String::new();
        if !data.process_uuid.is_empty() {
            process_uuid = String::from(&data.process_uuid[0..8])
                + "-"
                + &data.process_uuid[8..12]
                + "-"
                + &data.process_uuid[12..16]
                + "-"
                + &data.process_uuid[16..20]
                + "-"
                + &data.process_uuid[20..];
        }

        writer.write_record(&[
            "".to_string(),
            "0".to_string(),
            "0".to_string(),
            date_time.to_rfc3339_opts(SecondsFormat::Micros, true),
            data.thread_id.to_string(),
            data.log_type.to_owned(),
            data.activity_id.to_string(),
            "0".to_string(),
            data.pid.to_string(),
            data.euid.to_string(),
            "0".to_string(),
            process_name,
            library_name,
            data.subsystem.to_owned(),
            data.category.to_owned(),
            "".to_string(),
            "".to_string(),
            "0".to_string(),
            library_uuid.to_string(),
            process_uuid.to_string(),
            data.library.to_owned(),
            data.process.to_owned(),
            data.message.to_owned(),
        ])?;
    }
    Ok(())
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use env_logger::Builder;
use log::{debug, LevelFilter};
use ron::ser::{self, PrettyConfig};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::{
    borrow::BorrowMut,
    env,
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
    str,
};
use yubihsm::{
    audit::{LogEntries, LogEntry},
    serialization as yh_ser,
};

use yubihsm_audit::{Encoding, Kind};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Perform various operations on the types that represent the YubiHSM2
/// audit log.
struct Args {
    /// Encoding of data provided as input.
    #[clap(long, default_value_t = Encoding::Json, value_enum)]
    inform: Encoding,

    /// Path to input data file. If omitted input is read from `stdin`.
    #[clap(long)]
    input: Option<PathBuf>,

    /// command
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Calculate the truncated Sha256 hash of the provide LogEntry data.
    Hash,

    /// Split a LogEntries structure into the component LogEntry structures.
    /// These are written to individual files named according to the input
    /// file and the LogEntry 'item' field.
    Split {
        #[clap(long, default_value_t = Encoding::Json, value_enum)]
        outform: Encoding,

        /// Directory where the serialized encoding of LogEntry structures
        /// are written. The default is $(pwd).
        #[clap(long)]
        workdir: Option<PathBuf>,

        /// Prefix used for output files. Output will be in the form:
        /// {prefix}-{item}.json where:
        /// - `prefix` is the string provided here
        /// - `item` is the item number from the LogEntry
        #[clap(long, default_value_t = String::from("logentry"))]
        prefix: String,
    },

    /// Transform YubiHSM 2 `LogEntries` and `LogEntry` types between
    /// encodings.
    Xfrm {
        /// The YubiHSM type that will be deserialized from the input file.
        #[clap(long, default_value_t = Kind::LogEntry, value_enum)]
        kind: Kind,

        /// Encoding of output data.
        #[clap(long, default_value_t = Encoding::Json, value_enum)]
        outform: Encoding,

        /// Path to location where output data is written. If omitted output
        /// is written to `stdout`.
        #[clap(long)]
        output: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    builder.filter(None, LevelFilter::Debug).init();

    // if args.input file not provided use stdin
    let mut reader: Box<dyn Read> = match args.input {
        Some(i) => Box::new(File::open(i)?),
        None => Box::new(io::stdin()),
    };

    match args.command {
        Command::Hash => do_hash(&mut reader, args.inform),
        Command::Split {
            outform,
            workdir,
            prefix,
        } => do_split(&mut reader, args.inform, outform, workdir, prefix),
        Command::Xfrm {
            kind,
            outform,
            output,
        } => do_xfrm(&mut reader, args.inform, kind, outform, output),
    }
}

// Calculate the sha256 digest of a LogEtnry.
fn do_hash<R: Read>(reader: &mut R, inform: Encoding) -> Result<()> {
    // Holds the data fed into the hash function.
    // https://developers.yubico.com/YubiHSM2/Commands/Get_Log_Entries.html
    // calls this `E<sub>i</sub>.Data`.
    let mut buf: Vec<u8> = vec![0u8; 32];

    match inform {
        // if it's already encoded as binary just hash it
        Encoding::Bin => reader.read_exact(&mut buf)?,
        // else we must serialize it to binary before we hash it
        e => {
            // filling the vec by way of the `Write` trait will append all
            // data & we've declared a vec w/ 32 elements: they must be cleared
            buf.clear();
            let entry: LogEntry = deserialize(reader, &e)?;
            serialize(&entry, &mut buf, &Encoding::Bin)?
        }
    };

    debug!("buf: {:?}", &buf);
    debug!("hashing {:?}", &buf[..16]);

    let mut hasher = Sha256::new();
    hasher.update(&buf[..16]);

    // get hash string for truncated sha256 sum
    let digest = hex::encode(hasher.finalize());

    println!("{}", digest);

    Ok(())
}

fn do_split<R: Read>(
    reader: &mut R,
    inform: Encoding,
    outform: Encoding,
    workdir: Option<PathBuf>,
    prefix: String,
) -> Result<()> {
    let log_entries: LogEntries = deserialize(reader, &inform)?;

    // can my closure return an error here?
    let mut workdir = match workdir {
        Some(p) => p,
        None => env::current_dir()?,
    };

    for entry in log_entries.entries {
        workdir.push(format!("{}-{}.json", prefix, entry.item));
        let mut writer = Box::new(File::create(&workdir)?);
        serialize(entry, &mut writer, &outform)?;
        workdir.pop();
    }

    Ok(())
}

fn do_xfrm<R: Read>(
    reader: &mut R,
    inform: Encoding,
    kind: Kind,
    outform: Encoding,
    output: Option<PathBuf>,
) -> Result<()> {
    // if args.output file not provided use stdout
    let mut writer: Box<dyn Write> = match output {
        Some(o) => Box::new(File::create(o)?),
        None => Box::new(io::stdout()),
    };

    match kind {
        Kind::LogEntries => {
            let l: LogEntries = deserialize(reader, &inform)?;
            serialize(l, &mut writer, &outform)
        }
        Kind::LogEntry => {
            let l: LogEntry = deserialize(reader, &inform)?;
            serialize(l, &mut writer, &outform)
        }
    }
}

fn deserialize<T: DeserializeOwned, R: Read>(
    reader: &mut R,
    inform: &Encoding,
) -> Result<T> {
    let mut bytes: Vec<u8> = Vec::new();
    reader.read_to_end(&mut bytes)?;

    match inform {
        Encoding::Bin => Ok(yh_ser::deserialize(&bytes)?),
        Encoding::Json => Ok(serde_json::from_slice(&bytes)?),
        Encoding::Ron => Ok(ron::de::from_bytes(&bytes)?),
    }
}

fn serialize<T: Serialize, W: Write>(
    t: T,
    writer: &mut W,
    outform: &Encoding,
) -> Result<()> {
    match outform {
        Encoding::Bin => {
            let out = yh_ser::serialize(&t)?;
            writer.write_all(&out)?;
        }
        Encoding::Json => {
            serde_json::to_writer_pretty(writer.borrow_mut(), &t)?
        }
        Encoding::Ron => ser::to_writer_pretty(
            writer.borrow_mut(),
            &t,
            PrettyConfig::default(),
        )?,
    }

    Ok(writer.flush()?)
}

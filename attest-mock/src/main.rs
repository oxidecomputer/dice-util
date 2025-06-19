// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::{Parser, Subcommand};
use miette::{IntoDiagnostic, Result, miette};
use std::{
    fs,
    io::{self, Write},
    path::PathBuf,
};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Structure to mock from KDL
    #[command(subcommand)]
    cmd: Command,

    /// path to KDL file
    kdl: PathBuf,
}

/// Known types
#[derive(Debug, Subcommand)]
enum Command {
    /// Parse KDL describing rats_corim::Corim and produce CBOR encoded Corim
    Corim,

    /// Parse KDL describing attest_data::Log and produce hubpacked Log
    Log,
}

mod corim;
mod log;

fn main() -> Result<()> {
    let args = Args::parse();

    let name = args.kdl.to_string_lossy();
    let kdl = fs::read_to_string(&args.kdl)
        .into_diagnostic()
        .map_err(|e| miette!("failed to read file {name} to string: {e}"))?;

    let out = match args.cmd {
        Command::Corim => corim::mock(&name, &kdl)?,
        Command::Log => log::mock(&name, &kdl)?,
    };

    io::stdout()
        .write_all(&out)
        .into_diagnostic()
        .map_err(|e| miette!("failed to write to stdout: {e}"))
}

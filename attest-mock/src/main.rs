// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::{
    io::{self, Write},
    path::PathBuf,
};

use attest_mock::{MockCorim, MockData, MockLog};

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

fn main() -> Result<()> {
    let args = Args::parse();

    let out = match args.cmd {
        Command::Corim => {
            let mock = MockCorim::load(&args.kdl)?;
            mock.to_bytes()?
        }
        Command::Log => {
            let mock = MockLog::load(&args.kdl)?;
            mock.to_bytes()?
        }
    };

    Ok(io::stdout().write_all(&out)?)
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use clap::Parser;
use clap_verbosity::{InfoLevel, Verbosity};
use log::debug;

use std::{
    collections::BTreeMap,
    convert::TryFrom,
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::PathBuf,
};

/// For each sample read from the provided file / `stdin`, calculate it's
/// distance from the mean in units of the standard deviation. It then
/// categorizes each sample into a z-score band and reports the number
/// of samples that fall into each band to `stdout`.
// Ex:
// 0 10
// 1 6
// 3 9
//
// The numbers in the first column identify the band where:
//
// - `0` is for samples that fall within 1 standard deviation of the mean
// - `1` '' between 1 and 2 ''
// - `3` '' between 3 and 4 ''
//
// The numbers in the second column is the number of samples within each band
//
// Samples are read from the provided file or `stdin`.
// Samples must be formatted as one u32 as base10 string per line.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Dump debug output
    #[command(flatten)]
    verbose: Verbosity<InfoLevel>,

    /// Calculate distance from this mean.
    #[clap(long)]
    mean: u32,

    /// Stepping for distance calculation.
    #[clap(long)]
    std_dev: u32,

    /// Path to file holding samples (or stdin if omitted).
    #[clap(long)]
    input: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // if args.input file not provided use stdin
    let reader: Box<dyn Read> = match args.input {
        Some(i) => Box::new(
            File::open(&i)
                .with_context(|| format!("open file: {}", &i.display()))?,
        ),
        None => Box::new(io::stdin()),
    };
    let reader = BufReader::new(reader);

    env_logger::Builder::new()
        .filter_level(args.verbose.log_level_filter())
        .init();

    // we only accept the `mean` input by the user as a u32 but we do signed
    // arithmetic with it so this conversion is necessary
    let mean = i32::try_from(args.mean).context("mean to i32")?;

    // same for the `std-dev` but there's no checked conversion:
    // https://internals.rust-lang.org/t/tryfrom-for-f64/9793
    let std_dev = args.std_dev as f32;

    let mut std_dev_map = BTreeMap::new();

    for line in reader.lines() {
        let line = line.context("read line")?;
        let sample: i32 = line.parse().context("parse u32 from str")?;

        let diff_abs = (mean - sample).abs();
        let std_devs = (diff_abs as f32 / std_dev).trunc() as u32;

        debug!(
            "{sample} is {std_devs} std devs ({std_dev}) from the mean ({mean})"
        );

        if let Some(val) = std_dev_map.get_mut(&std_devs) {
            *val += 1;
        } else {
            std_dev_map.insert(std_devs, 1);
        }
    }

    for (std_devs, count) in std_dev_map.iter() {
        println!("{std_devs} {count}");
    }

    Ok(())
}

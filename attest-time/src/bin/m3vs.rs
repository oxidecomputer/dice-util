// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// This code implements Welford's method for calculating mean and variance
// from streaming data as described here:
// https://jonisalonen.com/2013/deriving-welfords-method-for-computing-variance/
// The TLDR is:
// variance(samples):
//  M := 0
//  S := 0
//  for k from 1 to N:
//    x := samples[k]
//    oldM := M
//    M := M + (x-M)/k
//    S := S + (x-M)*(x-oldM)
//  return S/(N-1)
//
//  where:
//  - M is the mean
//  - S is the squared distance from the mean

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read},
    path::PathBuf,
};

/// Read input samples formatted as a single sample per line. Each sample is
/// an positive integer that can fit in a u32. This is the same format emitted
/// by `attest-time`.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// An optional input file. If omitted stdin will be read.
    input: Option<PathBuf>,
}

/// This strcture holds data used to generate some measures of central
/// tendency and dispersion
struct Data {
    /// `count` is a float because it's mostly used as the denominator in the
    /// mean and variance calculation
    count: u32,
    /// collection used to collect input data
    /// TODO: we can get rid of this once we're confident in our impl of the
    /// Welford's algorithms
    durations: Vec<u32>,
    /// `max` is the running max for the dataset
    max: u32,
    /// `mean` holds the running mean calculated w/ Welford's method
    mean: f64,
    /// the running min for the dataset
    min: u32,
    /// `distance_2` is the running squared distance from the mean calculated
    /// w/ Welford's method
    distance_2: f64,
}

/// impl `Default` manually to set initial value for `min`
impl Default for Data {
    fn default() -> Self {
        Self {
            count: 0,
            distance_2: 0.0,
            max: 0,
            mean: 0.0,
            min: u32::MAX,
            durations: Vec::new(),
        }
    }
}

/// my naive and expensive mean calculation
fn mean(durations: &Vec<u32>, count: u32) -> Result<u32> {
    let mut total: u128 = 0;
    for v in durations {
        // data in the durations collection is u32, this conversion is safe
        total += *v as u128;
    }

    let mean = total / count as u128;
    u32::try_from(mean).context("mean u128 to u32")
}

/// my naive and expensive variance calculation
fn variance(durations: &Vec<u32>, count: u32, mean: u32) -> Result<u32> {
    // accumulate sum of the squared difference between each sample and the mean
    // this is the numerator in the classic variance equation
    let mut variance: u128 = 0;
    for v in durations {
        let diff = *v as i128 - mean as i128;
        let square = i128::pow(diff, 2);
        variance += square as u128;
    }

    let variance = variance / count as u128 - 1;
    Ok(variance as u32)
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

    let mut data = Data::default();

    for line in reader.lines() {
        let line = line.context("read line")?;
        let words: Vec<&str> = line.split_whitespace().collect();
        if words.len() != 1 {
            return Err(anyhow!("malformed line"));
        }

        let micros: u32 = words[0].parse().context("parse u32 from str")?;

        if micros < data.min {
            data.min = micros;
        }

        if micros > data.max {
            data.max = micros;
        }

        data.count = data
            .count
            .checked_add(1)
            .ok_or(anyhow!("too many samples: count overflow"))?;

        data.durations.push(micros);

        let micros = f64::from(micros);
        let old_mean = data.mean;
        data.mean = data.mean + (micros - data.mean) / (data.count as f64);
        data.distance_2 += (micros - data.mean) * (micros - old_mean);
    }

    println!("sample count: {}", data.count);
    println!("min: {}", data.min);
    println!("max: {}", data.max);

    // streaming mean, variance, & standard deviation
    {
        println!("welford's mean: {}", data.mean);

        // final calculation from welford's method for variance
        // return S/(n-1)
        let variance = data.distance_2 / f64::from(data.count - 1);
        println!("welford's variance: {}", variance);

        println!("welford's standard deviation: {}", variance.sqrt());
    }

    // classic mean, variance, & standard deviation
    {
        let mean = mean(&data.durations, data.count)
            .context("calculate mean from dataset")?;
        println!("mean: {mean}");

        let variance = variance(&data.durations, data.count, mean)
            .context("calculate variance from dataset")?;
        println!("variance: {variance}");

        let sqrt = f64::from(variance).sqrt();
        println!("standard deviation: {}", sqrt);
    }

    Ok(())
}

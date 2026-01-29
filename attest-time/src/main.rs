// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use dice_verifier::{
    Attest, Nonce, Nonce32,
    hiffy::{AttestHiffy, AttestTask},
    ipcc::AttestIpcc,
};
use std::{
    fmt,
    io::{self, Write},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::SystemTime,
};

#[derive(Clone, Debug, ValueEnum)]
enum Interface {
    Ipcc,
    Hiffy,
}

#[derive(Clone, Debug, ValueEnum)]
enum Unit {
    Milli,
    Micro,
    Nano,
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Unit::Milli => write!(f, "ms"),
            Unit::Micro => write!(f, "µs"),
            Unit::Nano => write!(f, "ns"),
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum Commands {
    Attest,
    GetCertChains,
    GetMeasurementLogs,
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Command from the vm_attest_trait::AttestMock to sample.
    #[clap(value_enum, long, default_value_t = Commands::Attest)]
    command: Commands,

    /// Number of samples to collect. If `None` then collect samples until
    /// canceled.
    #[clap(long)]
    count: Option<usize>,

    /// Interface used for communication with the Attest task.
    #[clap(value_enum, long, default_value_t = Interface::Ipcc)]
    interface: Interface,

    /// Unit of time used for each sample
    #[clap(value_enum, long, default_value_t = Unit::Nano)]
    units: Unit,
}

/// This program gets an attestation through the mock VM attestation API. We
/// get a timestamp from the system before and after. The caller can use this
/// to roughtly determine the performance characteristics of this API / the
/// underlying machinery.
fn main() -> Result<()> {
    let args = Args::parse();

    // set to `false` when terminated w/ Ctrl-C
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .context("set Ctrl-C handler")?;

    // use stdout & `writeln!` so we can handle errors that would panic
    // `println!`
    let mut stdout = io::stdout().lock();

    let attest: Box<dyn Attest> = match args.interface {
        Interface::Ipcc => {
            Box::new(AttestIpcc::new().context("create OxAttestIpcc")?)
        }
        Interface::Hiffy => Box::new(AttestHiffy::new(AttestTask::Rot)),
    };

    // we do not care about the nonce, all 0's will require the same amount of
    // work from the underlying impl
    let nonce = Nonce::N32(Nonce32 { 0: [0u8; 32] });

    // time calls to `VmInstanceAttestMock::attest`, output duration in µs
    let mut count: usize = 0;
    while running.load(Ordering::SeqCst) {
        let time = SystemTime::now();

        match args.command {
            Commands::Attest => {
                let _ = attest
                    .attest(&nonce)
                    .context("get attestation from Attest impl")?;
            }
            Commands::GetCertChains => {
                let _ = attest
                    .get_certificates()
                    .context("get cert chains from Attest impl")?;
            }
            Commands::GetMeasurementLogs => {
                let _ = attest
                    .get_measurement_log()
                    .context("get measurement logs from Attest impl")?;
            }
        }

        let elapsed = time
            .elapsed()
            .context("get elapsed time after attestation")?;

        let duration = match args.units {
            Unit::Milli => elapsed.as_millis(),
            Unit::Micro => elapsed.as_micros(),
            Unit::Nano => elapsed.as_nanos(),
        };

        // `writeln` returns `BrokenPipe` if we pipe output to another process
        // and it closes its stdin (usually Ctrl-C). In this case we suppress
        // the error and exit quietly
        match writeln!(stdout, "{}", duration) {
            Ok(_) => stdout.flush().context("flush stdout")?,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::BrokenPipe {
                    running.store(false, Ordering::SeqCst);
                    eprintln!("stdout closed");
                }
            }
        }

        // break the loop if the caller has provided a `--count` & we've
        // reached it
        count = count.checked_add(1).context("add new 1 to count")?;
        if let Some(max_count) = args.count
            && max_count <= count
        {
            break;
        }
    }

    stdout.flush().context("flush stdout")?;

    Ok(())
}

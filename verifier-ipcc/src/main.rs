// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Result};
use attest_data::messages::{HostToRotCommand, RotToHost};
use attest_data::Log;
use clap::Parser;
use libipcc::IpccHandle;
use std::path::PathBuf;

// A slight hack. These are only defined right now in the `ffi` part
// of libipcc which isn't available on non-illumos targets. Probably
// indicates those constants belong elsewhere...
const IPCC_MAX_DATA_SIZE: usize = 4123 - 19;

/// Commands for atttestaion supported over IPCC
#[derive(Debug, Parser)]
enum Command {
    /// Retreive the measurement log
    MeasurementLog,
    /// Retreive the certificate chain
    Certificates,
    /// Generate an attestation using the provided nonce
    Attest {
        #[clap(long)]
        nonce: PathBuf,
    },
    /// Verify the log against the given set of measurements
    VerifyLog {
        #[clap(long)]
        reference: PathBuf,
    },
}

/// Execute attest command over IPCC,
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Command to execute
    #[clap(subcommand)]
    command: Command,
    /// Path to save output
    #[clap(long)]
    out: PathBuf,
}

pub struct Ipcc {
    handle: IpccHandle,
}

impl Ipcc {
    /// Creates a new `Ipcc` instance.
    pub fn new() -> Result<Self> {
        let handle =
            IpccHandle::new().map_err(|e| anyhow!("Ipcc error {}", e))?;
        Ok(Self { handle })
    }

    pub fn get_measurement_log(&self) -> Result<Vec<u8>> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetTqCertificates,
            |_| 0,
        )
        .map_err(|e| anyhow!("serialize {}", e))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotTqCertificates,
        )
        .map_err(|e| anyhow!("bad response {:?}", e))?;
        Ok(data.to_vec())
    }
}

fn main() -> Result<()> {
    let handle = Ipcc::new()?;

    let args = Args::parse();

    match args.command {
        Command::MeasurementLog => {
            let log = handle.get_measurement_log()?;

            // do a check that what we got back is a Real Log
            let _ = hubpack::deserialize::<Log>(&log)
                .map_err(|e| anyhow!("Failed to deserialize Log: {}", e))?;

            std::fs::write(&args.out, &log)?;
            println!("Binary log written to {:?}", args.out);
        }
        Command::VerifyLog { reference } => {
            let corim = corim_experiments::Corim::from_file(reference)?;

            let log = handle.get_measurement_log()?;

            // do a check that what we got back is a Real Log
            let (log, _) = hubpack::deserialize::<Log>(&log)
                .map_err(|e| anyhow!("Failed to deserialize Log: {}", e))?;

            dice_verifier::verify_log(&log, &corim)?;

            println!("Done.");
        }
        _ => todo!(),
    }
    Ok(())
}

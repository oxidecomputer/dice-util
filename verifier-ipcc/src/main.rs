// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Result};
use attest_data::messages::{HostToRotCommand, RotToHost};
use attest_data::{Attestation, Log, Nonce};
use clap::Parser;
use dice_verifier::PkiPathSignatureVerifier;
use libipcc::IpccHandle;
use log::{debug, info};
use std::path::PathBuf;
use x509_cert::{
    der::{self, Decode, DecodePem, Encode, Reader},
    Certificate,
};

// A slight hack. These are only defined right now in the `ffi` part
// of libipcc which isn't available on non-illumos targets. Probably
// indicates those constants belong elsewhere...
const IPCC_MAX_DATA_SIZE: usize = 4123 - 19;

/// Commands for atttestaion supported over IPCC
#[derive(Debug, Parser)]
enum Command {
    /// Retreive the measurement log
    Log {
        /// Path to save log
        #[clap(long)]
        out: PathBuf,
    },
    /// Retreive the certificate chain
    PrintCertChain {
        /// Optionally verify the cert chain
        #[clap(long)]
        verify: bool,
        /// Use a root certicate for verification
        #[clap(long)]
        ca_cert: Option<PathBuf>,
    },
    /// Generate an attestation using the provided nonce
    Attest {
        #[clap(long)]
        nonce: PathBuf,
        #[clap(long)]
        out: PathBuf,
    },
    /// Verify signature over the attesattion
    VerifyAttestation {
        /// Path to the file holding the attestation
        #[clap(long)]
        attestation: PathBuf,
        /// Path to the file containing the log
        #[clap(long)]
        log: PathBuf,
        /// Path to file containing the nonce
        #[clap(long)]
        nonce: PathBuf,
    },
    /// Generates a nonce, attestation and verifies it
    VerifyRoundTrip {
        /// Path to file holding trust anchor for the associated PKI.
        #[clap(
            long,
            env = "VERIFIER_CLI_CA_CERT",
            conflicts_with = "self_signed"
        )]
        ca_cert: Option<PathBuf>,

        /// Verify the final cert in the provided PkiPath against itself.
        #[clap(long, env, conflicts_with = "ca_cert")]
        self_signed: bool,
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
            &HostToRotCommand::GetMeasurementLog,
            |_| 0,
        )
        .map_err(|e| anyhow!("serialize {}", e))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotMeasurementLog,
        )
        .map_err(|e| anyhow!("bad response {:?}", e))?;
        Ok(data.to_vec())
    }

    pub fn get_certificates(&self) -> Result<Vec<Certificate>> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::GetCertificates,
            |_| 0,
        )
        .map_err(|e| anyhow!("serialize {}", e))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let cert_chain_bytes = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotCertificates,
        )
        .map_err(|e| anyhow!("bad response {:?}", e))?;

        let mut idx = 0;

        let mut certs = vec![];
        // Turn the DER chain into something we can actually use
        while idx < cert_chain_bytes.len() {
            let reader = der::SliceReader::new(&cert_chain_bytes[idx..])?;
            let header = reader.peek_header()?;
            // DER certificates are supposed to be a `Sequence`.
            // We could check that here but we're going to get better
            // error messages by letting the cert parsing code say
            // exactly what went wrong
            let seq_len: usize = header.length.try_into()?;
            let tag_len: usize = header.encoded_len()?.try_into()?;
            // Total len = length from the sequence plus the tag itself
            let end = idx + seq_len + tag_len;

            certs.push(Certificate::from_der(&cert_chain_bytes[idx..end])?);
            idx += seq_len + tag_len;
        }

        Ok(certs)
    }

    pub fn attest(&self, nonce: &[u8]) -> Result<Vec<u8>> {
        let mut rot_message = vec![0; attest_data::messages::MAX_REQUEST_SIZE];
        let mut rot_resp = vec![0; IPCC_MAX_DATA_SIZE];
        let len = attest_data::messages::serialize(
            &mut rot_message,
            &HostToRotCommand::Attest,
            |buf| {
                buf[..nonce.len()].copy_from_slice(&nonce);
                32
            },
        )
        .map_err(|e| anyhow!("serialize {}", e))?;
        let len = self
            .handle
            .rot_request(&rot_message[..len], &mut rot_resp)?;
        let data = attest_data::messages::parse_response(
            &rot_resp[..len],
            RotToHost::RotAttestation,
        )
        .map_err(|e| anyhow!("bad response {:?}", e))?;
        Ok(data.to_vec())
    }
}

fn main() -> Result<()> {
    let handle = Ipcc::new()?;

    let args = Args::parse();

    match args.command {
        Command::Log { out } => {
            let log = handle.get_measurement_log()?;

            std::fs::write(&out, &log)?;
            println!("Binary log written to {:?}", out);

            // do a check that what we got back is a Real Log
            let (log, _) = hubpack::deserialize::<Log>(&log)
                .map_err(|e| anyhow!("Failed to deserialize Log: {}", e))?;

            info!("Log entries:");
            for (i, entry) in log.iter().enumerate() {
                info!("{}: {:x?}", i, entry);
            }
        }
        Command::PrintCertChain { verify, ca_cert } => {
            let chain = handle.get_certificates()?;

            for cert in &chain {
                info!("Certificate => {}", cert.tbs_certificate.subject);
                debug!("Full certificate => {cert:?}");
            }

            if verify {
                let root = match ca_cert {
                    Some(r) => {
                        let root = std::fs::read(r)?;
                        Some(Certificate::from_pem(root)?)
                    }
                    None => None,
                };

                let verifier = PkiPathSignatureVerifier::new(root)?;
                verifier.verify(&chain)?;
            } else {
                println!("Skipping chain validation");
            }
        }
        Command::Attest { nonce, out } => {
            let nonce = std::fs::read(nonce)?;
            let nonce = Nonce::try_from(&nonce[..])?;

            let attest = handle.attest(&nonce.as_ref())?;

            std::fs::write(&out, &attest)?;
            info!("Wrote attestation to {:?}", out);
        }
        Command::VerifyAttestation {
            attestation,
            log,
            nonce,
        } => {
            let nonce = std::fs::read(nonce)?;
            let nonce = Nonce::try_from(&nonce[..])?;

            let log = std::fs::read(log)?;

            let attestation = std::fs::read(attestation)?;
            let (attestation, _) = hubpack::deserialize::<Attestation>(
                &attestation,
            )
            .map_err(|e| anyhow!("Failed to deserialize Attestation: {}", e))?;

            let chain = handle.get_certificates()?;

            dice_verifier::verify_attestation(
                &chain[0],
                &attestation,
                &log,
                &nonce,
            )?;
        }
        _ => todo!(),
    }
    Ok(())
}

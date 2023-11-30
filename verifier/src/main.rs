// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use env_logger::Builder;
use log::{debug, LevelFilter};
use std::{
    fmt::{self, Debug, Formatter},
    io::{self, Read, Write},
    path::Path,
    process::{Command, Output},
};

/// Execute HIF operations exposed by the RoT Attest task.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Interface used for communication with the Attest task.
    #[clap(value_enum, long, env, default_value_t = Interface::Rot)]
    interface: Interface,

    /// Attest task command to execute.
    #[command(subcommand)]
    command: AttestCommand,

    /// verbosity
    #[clap(long, env)]
    verbose: bool,
}

/// An enum of the HIF operations supported by the `Attest` interface.
#[derive(Debug, Subcommand)]
enum AttestCommand {
    /// Get a certificate from the Attest task.
    Cert {
        /// Index of certificate in certificate chain.
        #[clap(long, env)]
        index: u32,
    },
    /// Get the length of the certificate chain that ties the key used by the
    /// `Attest` task to sign attestations back to some PKI. This chain may be
    /// self signed or will terminate at the intermediate before the root.
    CertChainLen,
    /// get the length of the certificate at the provided index.
    CertLen {
        /// Index of certificate in certificate chain.
        #[clap(long, env)]
        index: u32,
    },
    /// Get the log of measurements recorded by the RoT.
    Log,
    /// Get the length in bytes of the Log.
    LogLen,
    /// Get an attestation.
    /// NOTE: The nonce is generated from the platform RNG. Future work may
    /// allow providing it as a parameter.
    Quote,
    /// Get the length in bytes of attestations.
    QuoteLen,
    /// Report a measurement to the `Attest` task for recording in the
    /// measurement log.
    Record,
}

/// An enum of the possible routes to the `Attest` task.
#[derive(Clone, Debug, ValueEnum)]
enum Interface {
    Rot,
    Sprot,
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Interface::Rot => write!(f, "Attest"),
            Interface::Sprot => write!(f, "Sprot"),
        }
    }
}

/// A type to simplify the execution of the HIF operations exposed by the RoT
/// Attest task.
struct AttestHiffy {
    /// The Attest task can be reached either directly through the `hiffy`
    /// task in the RoT or through the `Sprot` task in the Sp. This member
    /// determins which is used.
    interface: Interface,
}

impl AttestHiffy {
    const CHUNK_SIZE: usize = 256;

    fn new(interface: Interface) -> Self {
        AttestHiffy { interface }
    }

    /// `humility` returns u32s as hex strings prefixed with "0x". This
    /// function expects a string formatted like an output string from hiffy
    /// returning a u32. If the string is not prefixed with "0x" it is assumed
    /// to be decimal. Currently this function ignores the interface and
    /// operation names from the string. Future work may check that these are
    /// consistent with the operation executed.
    fn u32_from_cmd_output(output: Output) -> Result<u32> {
        if output.status.success() {
            // check interface & operation name?
            let output = String::from_utf8_lossy(&output.stdout);
            let output: Vec<&str> = output.trim().split(' ').collect();
            let output = output[output.len() - 1];
            debug!("output: {}", output);

            let (output, radix) = match output.strip_prefix("0x") {
                Some(s) => {
                    debug!("prefix stripped: \"{}\"", s);
                    (s, 16)
                }
                None => (output, 10),
            };

            let log_len =
                u32::from_str_radix(output, 16).with_context(|| {
                    format!(
                        "Failed to parse \"{}\" as base {} u32",
                        output, radix
                    )
                })?;

            debug!("output u32: {}", log_len);

            Ok(log_len)
        } else {
            Err(anyhow!(
                "command failed with status: {}\nstdout: \"{}\"\nstderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    /// This convenience function encapsulates a pattern common to
    /// the hiffy command line for the `Attest` operations that get the
    /// lengths of the data returned in leases.
    fn get_len_cmd(&self, op: &str, args: Option<String>) -> Result<u32> {
        // rely on environment for target & archive?
        // check that they are set before continuing
        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg("--call");
        cmd.arg(format!("{}.{}", self.interface, op));
        if let Some(a) = args {
            cmd.arg(format!("--arguments={}", a));
        }
        debug!("executing command: {:?}", cmd);

        let output = cmd.output()?;
        Self::u32_from_cmd_output(output)
    }

    /// Get length of the certificate chain from the Attest task. This cert
    /// chain may be self signed or will terminate at the intermediate before
    /// the root.
    fn cert_chain_len(&self) -> Result<u32> {
        self.get_len_cmd("cert_chain_len", None)
    }

    /// Get length of the certificate at the provided index in bytes.
    fn cert_len(&self, index: u32) -> Result<u32> {
        self.get_len_cmd("cert_len", Some(format!("index={}", index)))
    }

    /// Get a chunk of the measurement log defined by `offset` and `length`.
    /// The chunk is written to `output` as a byte stream.
    fn log_cmd(
        &self,
        offset: usize,
        length: usize,
        output: &Path,
    ) -> Result<()> {
        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg(format!("--call={}.log", self.interface));
        cmd.arg(format!("--num={}", length));
        cmd.arg("--arguments");
        cmd.arg(format!("offset={}", offset));
        cmd.arg(format!("--output={}", output.to_string_lossy()));
        debug!("executing command: {:?}", cmd);

        let output = cmd.output()?;
        if output.status.success() {
            debug!("output: {}", String::from_utf8_lossy(&output.stdout));
            Ok(())
        } else {
            Err(anyhow!(
                "command failed with status: {}\nstdout: \"{}\"\nstderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    /// Get measurement log. This function assumes that the vector provided
    /// is sufficiently large to hold the log.
    fn log(&self, out: &mut Vec<u8>) -> Result<()> {
        for offset in
            (0..out.len() - Self::CHUNK_SIZE).step_by(Self::CHUNK_SIZE)
        {
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.log_cmd(offset, Self::CHUNK_SIZE, tmp.path())?;
            tmp.read_exact(&mut out[offset..Self::CHUNK_SIZE])?;
        }

        let remain = out.capacity() % Self::CHUNK_SIZE;
        if remain != 0 {
            let offset = out.len() - remain;
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.log_cmd(offset, remain, tmp.path())?;
            tmp.read_exact(&mut out[offset..])?;
        }

        Ok(())
    }

    /// Get length of the measurement log in bytes.
    fn log_len(&self) -> Result<u32> {
        self.get_len_cmd("log_len", None)
    }

    /// Get length of the measurement log in bytes.
    fn quote_len(&self) -> Result<u32> {
        self.get_len_cmd("quote_len", None)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Warn
    };
    builder.filter(None, level).init();

    let attest = AttestHiffy::new(args.interface);

    match args.command {
        AttestCommand::Cert { index } => {
            todo!("AttestCommand::Cert: index={}", index)
        }
        AttestCommand::CertChainLen => println!("{}", attest.cert_chain_len()?),
        AttestCommand::CertLen { index } => {
            println!("{}", attest.cert_len(index)?)
        }
        AttestCommand::Log => {
            let log_len = attest.log_len()?;
            let mut out = vec![0u8; log_len as usize];
            attest.log(&mut out)?;

            io::stdout().write_all(&out)?;
            io::stdout().flush()?;
        }
        AttestCommand::LogLen => println!("{}", attest.log_len()?),
        AttestCommand::Quote => todo!("AttestCommand::Quote"),
        AttestCommand::QuoteLen => println!("{}", attest.quote_len()?),
        AttestCommand::Record => todo!("AttestCommand::Record"),
    }

    Ok(())
}

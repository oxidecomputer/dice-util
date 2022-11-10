// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::{Parser, Subcommand};
use dice_mfg::Result;
use dice_mfg_msgs::SerialNumber;
use env_logger::Builder;
use log::{info, LevelFilter};
use std::{path::PathBuf, result, str};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Send commands to the RoT for DeviceId certification.
struct Args {
    /// serial port device path
    #[clap(long, default_value = "/dev/ttyACM0", env)]
    serial_dev: String,

    /// baud rate
    #[clap(long, default_value = "9600", env)]
    baud: u32,

    /// command
    #[command(subcommand)]
    command: Command,

    /// verbosity
    #[clap(long, env)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    Break,
    GetCsr {
        /// Destination path for CSR, stdout if omitted
        csr_path: Option<PathBuf>,
    },
    Liveness {
        /// Maximum number of retries in liveness test.
        #[clap(default_value = "10")]
        max_retry: u8,
    },
    Manufacture {
        /// Path to openssl.cnf file used for signing operation.
        #[clap(long, env)]
        openssl_cnf: PathBuf,

        /// CA section from openssl.cnf used for signing operation.
        /// If omitted default from openssl.cnf is used.
        #[clap(long, env)]
        ca_section: Option<String>,

        /// x509 v3 extension section from openssl.cnf used for signing operation.
        /// If omitted default from openssl.cnf is used.
        #[clap(long, env)]
        v3_section: Option<String>,

        /// engine section from openssl.cnf used for signing operation.
        /// If omitted openssl will fall back to files.
        #[clap(long, env)]
        engine_section: Option<String>,

        /// Maximum number of retries in liveness test.
        #[clap(long, default_value = "10")]
        max_retry: u8,

        /// Path to intermediate cert sent to manufactured system.
        #[clap(long, env)]
        intermediate_cert: PathBuf,

        /// Platform serial number
        #[clap(value_parser = validate_sn, env)]
        serial_number: SerialNumber,

        /// Don't use yubikey for private key operations.
        #[clap(long, env)]
        no_yubi: bool,
    },
    Ping,
    SetDeviceId {
        /// File to read DeviceId cert from
        cert_in: PathBuf,
    },
    SetIntermediate {
        /// File to read intermediate cert from
        cert_in: PathBuf,
    },
    SetSerialNumber {
        /// Platform serial number
        #[clap(value_parser = validate_sn)]
        serial_number: SerialNumber,
    },
    SignCert {
        /// Path where Cert is written.
        #[clap(long)]
        cert_out: PathBuf,

        /// Path to openssl.cnf file used for signing operation.
        #[clap(long, env)]
        openssl_cnf: PathBuf,

        /// CA section from openssl.cnf used for signing operation.
        /// If omitted default from openssl.cnf is used.
        #[clap(long, env)]
        ca_section: Option<String>,

        /// x509 v3 extension section from openssl.cnf used for signing operation.
        /// If omitted default from openssl.cnf is used.
        #[clap(long, env)]
        v3_section: Option<String>,

        /// engine section from openssl.cnf used for signing operation.
        /// If omitted openssl will fall back to files.
        #[clap(long, env)]
        engine_section: Option<String>,

        /// Path to input CSR file.
        #[clap(long)]
        csr_in: PathBuf,

        /// Don't use yubikey for private key operations.
        #[clap(long, env)]
        no_yubi: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Info
    } else {
        LevelFilter::Warn
    };
    builder.filter(None, level).init();

    if args.verbose {
        info!("device: {}, baud: {}", args.serial_dev, args.baud);
    }
    match args.command {
        Command::Break => {
            let mut port = dice_mfg::open_serial(&args.serial_dev, args.baud)?;
            dice_mfg::do_break(&mut port)
        }
        Command::GetCsr { csr_path } => {
            let mut port = dice_mfg::open_serial(&args.serial_dev, args.baud)?;
            dice_mfg::do_get_csr(&mut port, &csr_path)
        }
        Command::Liveness { max_retry } => {
            let mut port = dice_mfg::open_serial(&args.serial_dev, args.baud)?;
            dice_mfg::do_liveness(&mut port, max_retry)
        }
        Command::Manufacture {
            openssl_cnf,
            ca_section,
            v3_section,
            engine_section,
            max_retry,
            serial_number,
            intermediate_cert,
            no_yubi,
        } => {
            let mut port = dice_mfg::open_serial(&args.serial_dev, args.baud)?;
            dice_mfg::do_manufacture(
                &mut port,
                openssl_cnf,
                ca_section,
                v3_section,
                engine_section,
                max_retry,
                serial_number,
                intermediate_cert,
                no_yubi,
            )
        }
        Command::Ping => {
            let mut port = dice_mfg::open_serial(&args.serial_dev, args.baud)?;
            dice_mfg::do_ping(&mut port)
        }
        Command::SetDeviceId { cert_in } => {
            let mut port = dice_mfg::open_serial(&args.serial_dev, args.baud)?;
            dice_mfg::do_set_device_id(&mut port, &cert_in)
        }
        Command::SetIntermediate { cert_in } => {
            let mut port = dice_mfg::open_serial(&args.serial_dev, args.baud)?;
            dice_mfg::do_set_intermediate(&mut port, &cert_in)
        }
        Command::SetSerialNumber { serial_number } => {
            let mut port = dice_mfg::open_serial(&args.serial_dev, args.baud)?;
            dice_mfg::do_set_serial_number(&mut port, serial_number)
        }
        Command::SignCert {
            cert_out,
            openssl_cnf,
            ca_section,
            v3_section,
            engine_section,
            csr_in,
            no_yubi,
        } => dice_mfg::do_sign_cert(
            &cert_out,
            &openssl_cnf,
            ca_section,
            v3_section,
            engine_section,
            &csr_in,
            no_yubi,
        ),
    }
}

pub fn validate_sn(s: &str) -> result::Result<SerialNumber, String> {
    for c in s.chars() {
        if !c.is_ascii_alphanumeric() {
            return Err(String::from(format!(
                "invalid character in serial number: \'{}\'",
                c
            )));
        }
    }

    Ok(s.try_into().or_else(|_| {
        Err(String::from(
            "serial number is the wrong length, should be 11 characters",
        ))
    })?)
}

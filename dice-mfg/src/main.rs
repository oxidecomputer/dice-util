// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::{Parser, Subcommand};
use dice_mfg::Result;
use dice_mfg_msgs::{SerialNumber, SizedBlob};
use env_logger::Builder;
use log::{info, LevelFilter};
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    result, str,
    time::Duration,
};
use zerocopy::AsBytes;

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
    #[clap(long)]
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
        #[clap(default_value = "10")]
        max_fail: u8,
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
    let mut port = serialport::new(args.serial_dev.clone(), args.baud)
        .timeout(Duration::from_secs(1))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?;

    match args.command {
        Command::Break => {
            print!("sending Break ... ");
            match dice_mfg::send_break(&mut port) {
                Ok(_) => {
                    println!("success");
                    Ok(())
                }
                Err(e) => {
                    println!("failed");
                    Err(e)
                }
            }
        }
        Command::GetCsr { csr_path } => {
            print!("getting CSR ... ");
            let csr = match dice_mfg::get_csr(&mut port) {
                Ok(csr) => {
                    println!("success");
                    csr
                }
                Err(e) => {
                    println!("failed");
                    return Err(e);
                }
            };
            let out: Box<dyn Write> = match csr_path {
                Some(csr_path) => Box::new(File::create(csr_path)?),
                None => Box::new(io::stdout()),
            };
            // io::Error is weird
            Ok(dice_mfg::save_csr(out, csr)?)
        }
        Command::Liveness { max_fail } => {
            print!("checking RoT for liveness ... ");
            io::stdout().flush()?;
            match dice_mfg::check_liveness(&mut port, max_fail) {
                Err(e) => {
                    println!("failed");
                    Err(e)
                }
                _ => {
                    println!("success");
                    Ok(())
                }
            }
        }
        Command::Ping => {
            print!("sending ping ... ");
            match dice_mfg::send_ping(&mut port) {
                Ok(_) => {
                    println!("success");
                    Ok(())
                }
                Err(e) => {
                    println!("failed");
                    Err(e)
                }
            }
        }
        Command::SetDeviceId { cert_in } => {
            let cert = sized_blob_from_pem_path(cert_in)?;

            print!("setting DeviceId cert ... ");
            match dice_mfg::set_deviceid(&mut port, cert) {
                Ok(_) => {
                    println!("success");
                    Ok(())
                }
                Err(e) => {
                    println!("failed");
                    Err(e)
                }
            }
        }
        Command::SetIntermediate { cert_in } => {
            let cert = sized_blob_from_pem_path(cert_in)?;

            print!("setting Intermediate cert ... ");
            match dice_mfg::set_intermediate(&mut port, cert) {
                Ok(_) => {
                    println!("success");
                    Ok(())
                }
                Err(e) => {
                    println!("failed");
                    Err(e)
                }
            }
        }
        Command::SetSerialNumber { serial_number } => {
            // SerialNumber doesn't implement ToString, dice-mfg-msgs is no_std
            print!(
                "setting serial number to: {} ... ",
                str::from_utf8(serial_number.as_bytes())?
            );
            match dice_mfg::set_serial_number(&mut port, serial_number) {
                Ok(_) => {
                    println!("success");
                    Ok(())
                }
                Err(e) => {
                    println!("failed");
                    Err(e)
                }
            }
        }
    }
}

pub fn sized_blob_from_pem_path(p: PathBuf) -> Result<SizedBlob> {
    let cert = fs::read_to_string(&p)?;
    let cert = pem::parse(cert)?;

    // Error type doesn't implement std Error
    Ok(SizedBlob::try_from(&cert.contents[..]).expect("cert too big"))
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

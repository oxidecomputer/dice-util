// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::{Parser, Subcommand};
use dice_mfg::Result;
use dice_mfg_msgs::{SerialNumber, SizedBlob};
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::{
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    process, result,
    time::Duration,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Send commands to the RoT for DeviceId certification.
struct Args {
    /// serial port device path
    #[clap(long, default_value = "/dev/ttyACM0")]
    serial_dev: String,

    /// baud rate
    #[clap(long, default_value = "9600")]
    baud: u32,

    /// send ping and wait for pong before sending command
    #[arg(long)]
    skip_ping: bool,

    /// ping-pong count
    #[clap(long, default_value = "10")]
    ping_pong_count: u8,

    /// command
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Break,
    GetCsr {
        /// Destination path for CSR, stdout if omitted
        csr_path: Option<PathBuf>,
    },
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

    println!("device: {}, baud: {}", args.serial_dev, args.baud);
    let mut port = serialport::new(args.serial_dev.clone(), args.baud)
        .timeout(Duration::from_secs(1))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?;

    if !args.skip_ping
        && !dice_mfg::ping_pong_loop(&mut port, args.ping_pong_count)?
    {
        println!("no pings ack'd: aborting");
        process::exit(1);
    }

    println!("made it to matching");
    match args.command {
        Command::Break => dice_mfg::send_break(&mut port),
        Command::GetCsr { csr_path } => {
            let csr = dice_mfg::get_csr(&mut port)?;
            let out: Box<dyn Write> = match csr_path {
                Some(csr_path) => Box::new(File::create(csr_path)?),
                None => Box::new(io::stdout()),
            };
            // io::Error is weird
            Ok(dice_mfg::save_csr(out, csr)?)
        }
        Command::SetDeviceId { cert_in } => {
            let cert = sized_blob_from_pem_path(cert_in)?;
            dice_mfg::set_deviceid(&mut port, cert)
        }
        Command::SetIntermediate { cert_in } => {
            let cert = sized_blob_from_pem_path(cert_in)?;
            dice_mfg::set_intermediate(&mut port, cert)
        }
        Command::SetSerialNumber { serial_number } => {
            dice_mfg::set_serial_number(&mut port, serial_number)
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

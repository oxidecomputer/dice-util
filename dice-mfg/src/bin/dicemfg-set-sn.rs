// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::Parser;
use dice_mfg::Result;
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::time::Duration;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// serial port device path
    #[clap(long, default_value = "/dev/ttyACM0")]
    serial_dev: String,

    /// baud rate
    #[clap(long, default_value = "9600")]
    baud: u32,

    /// ping-pong count
    #[clap(long, default_value = "5")]
    ping_pong_count: u8,

    /// Platform serial number
    #[clap(long)]
    serial_number: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // can clap this this for us?
    let sn = validate_sn(&args.serial_number)?;

    println!("device: {}, baud: {}", args.serial_dev, args.baud);
    let mut port = serialport::new(args.serial_dev.clone(), args.baud)
        .timeout(Duration::from_secs(1))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?;

    if dice_mfg::ping_pong_loop(&mut port, args.ping_pong_count)? {
        dice_mfg::set_sn(&mut port, sn)
    } else {
        println!("no pings ack'd: aborting");
        Ok(())
    }
}

pub fn validate_sn(s: &String) -> Result<[u8; 12]> {
    let s = String::from(s);
    for c in s.chars() {
        if !c.is_ascii_alphanumeric() {
            return Err(string_error::into_err(String::from(format!(
                "invalid character in serial number: \'{}\'",
                c
            ))));
        }
    }

    Ok(s.as_bytes().try_into().or_else(|_| {
        Err(string_error::into_err(String::from(
            "serial number is the wrong length, should be 12 characters",
        )))
    })?)
}

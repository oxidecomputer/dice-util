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

    if dice_mfg::ping_pong_loop(&mut port, args.ping_pong_count)? {
        dice_mfg::send_break(&mut port)
    } else {
        println!("no pings ack'd: aborting");
        Ok(())
    }
}

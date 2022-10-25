// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::Parser;
use dice_mfg::Result;
use env_logger::Builder;
use log::{info, LevelFilter};
use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::time::Duration;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Send Ping mesages to the RoT until we get an Ack.
/// The USART on the lpc55 appears to have a short period of instability
/// after power is applied. In practice this means several failed commands
/// before it stabilizes and commands succeed w/o issue.
struct Args {
    /// serial port device path
    #[clap(long, default_value = "/dev/ttyACM0", env)]
    serial_dev: String,

    /// baud rate
    #[clap(long, default_value = "9600", env)]
    baud: u32,

    /// verbosity
    #[clap(long)]
    verbose: bool,

    /// max number of failed pings
    #[clap(long, default_value = "10")]
    max_fail: u8,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Info
    } else {
        // this would normally be 'Warn' but we expect timeouts given the
        // use case for this tool. To keep from spamming warnings about these
        // timeouts we just set the log threshold higher.
        LevelFilter::Error
    };

    builder.filter(None, level).init();

    info!("device: {}, baud: {}", args.serial_dev, args.baud);

    let mut port = serialport::new(args.serial_dev.clone(), args.baud)
        .timeout(Duration::from_secs(1))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?;

    let mut i = 0;

    loop {
        match dice_mfg::send_ping(&mut port) {
            Err(e) => {
                if !(i < args.max_fail - 1) {
                    return Err(e);
                } else {
                    i += 1;
                }
            }
            _ => return Ok(()),
        }
    }
}

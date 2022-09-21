use clap::Parser;
use pem::{EncodeConfig, Pem};
use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use std::{
    env, fmt,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    process::Command,
    thread,
    time::Duration,
};

use dice_mfg_msgs::{CommsCheck, Error as MsgsError, Msg, Msgs};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// serial port device path
    #[clap(long, default_value = "/dev/ttyACM0")]
    serial_dev: String,

    /// baud rate
    #[clap(long, default_value = "9600")]
    baud: u32,
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    BadTag,
    BufFull,
    CertGenFail,
    Recv,
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::BadTag => write!(f, "PEM file has wrong tag value."),
            Error::BufFull => {
                write!(f, "Buffer provided is full before end of data.")
            }
            Error::CertGenFail => write!(f, "Cert generation failed."),
            Error::Recv => write!(f, "Recv failed."),
        }
    }
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

    serial_warmup(&mut port)?;

    Ok(())
}

pub fn read_all(
    port: &mut Box<dyn SerialPort>,
    buf: &mut [u8],
) -> Result<usize> {
    if buf.is_empty() {
        panic!("zero sized buffer, nothing to send");
    }
    let mut pos = 0;
    let mut done = false;
    while !done {
        done = match port.read(&mut buf[pos..]) {
            Ok(bytes_read) => {
                pos += bytes_read;
                if buf[pos - 1] == 0 {
                    // zero byte ends read
                    true
                } else {
                    if pos < buf.len() {
                        // more buffer available, keep reading
                        false
                    } else {
                        return Err(Box::new(Error::BufFull));
                    }
                }
            }
            // not sure what to do w/ timeouts
            //Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {
            //    true
            //},
            Err(e) => return Err(Box::new(e)),
        }
    }

    Ok(pos)
}

fn send_msg(port: &mut Box<dyn SerialPort>, msg: &Msg) -> Result<()> {
    let mut buf = [0u8; Msg::MAX_ENCODED_SIZE];

    let size = msg.encode(&mut buf).expect("encode");

    port.write_all(&buf[..size])?;
    port.flush().map_err(|e| e.into())
}

fn recv_msg(port: &mut Box<dyn SerialPort>) -> Result<Msg> {
    let mut encoded_buf = [0xFFu8; Msg::MAX_ENCODED_SIZE];

    let size = read_all(port, &mut encoded_buf)?;

    match Msg::decode(&encoded_buf[..size]) {
        Ok(msg) => Ok(msg),
        Err(e) => {
            println!("{:?}", e);
            Err(Box::new(Error::Recv))
        }
    }
}

/// Testing has show that the serial hardware on the lpc55 dev boards and the
/// rot-carrier predictibly produce errors on first use after power on. As a
/// work around this function exchanges messages over the serial port until
/// a threshold of successful message exchanges has occured.
fn serial_warmup(port: &mut Box<dyn SerialPort>) -> Result<()> {
    // TODO: this needs more structure
    const THRESHOLD: u8 = 5;
    let mut cnt = 0;

    loop {
        println!("loop count: {}", cnt);
        let msg = Msg {
            id: 666,
            msg: Msgs::HowYouDoin(CommsCheck([6u8; 32])),
        };
        send_msg(port, &msg)?;

        let resp = match recv_msg(port) {
            Ok(resp) => {
                println!("got: {:?}", resp);
                resp
            }
            Err(e) => {
                println!("error receiving message: {:?}", e);
                // consider a failure threshold to keep this from looping
                // haven't seen this happen in practice though
                continue;
            }
        };

        match resp.msg {
            Msgs::NotGreat => {
                println!("Peer is NotGreat: trying again");
                continue;
            }
            Msgs::NotBad => {
                println!("Peer is NotBad: {}", cnt);
                cnt += 1;
                if cnt > THRESHOLD {
                    let msg = Msg {
                        id: resp.id + 1,
                        msg: Msgs::Break,
                    };
                    send_msg(port, &msg)?;
                    println!("Crossed NotBad threshold: done");
                    break;
                } else {
                    continue;
                }
            }
            _ => {
                println!("unexpected message type, trying again");
                continue;
            }
        }
    }

    Ok(())
}

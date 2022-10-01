// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dice_mfg_msgs::{Msg, Msgs, SizedBlob};
use serialport::SerialPort;
use std::{fmt, ops::Range};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    BadTag,
    BufFull,
    CertGenFail,
    Recv,
    WrongMsg,
    Decode,
    PingRange,
    NoSerialNumber,
    ConfigIncomplete,
    NoResponse,
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
            Error::WrongMsg => write!(f, "Unexpected message received."),
            Error::Decode => write!(f, "Failed to decode message."),
            Error::PingRange => write!(f, "Ping-pong sync failed."),
            Error::NoSerialNumber => {
                write!(f, "Platform has no serial number: can't generate CSR.")
            }
            Error::ConfigIncomplete => {
                write!(f, "Configuration incomplete.")
            }
            Error::NoResponse => {
                write!(f, "No pings acknowledged: check connection to RoT")
            }
        }
    }
}

pub fn set_intermediate(
    port: &mut Box<dyn SerialPort>,
    cert: SizedBlob,
) -> Result<()> {
    println!("sending Intermediate cert ...");
    let msg = Msg {
        id: 0,
        msg: Msgs::IntermediateCert(cert),
    };

    send_msg(port, &msg)?;
    recv_ack(port)
}

pub fn set_deviceid(
    port: &mut Box<dyn SerialPort>,
    cert: SizedBlob,
) -> Result<()> {
    println!("sending DeviceId cert ...");
    let msg = Msg {
        id: 0,
        msg: Msgs::DeviceIdCert(cert),
    };

    send_msg(port, &msg)?;
    recv_ack(port)
}

pub fn get_csr(port: &mut Box<dyn SerialPort>) -> Result<SizedBlob> {
    println!("requesting CSR ...");
    let msg = Msg {
        id: 1,
        msg: Msgs::CsrPlz,
    };

    send_msg(port, &msg)?;

    let resp = recv_msg(port).map_err(|_| Error::Recv)?;

    match resp.msg {
        Msgs::Csr(csr) => Ok(csr),
        // RoT will nak a request for the DeviceId CSR if it hasn't been given
        // a serial number yet.
        Msgs::Nak => Err(Box::new(Error::NoSerialNumber)),
        _ => {
            println!("got unexpected response, was expecting SerialNumberAck");
            Err(Box::new(Error::WrongMsg))
        }
    }
}

pub fn send_break(port: &mut Box<dyn SerialPort>) -> Result<()> {
    print!("sending Break ... ");
    let msg = Msg {
        id: 1,
        msg: Msgs::Break,
    };

    send_msg(port, &msg)?;

    let resp = recv_msg(port).map_err(|_| Error::Recv)?;

    match resp.msg {
        Msgs::Ack => {
            println!("success");
            Ok(())
        }
        Msgs::Nak => {
            println!("failure: command refused.");
            Err(Box::new(Error::ConfigIncomplete))
        }
        _ => {
            println!("got unexpected response");
            Err(Box::new(Error::WrongMsg))
        }
    }
}

pub fn set_sn(port: &mut Box<dyn SerialPort>, sn: [u8; 12]) -> Result<()> {
    println!("sending serial number: {:?}", &sn);
    let msg = Msg {
        id: 666,
        msg: Msgs::SerialNumber(sn),
    };

    send_msg(port, &msg)?;
    recv_ack(port)
}

pub fn ping_pong_loop(
    port: &mut Box<dyn SerialPort>,
    count: u8,
) -> Result<bool> {
    let msg = Msg {
        id: 666,
        msg: Msgs::Ping,
    };

    for i in (Range {
        start: 0,
        end: count,
    }) {
        send_msg(port, &msg)?;
        match recv_ack(port) {
            Ok(_) => return Ok(true),
            Err(e) => {
                println!("ping {} failed: \"{}\"", i, e);
                continue;
            }
        }
    }

    Ok(false)
}

pub fn recv_ack(port: &mut Box<dyn SerialPort>) -> Result<()> {
    print!("waiting for Ack ... ");
    let resp = recv_msg(port).map_err(|_| Error::Recv)?;

    match resp.msg {
        Msgs::Ack => {
            println!("success!");
            Ok(())
        }
        _ => {
            println!("unexpected response");
            Err(Box::new(Error::WrongMsg))
        }
    }
}

fn send_msg(port: &mut Box<dyn SerialPort>, msg: &Msg) -> Result<()> {
    let mut buf = [0u8; Msg::MAX_ENCODED_SIZE];

    let size = msg.encode(&mut buf).expect("encode");

    port.write_all(&buf[..size])?;
    port.flush().map_err(|e| e.into())
}

fn recv_msg(port: &mut Box<dyn SerialPort>) -> Result<Msg> {
    let mut encoded_buf = [0xFFu8; Msg::MAX_ENCODED_SIZE];
    //println!("recv_msg w/ MAX_ENCODED_SIZE: {}", Msg::MAX_ENCODED_SIZE);

    let size = read_all(port, &mut encoded_buf)?;

    match Msg::decode(&encoded_buf[..size]) {
        Ok(msg) => Ok(msg),
        Err(e) => {
            println!("{:?}", e);
            Err(Box::new(Error::Decode))
        }
    }
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
            Err(e) => return Err(Box::new(e)),
        }
    }

    Ok(pos)
}

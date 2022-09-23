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
        }
    }
}

pub fn get_csr(port: &mut Box<dyn SerialPort>) -> Result<SizedBlob> {
    println!("requesting CSR");
    let msg = Msg {
        id: 1,
        msg: Msgs::CsrPlz,
    };

    send_msg(port, &msg)?;

    println!("waiting for CSR");
    let resp = recv_msg(port).map_err(|_| Error::Recv)?;

    match resp.msg {
        Msgs::Csr(csr) => Ok(csr),
        Msgs::NoSerialNumber => Err(Box::new(Error::NoSerialNumber)),
        _ => {
            println!("got unexpected response, was expecting SerialNumberAck");
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

    send_msg(port, &msg)
}

pub fn ping_pong_loop(port: &mut Box<dyn SerialPort>, count: u8) -> Result<()> {
    let end = count;

    for i in (Range {
        start: 0,
        end: count,
    }) {
        match ping_pong(port) {
            Ok(_) => break,
            Err(_) => {
                if i == end {
                    return Err(Box::new(Error::PingRange));
                }
                continue;
            }
        }
    }

    Ok(())
}

pub fn ping_pong(port: &mut Box<dyn SerialPort>) -> Result<()> {
    println!("sending ping");
    let msg = Msg {
        id: 666,
        msg: Msgs::Ping,
    };

    send_msg(port, &msg)?;

    println!("waiting for pong");
    let resp = recv_msg(port).map_err(|_| Error::Recv)?;

    match resp.msg {
        Msgs::Pong => {
            println!("success!");
            Ok(())
        }
        _ => {
            println!("got unexpected response, was expecting SerialNumberAck");
            Err(Box::new(Error::WrongMsg))
        }
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

fn send_msg(port: &mut Box<dyn SerialPort>, msg: &Msg) -> Result<()> {
    let mut buf = [0u8; Msg::MAX_ENCODED_SIZE];

    let size = msg.encode(&mut buf).expect("encode");

    port.write_all(&buf[..size])?;
    port.flush().map_err(|e| e.into())
}

fn recv_msg(port: &mut Box<dyn SerialPort>) -> Result<Msg> {
    let mut encoded_buf = [0xFFu8; Msg::MAX_ENCODED_SIZE];
    println!("recv_msg w/ MAX_ENCODED_SIZE: {}", Msg::MAX_ENCODED_SIZE);

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

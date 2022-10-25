// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dice_mfg_msgs::{MfgMessage, SerialNumber, SizedBlob};
use log::{info, warn};

use serialport::SerialPort;
use std::{fmt, io::Write, str};
use zerocopy::AsBytes;

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
    print!("setting Intermediate cert ... ");

    send_msg(port, &MfgMessage::IntermediateCert(cert))?;
    recv_ack(port)
}

pub fn set_deviceid(
    port: &mut Box<dyn SerialPort>,
    cert: SizedBlob,
) -> Result<()> {
    print!("setting DeviceId cert ... ");

    send_msg(port, &MfgMessage::DeviceIdCert(cert))?;
    recv_ack(port)
}

pub fn get_csr(port: &mut Box<dyn SerialPort>) -> Result<SizedBlob> {
    print!("getting CSR ... ");

    send_msg(port, &MfgMessage::CsrPlz)?;

    let recv = recv_msg(port).map_err(|e| {
        println!("failed");

        e
    })?;

    match recv {
        MfgMessage::Csr(csr) => {
            println!("success");
            Ok(csr)
        }
        // RoT will nak a request for the DeviceId CSR if it hasn't been given
        // a serial number yet.
        MfgMessage::Nak => {
            println!("failed");
            Err(Error::NoSerialNumber.into())
        }
        _ => {
            warn!("requested CSR, got unexpected message back: \"{:?}\"", recv);
            println!("failed");
            Err(Error::WrongMsg.into())
        }
    }
}

pub fn save_csr<W: Write>(mut w: W, csr: SizedBlob) -> Result<()> {
    let size = usize::from(csr.size);

    // encode as PEM
    let pem = pem::Pem {
        tag: String::from("CERTIFICATE REQUEST"),
        contents: csr.as_bytes()[..size].to_vec(),
    };
    let csr_pem = pem::encode_config(
        &pem,
        pem::EncodeConfig {
            line_ending: pem::LineEnding::LF,
        },
    );

    Ok(w.write_all(&csr_pem.as_bytes())?)
}

pub fn send_break(port: &mut Box<dyn SerialPort>) -> Result<()> {
    print!("sending Break ... ");

    send_msg(port, &MfgMessage::Break)?;

    let resp = recv_msg(port).map_err(|e| {
        println!("failed");

        e
    })?;

    match resp {
        MfgMessage::Ack => {
            println!("success");
            Ok(())
        }
        MfgMessage::Nak => {
            println!("failed");
            Err(Error::ConfigIncomplete.into())
        }
        _ => {
            println!("failed");
            Err(Error::WrongMsg.into())
        }
    }
}

pub fn set_serial_number(
    port: &mut Box<dyn SerialPort>,
    sn: SerialNumber,
) -> Result<()> {
    // SerialNumber doesn't implement ToString, dice-mfg-msgs is no_std
    print!(
        "setting serial number to: {} ... ",
        str::from_utf8(sn.as_bytes())?
    );
    send_msg(port, &MfgMessage::SerialNumber(sn))?;

    recv_ack(port)
}

pub fn send_ping(port: &mut Box<dyn SerialPort>) -> Result<()> {
    print!("sending ping ... ");
    send_msg(port, &MfgMessage::Ping)?;

    recv_ack(port)
}

fn recv_ack(port: &mut Box<dyn SerialPort>) -> Result<()> {
    info!("waiting for Ack ... ");
    let resp = recv_msg(port).map_err(|e| {
        println!("failed");

        e
    })?;

    match resp {
        MfgMessage::Ack => {
            println!("success");
            Ok(())
        }
        _ => {
            println!("failed");
            warn!("expected Ack, got unexpected message: \"{:?}\"", resp);
            Err(Error::WrongMsg.into())
        }
    }
}

fn send_msg(port: &mut Box<dyn SerialPort>, msg: &MfgMessage) -> Result<()> {
    let mut buf = [0u8; MfgMessage::MAX_ENCODED_SIZE];

    let size = msg.encode(&mut buf).expect("encode");

    port.write_all(&buf[..size])?;
    port.flush().map_err(|e| e.into())
}

fn recv_msg(port: &mut Box<dyn SerialPort>) -> Result<MfgMessage> {
    let mut encoded_buf = [0xFFu8; MfgMessage::MAX_ENCODED_SIZE];

    let size = read_all(port, &mut encoded_buf)?;

    // map_err?
    match MfgMessage::decode(&encoded_buf[..size]) {
        Ok(msg) => Ok(msg),
        Err(e) => {
            warn!("{:?}", e);
            Err(Error::Decode.into())
        }
    }
}

fn read_all(port: &mut Box<dyn SerialPort>, buf: &mut [u8]) -> Result<usize> {
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
                        return Err(Error::BufFull.into());
                    }
                }
            }
            Err(e) => {
                warn!("read_all failed with error: \"{}\"", e);
                return Err(e.into());
            }
        }
    }

    Ok(pos)
}

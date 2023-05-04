// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use dice_mfg_msgs::{MfgMessage, PlatformId, PlatformIdError, SizedBlob};
use log::{info, warn};

use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use std::{
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    process::Command,
    str,
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Error {
    BadTag,
    BufFull,
    CertGenFail,
    Recv,
    WrongMsg,
    Decode,
    PingRange,
    NoPlatformId,
    ConfigIncomplete,
    NoResponse,
    InvalidPlatformId(PlatformIdError),
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
            Error::NoPlatformId => {
                write!(f, "Platform has no platform id: can't generate CSR.")
            }
            Error::ConfigIncomplete => {
                write!(f, "Configuration incomplete.")
            }
            Error::NoResponse => {
                write!(f, "No pings acknowledged: check connection to RoT")
            }
            Error::InvalidPlatformId(e) => {
                write!(f, "PlatformId is invalid: {:?}", e)
            }
        }
    }
}

// https://github.com/oxidecomputer/dice-util/issues/16
#[allow(clippy::too_many_arguments)]
pub fn do_manufacture(
    port: &mut Box<dyn SerialPort>,
    openssl_cnf: PathBuf,
    ca_section: Option<String>,
    v3_section: Option<String>,
    engine_section: Option<String>,
    ping_retry: u8,
    platform_id: PlatformId,
    intermediate_cert: PathBuf,
    no_yubi: bool,
) -> Result<()> {
    do_liveness(port, ping_retry)?;
    do_set_platform_id(port, platform_id)?;

    let temp_dir = tempfile::tempdir()?;
    let csr = Some(temp_dir.path().join("csr.pem"));
    do_get_csr(port, &csr)?;

    let cert = temp_dir.into_path().join("cert.pem");
    do_sign_cert(
        &cert,
        &openssl_cnf,
        ca_section,
        v3_section,
        engine_section,
        &csr.unwrap(),
        no_yubi,
    )?;
    do_set_device_id(port, &cert)?;
    do_set_intermediate(port, &intermediate_cert)?;
    do_break(port)
}
pub fn do_break(port: &mut Box<dyn SerialPort>) -> Result<()> {
    print!("sending Break ... ");
    match send_break(port) {
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

pub fn do_get_csr(
    port: &mut Box<dyn SerialPort>,
    csr_path: &Option<PathBuf>,
) -> Result<()> {
    print!("getting CSR ... ");
    let csr = match get_csr(port) {
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

    save_csr(out, csr)
}

pub fn do_liveness(port: &mut Box<dyn SerialPort>, max_fail: u8) -> Result<()> {
    print!("checking RoT for liveness ... ");
    io::stdout().flush()?;
    match check_liveness(port, max_fail) {
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

pub fn do_ping(port: &mut Box<dyn SerialPort>) -> Result<()> {
    print!("sending ping ... ");
    match send_ping(port) {
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

pub fn do_set_device_id(
    port: &mut Box<dyn SerialPort>,
    cert_in: &PathBuf,
) -> Result<()> {
    let cert = sized_blob_from_pem_path(cert_in)?;

    print!("setting DeviceId cert ... ");
    match set_deviceid(port, cert) {
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

pub fn do_set_intermediate(
    port: &mut Box<dyn SerialPort>,
    cert_in: &PathBuf,
) -> Result<()> {
    let cert = sized_blob_from_pem_path(cert_in)?;

    print!("setting Intermediate cert ... ");
    match set_intermediate(port, cert) {
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

pub fn do_set_platform_id(
    port: &mut Box<dyn SerialPort>,
    platform_id: PlatformId,
) -> Result<()> {
    match platform_id.as_str() {
        Ok(s) => print!("setting platform id to: \"{}\" ... ", s),
        Err(e) => return Err(Error::InvalidPlatformId(e).into()),
    }

    match set_platform_id(port, platform_id) {
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

pub fn do_sign_cert(
    cert_out: &PathBuf,
    openssl_cnf: &PathBuf,
    ca_section: Option<String>,
    v3_section: Option<String>,
    engine_section: Option<String>,
    csr_in: &PathBuf,
    no_yubi: bool,
) -> Result<()> {
    // this is kinda ugly. Remove the 'no-yubi' trap door?
    let engine_section = if !no_yubi && engine_section.is_none() {
        Some(String::from("pkcs11"))
    } else {
        engine_section
    };

    print!("signing CSR ... ");
    match sign_cert(
        openssl_cnf,
        csr_in,
        cert_out,
        ca_section,
        v3_section,
        engine_section,
    ) {
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

fn sized_blob_from_pem_path(p: &PathBuf) -> Result<SizedBlob> {
    let cert = fs::read_to_string(p)?;
    let cert = pem::parse(cert)?;

    // Error type doesn't implement std Error
    Ok(SizedBlob::try_from(&cert.contents[..]).expect("cert too big"))
}

pub fn sign_cert(
    openssl_cnf: &PathBuf,
    csr_in: &PathBuf,
    cert_out: &PathBuf,
    ca_section: Option<String>,
    v3_section: Option<String>,
    engine_section: Option<String>,
) -> Result<()> {
    let mut cmd = Command::new("openssl");

    cmd.arg("ca")
        .arg("-batch")
        .arg("-notext")
        .arg("-config")
        .arg(openssl_cnf)
        .arg("-in")
        .arg(csr_in)
        .arg("-out")
        .arg(cert_out);

    if let Some(section) = ca_section {
        cmd.arg("-name").arg(section);
    }
    if let Some(section) = v3_section {
        cmd.arg("-extensions").arg(section);
    }

    if let Some(section) = engine_section {
        cmd.arg("-engine")
            .arg(section)
            .arg("-keyform")
            .arg("engine");
    }

    info!("cmd: {:?}", cmd);

    let output = cmd.output()?;

    if output.status.success() {
        Ok(())
    } else {
        warn!("command failed with status: {}", output.status);
        warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        Err(Error::CertGenFail.into())
    }
}

pub fn set_intermediate(
    port: &mut Box<dyn SerialPort>,
    cert: SizedBlob,
) -> Result<()> {
    send_msg(port, &MfgMessage::IntermediateCert(cert))?;
    recv_ack(port)
}

pub fn set_deviceid(
    port: &mut Box<dyn SerialPort>,
    cert: SizedBlob,
) -> Result<()> {
    send_msg(port, &MfgMessage::IdentityCert(cert))?;
    recv_ack(port)
}

pub fn get_csr(port: &mut Box<dyn SerialPort>) -> Result<SizedBlob> {
    send_msg(port, &MfgMessage::CsrPlz)?;

    let recv = recv_msg(port)?;

    match recv {
        MfgMessage::Csr(csr) => Ok(csr),
        // RoT will nak a request for the DeviceId CSR if it hasn't been given
        // a serial number yet.
        MfgMessage::Nak => Err(Error::NoPlatformId.into()),
        _ => {
            warn!("requested CSR, got unexpected message back: \"{:?}\"", recv);
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

    Ok(w.write_all(csr_pem.as_bytes())?)
}

pub fn send_break(port: &mut Box<dyn SerialPort>) -> Result<()> {
    send_msg(port, &MfgMessage::Break)?;

    let resp = recv_msg(port)?;

    match resp {
        MfgMessage::Ack => Ok(()),
        MfgMessage::Nak => Err(Error::ConfigIncomplete.into()),
        _ => Err(Error::WrongMsg.into()),
    }
}

pub fn set_platform_id(
    port: &mut Box<dyn SerialPort>,
    pid: PlatformId,
) -> Result<()> {
    send_msg(port, &MfgMessage::PlatformId(pid))?;
    recv_ack(port)
}

pub fn check_liveness(
    port: &mut Box<dyn SerialPort>,
    mut max_fail: u8,
) -> Result<()> {
    loop {
        match send_ping(port) {
            Err(e) => {
                if max_fail > 0 {
                    max_fail -= 1;
                } else {
                    return Err(e);
                }
            }
            _ => {
                return Ok(());
            }
        }
    }
}

pub fn send_ping(port: &mut Box<dyn SerialPort>) -> Result<()> {
    send_msg(port, &MfgMessage::Ping)?;
    recv_ack(port)
}

fn recv_ack(port: &mut Box<dyn SerialPort>) -> Result<()> {
    info!("waiting for Ack ... ");
    let resp = recv_msg(port)?;

    match resp {
        MfgMessage::Ack => {
            info!("success");
            Ok(())
        }
        _ => {
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
                } else if pos < buf.len() {
                    // more buffer available, keep reading
                    false
                } else {
                    return Err(Error::BufFull.into());
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

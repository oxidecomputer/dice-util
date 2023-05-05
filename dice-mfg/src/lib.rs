// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use dice_mfg_msgs::{MfgMessage, PlatformId, PlatformIdError, SizedBlob};
use log::{info, warn};

use serialport::SerialPort;
use std::{
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    process::Command,
};

#[derive(Debug, PartialEq)]
pub enum Error {
    BadTag,
    BufFull,
    CertGenFail,
    Recv,
    WrongMsg(String),
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
            Error::WrongMsg(s) => {
                write!(f, "Unexpected message received: {}.", s)
            }
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

/// The MfgDriver is used to send commands to the RoT as part of programming
/// identity credentials. The structure holds SerialPort instance. The
/// associated functions map 1:1 to members of the MfgMessage enum from
/// dice-mfg-msgs. The `liveness` function is a minor exception to this rule.
pub struct MfgDriver {
    port: Box<dyn SerialPort>,
}

impl MfgDriver {
    pub fn new(port: Box<dyn SerialPort>) -> Self {
        MfgDriver { port }
    }

    /// Ping the RoT at most `max_fail` times. If the RoT does not reply with
    /// an Ack to one of these Pings this function returns an error.
    pub fn liveness(&mut self, mut max_fail: u8) -> Result<()> {
        print!("checking RoT for liveness ... ");
        io::stdout().flush()?;

        loop {
            self.send_msg(&MfgMessage::Ping)?;
            match self.recv_ack() {
                Err(e) => {
                    if max_fail > 0 {
                        max_fail -= 1;
                    } else {
                        return Err(e);
                    }
                }
                _ => {
                    println!("success");
                    return Ok(());
                }
            }
        }
    }

    /// Tell the RoT that we're dong programming it.NOTE: This function name
    /// is prefixed with `send_` to avoid conflict with the `break` keyword.
    pub fn send_break(&mut self) -> Result<()> {
        print!("sending Break ... ");
        io::stdout().flush()?;

        self.send_msg(&MfgMessage::Break)?;
        self.recv_ack()?;

        println!("success");
        Ok(())
    }

    /// Ping the RoT. If the RoT doesn't acknowledge the Ping this function
    /// returns an error.
    pub fn ping(&mut self) -> Result<()> {
        print!("sending ping ... ");
        io::stdout().flush()?;

        self.send_msg(&MfgMessage::Ping)?;
        self.recv_ack()?;

        println!("success");
        Ok(())
    }

    /// Tell the RoT what it's unique ID is.
    pub fn set_platform_id(&mut self, pid: PlatformId) -> Result<()> {
        match pid.as_str() {
            Ok(s) => print!("setting platform id to: \"{}\" ... ", s),
            Err(e) => return Err(Error::InvalidPlatformId(e).into()),
        }
        io::stdout().flush()?;

        self.send_msg(&MfgMessage::PlatformId(pid))?;
        self.recv_ack()?;

        println!("success");
        Ok(())
    }

    /// Request a CSR from the RoT.
    pub fn get_csr(&mut self, csr_path: &Option<PathBuf>) -> Result<()> {
        print!("getting CSR ... ");
        io::stdout().flush()?;

        self.send_msg(&MfgMessage::CsrPlz)?;
        let recv = self.recv_msg()?;

        let csr = match recv {
            MfgMessage::Csr(csr) => {
                println!("success");
                csr
            }
            // RoT will nak a request for the DeviceId CSR if it hasn't been
            // given a serial number yet.
            MfgMessage::Nak => return Err(Error::NoPlatformId.into()),
            _ => {
                warn!("requested CSR, got unexpected response: \"{:?}\"", recv);
                return Err(Error::WrongMsg(recv.to_string()).into());
            }
        };

        let out: Box<dyn Write> = match csr_path {
            Some(csr_path) => Box::new(File::create(csr_path)?),
            None => Box::new(io::stdout()),
        };

        save_csr(out, csr)
    }

    /// Send the RoT the cert for the intermediate / signing CA.
    pub fn set_intermediate_cert(&mut self, cert_in: &PathBuf) -> Result<()> {
        let cert = sized_blob_from_pem_path(cert_in)?;

        print!("setting Intermediate cert ... ");
        io::stdout().flush()?;

        self.send_msg(&MfgMessage::IntermediateCert(cert))?;
        self.recv_ack()?;

        println!("success");
        Ok(())
    }

    /// Send the RoT its certified identity.
    pub fn set_platform_id_cert(&mut self, cert_in: &PathBuf) -> Result<()> {
        let cert = sized_blob_from_pem_path(cert_in)?;

        print!("setting PlatformId cert ... ");
        io::stdout().flush()?;

        self.send_msg(&MfgMessage::IdentityCert(cert))?;
        self.recv_ack()?;

        println!("success");
        Ok(())
    }

    /// Read a message from the serial port. Return an error if it's not an
    /// `Ack`.
    fn recv_ack(&mut self) -> Result<()> {
        info!("waiting for Ack ... ");
        let resp = self.recv_msg()?;

        match resp {
            MfgMessage::Ack => Ok(()),
            _ => {
                warn!("expected Ack, got unexpected message: \"{:?}\"", resp);
                Err(Error::WrongMsg(resp.to_string()).into())
            }
        }
    }

    /// Send a message to the RoT.
    fn send_msg(&mut self, msg: &MfgMessage) -> Result<()> {
        let mut buf = [0u8; MfgMessage::MAX_ENCODED_SIZE];

        let size = msg.encode(&mut buf).expect("encode");

        self.port.write_all(&buf[..size])?;
        self.port.flush().map_err(|e| e.into())
    }

    /// Receive a message from the RoT.
    fn recv_msg(&mut self) -> Result<MfgMessage> {
        let mut encoded_buf = [0xFFu8; MfgMessage::MAX_ENCODED_SIZE];

        let size = self.read_all(&mut encoded_buf)?;

        // map_err?
        match MfgMessage::decode(&encoded_buf[..size]) {
            Ok(msg) => Ok(msg),
            Err(e) => {
                warn!("{:?}", e);
                Err(Error::Decode.into())
            }
        }
    }

    /// Read from serial port till 0 byte.
    fn read_all(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            panic!("zero sized buffer, nothing to send");
        }
        let mut pos = 0;
        let mut done = false;
        while !done {
            done = match self.port.read(&mut buf[pos..]) {
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

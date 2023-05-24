// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![feature(absolute_path)]

use anyhow::Result;
use dice_mfg_msgs::{MfgMessage, PlatformId, PlatformIdError, SizedBlob};
use log::{info, warn};

use serialport::SerialPort;
use std::{
    env::{self, VarError},
    fmt,
    fs::{self, File},
    io::{self, Write},
    path::PathBuf,
    process::Command,
};
use yubihsm::{object::Id, Client, Connector, Credentials, HttpConfig};
use zeroize::Zeroizing;

// Name of environment variable used to pass in the YubiHSM password into
// the application.
pub const ENV_PASSWD: &str = "DICE_MFG_YUBIHSM_AUTH";

// Name of environment variable used to pass the YubiHSM password through
// openssl & PKCS#11 module to the YubiHSM. This variable is set should
// *not* be set by the caller.
const ENV_PASSWD_PKCS11: &str = "DICE_MFG_PKCS11_AUTH";

// default object id for auth credential from oks
pub const DEFAULT_AUTH_ID: Id = 2;
// default openssl engine section
pub const DEFAULT_ENGINE_SECTION: &str = "pkcs11";

#[derive(Debug, PartialEq)]
pub enum Error {
    BadTag,
    BufFull,
    CertGenFail,
    Recv,
    WrongMsg(String),
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
    pub fn get_csr(&mut self, csr_path: Option<&PathBuf>) -> Result<()> {
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

        let size = msg.encode(&mut buf)?;

        self.port.write_all(&buf[..size])?;
        self.port.flush().map_err(|e| e.into())
    }

    /// Receive a message from the RoT.
    fn recv_msg(&mut self) -> Result<MfgMessage> {
        let mut encoded_buf = [0xFFu8; MfgMessage::MAX_ENCODED_SIZE];

        let size = self.read_all(&mut encoded_buf)?;

        Ok(MfgMessage::decode(&encoded_buf[..size])?)
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

pub struct CertSignerBuilder {
    auth_id: Id,
    ca_root: PathBuf,
    ca_section: Option<String>,
    engine_section: Option<String>,
    openssl_cnf: Option<PathBuf>,
    v3_section: Option<String>,
}

impl CertSignerBuilder {
    pub fn new(ca_root: PathBuf) -> Self {
        CertSignerBuilder {
            auth_id: DEFAULT_AUTH_ID,
            ca_root,
            ca_section: None,
            engine_section: None,
            openssl_cnf: None,
            v3_section: None,
        }
    }

    pub fn set_auth_id(mut self, auth_id: Id) -> Self {
        self.auth_id = auth_id;
        self
    }

    pub fn set_ca_section(mut self, ca_section: Option<String>) -> Self {
        self.ca_section = ca_section;
        self
    }

    pub fn set_openssl_cnf(mut self, openssl_cnf: Option<PathBuf>) -> Self {
        self.openssl_cnf = openssl_cnf;
        self
    }

    pub fn set_v3_section(mut self, v3_section: Option<String>) -> Self {
        self.v3_section = v3_section;
        self
    }

    pub fn set_engine_section(
        mut self,
        engine_section: Option<String>,
    ) -> Self {
        self.engine_section = engine_section;
        self
    }

    pub fn build(self) -> CertSigner {
        CertSigner {
            auth_id: self.auth_id,
            openssl_cnf: self
                .openssl_cnf
                .unwrap_or_else(|| self.ca_root.join("openssl.cnf")),
            ca_root: self.ca_root,
            ca_section: self.ca_section,
            engine_section: self.engine_section,
            v3_section: self.v3_section,
        }
    }
}

pub struct CertSigner {
    auth_id: Id,
    ca_root: PathBuf,
    ca_section: Option<String>,
    engine_section: Option<String>,
    openssl_cnf: PathBuf,
    v3_section: Option<String>,
}

impl CertSigner {
    pub fn sign(&self, csr_in: &PathBuf, cert_out: &PathBuf) -> Result<()> {
        print!("signing CSR ... ");
        io::stdout().flush()?;

        if cert_out.exists() {
            return Err(anyhow::anyhow!("output file already exists"));
        }

        let engine_section = &self
            .engine_section
            .clone()
            .unwrap_or(DEFAULT_ENGINE_SECTION.to_string());

        //canonicalize paths before we chdir
        let openssl_cnf = fs::canonicalize(&self.openssl_cnf)?;
        let csr_in = fs::canonicalize(csr_in)?;
        let cert_out = std::path::absolute(cert_out)?;
        let lastpwd = env::current_dir()?;
        info!("setting pwd to: {}", self.ca_root.display());
        env::set_current_dir(&self.ca_root)?;

        let mut password = Zeroizing::new(format!("{:04x}", self.auth_id));
        match env::var(ENV_PASSWD) {
            Ok(p) => password.push_str(&p),
            Err(VarError::NotPresent) => {
                return Err(anyhow::anyhow!(
                    "could not get auth value from env"
                ));
            }
            Err(e) => return Err(e.into()),
        }
        env::set_var(ENV_PASSWD_PKCS11, password);

        let mut cmd = Command::new("openssl");

        cmd.arg("ca")
            .arg("-batch")
            .arg("-notext")
            .arg("-config")
            .arg(openssl_cnf)
            .arg("-in")
            .arg(csr_in)
            .arg("-out")
            .arg(cert_out)
            .arg("-engine")
            .arg(engine_section)
            .arg("-keyform")
            .arg("engine")
            .arg("-passin")
            .arg(format!("env:{ENV_PASSWD_PKCS11}"));

        if let Some(section) = &self.ca_section {
            cmd.arg("-name").arg(section);
        }
        if let Some(section) = &self.v3_section {
            cmd.arg("-extensions").arg(section);
        }

        info!("cmd: {:?}", cmd);

        let output = cmd.output()?;

        if output.status.success() {
            println!("success");
        } else {
            warn!("command failed with status: {}", output.status);
            warn!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
            return Err(Error::CertGenFail.into());
        }

        let client = get_client(self.auth_id)?;

        info!("getting log entries");
        let entries = client.get_log_entries()?;
        info!("LogEntries: {:#?}", entries);

        use chrono::{SecondsFormat, Utc};

        let now = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        info!("now: {}", now);
        fs::write(
            format!("{}.audit.json", now),
            serde_json::to_string(&entries)?,
        )?;

        // set log index to last entry returned or error out if it's empty
        match entries.entries.last() {
            Some(e) => client.set_log_index(e.item)?,
            None => {
                return Err(anyhow::anyhow!("audit log contains no entries"));
            }
        }

        info!("restoring pwd to: {}", lastpwd.display());
        env::set_current_dir(lastpwd)?;

        Ok(())
    }
}

fn sized_blob_from_pem_path(p: &PathBuf) -> Result<SizedBlob> {
    let cert = fs::read_to_string(p)?;
    let cert = pem::parse(cert)?;

    // Error type doesn't implement std Error
    Ok(SizedBlob::try_from(&cert.contents[..])?)
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

pub fn get_log_entries(auth_id: Id) -> Result<u16> {
    let client = get_client(auth_id)?;

    let entries = client.get_log_entries()?;
    println!("{}", serde_json::to_string_pretty(&entries)?);

    match entries.entries.last() {
        Some(e) => Ok(e.item),
        None => Err(anyhow::anyhow!("audit log contains no entries")),
    }
}

pub fn set_log_index(auth_id: Id, index: u16) -> Result<()> {
    let client = get_client(auth_id)?;
    info!("setting log index to: {}", index);

    Ok(client.set_log_index(index)?)
}

fn get_client(auth_id: Id) -> Result<Client> {
    let config = HttpConfig::default();
    let connector = Connector::http(&config);

    // get passwd from env
    let password = Zeroizing::new(env::var(ENV_PASSWD)?);
    let credentials = Credentials::from_password(auth_id, password.as_bytes());

    Ok(Client::open(connector, credentials, true)?)
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::Nonce;
use hubpack::SerializedSize;
use sha3::{Digest, Sha3_256};
use std::{
    fmt,
    io::{Read, Write},
    path::Path,
    process::{Command, Output},
};
use tempfile::NamedTempFile;
use thiserror::Error;

/// This trait implements the hubris attestation API exposed by the `attest`
/// task in the RoT and proxied through the `sprot` task in the SP.
pub trait AttestSprot {
    fn attest_len(&self) -> Result<u32, AttestHiffyError>;
    fn attest(
        &self,
        nonce: &Nonce,
        out: &mut [u8],
    ) -> Result<(), AttestHiffyError>;
    fn cert_chain_len(&self) -> Result<u32, AttestHiffyError>;
    fn cert_len(&self, index: u32) -> Result<u32, AttestHiffyError>;
    fn cert(&self, index: u32, out: &mut [u8]) -> Result<(), AttestHiffyError>;
    fn log(&self, out: &mut [u8]) -> Result<(), AttestHiffyError>;
    fn log_len(&self) -> Result<u32, AttestHiffyError>;
    fn record(&self, data: &[u8]) -> Result<(), AttestHiffyError>;
}

/// The `AttestHiffy` type can speak to the `Attest` tasks eaither the RoT
/// directly or through SpRot task in the SP. This enum is used to control
/// which.
#[derive(Clone, Debug)]
pub enum AttestTask {
    Rot,
    Sprot,
}

/// We use the `Display` trait to produce the string representation of the
/// attest task name. In the RoT the task is called `Attest`, in the SP the
/// Attest API is exposed by the task named `SpRot`.
impl fmt::Display for AttestTask {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Rot => write!(f, "Attest"),
            Self::Sprot => write!(f, "SpRot"),
        }
    }
}

#[derive(Debug, Error)]
pub enum AttestHiffyError {
    #[error("Failed to parse u32 from hiffy hex output: {0}")]
    BadU32(#[from] std::num::ParseIntError),
    #[error("Hiffy command failed: {0}")]
    ExitStatus(std::process::ExitStatus),
    #[error("Failed to hubpack something: {0}")]
    Serialize(#[from] hubpack::Error),
    #[error("Failed to do something w/ a tempfile: {0}")]
    TempFile(#[from] std::io::Error),
}

/// A type to simplify the execution of the HIF operations exposed by the RoT
/// Attest task.
pub struct AttestHiffy {
    task: AttestTask,
}

impl AttestHiffy {
    const CHUNK_SIZE: usize = 256;

    pub fn new(task: AttestTask) -> Self {
        AttestHiffy { task }
    }

    /// `humility` returns u32s as hex strings prefixed with "0x". This
    /// function expects a string formatted like an output string from hiffy
    /// returning a u32. If the string is not prefixed with "0x" it is assumed
    /// to be decimal. Currently this function ignores the interface and
    /// operation names from the string. Future work may check that these are
    /// consistent with the operation executed.
    fn u32_from_cmd_output(output: Output) -> Result<u32, AttestHiffyError> {
        if output.status.success() {
            // check interface & operation name?
            let output = String::from_utf8_lossy(&output.stdout);
            let output: Vec<&str> = output.trim().split(' ').collect();
            let output = output[output.len() - 1];

            let (output, _) = match output.strip_prefix("0x") {
                Some(s) => (s, 16),
                None => (output, 10),
            };

            Ok(u32::from_str_radix(output, 16)
                .map_err(AttestHiffyError::BadU32)?)
        } else {
            Err(AttestHiffyError::ExitStatus(output.status))
        }
    }

    /// This convenience function encapsulates a pattern common to
    /// the hiffy command line for the `Attest` operations that get the
    /// lengths of the data returned in leases.
    fn get_len_cmd(
        &self,
        op: &str,
        args: Option<String>,
    ) -> Result<u32, AttestHiffyError> {
        // rely on environment for target & archive?
        // check that they are set before continuing
        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg("--call");
        cmd.arg(format!("{}.{}", self.task, op));
        if let Some(a) = args {
            cmd.arg(format!("--arguments={a}"));
        }

        let output = cmd.output()?;
        Self::u32_from_cmd_output(output)
    }

    /// This convenience function encapsulates a pattern common to the hiffy
    /// command line for the `Attest` operations that return blobs in chunks.
    fn get_chunk(
        &self,
        op: &str,
        length: usize,
        output: &Path,
        args: Option<&str>,
        input: Option<&str>,
    ) -> Result<(), AttestHiffyError> {
        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg(format!("--call={}.{}", self.task, op));
        cmd.arg(format!("--num={length}"));
        cmd.arg(format!("--output={}", output.to_string_lossy()));
        if let Some(args) = args {
            cmd.arg("--arguments");
            cmd.arg(args);
        }
        if let Some(i) = input {
            cmd.arg(format!("--input={i}"));
        }

        let output = cmd.output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(AttestHiffyError::ExitStatus(output.status))
        }
    }
}

impl AttestSprot for AttestHiffy {
    fn attest(
        &self,
        nonce: &Nonce,
        out: &mut [u8],
    ) -> Result<(), AttestHiffyError> {
        let mut attestation_tmp = tempfile::NamedTempFile::new()?;
        let mut nonce_tmp = tempfile::NamedTempFile::new()?;

        let mut buf = [0u8; Nonce::MAX_SIZE];
        hubpack::serialize(&mut buf, &nonce)
            .map_err(AttestHiffyError::Serialize)?;
        nonce_tmp.write_all(&buf)?;

        self.get_chunk(
            "attest",
            out.len(),
            attestation_tmp.path(),
            None,
            Some(&nonce_tmp.path().to_string_lossy()),
        )?;
        Ok(attestation_tmp.read_exact(&mut out[..])?)
    }

    /// Get length of the measurement log in bytes.
    fn attest_len(&self) -> Result<u32, AttestHiffyError> {
        self.get_len_cmd("attest_len", None)
    }

    /// Get length of the certificate chain from the Attest task. This cert
    /// chain may be self signed or will terminate at the intermediate before
    /// the root.
    fn cert_chain_len(&self) -> Result<u32, AttestHiffyError> {
        self.get_len_cmd("cert_chain_len", None)
    }

    /// Get length of the certificate at the provided index in bytes.
    fn cert_len(&self, index: u32) -> Result<u32, AttestHiffyError> {
        self.get_len_cmd("cert_len", Some(format!("index={index}")))
    }

    fn cert(&self, index: u32, out: &mut [u8]) -> Result<(), AttestHiffyError> {
        for offset in
            (0..out.len() - Self::CHUNK_SIZE).step_by(Self::CHUNK_SIZE)
        {
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.get_chunk(
                "cert",
                Self::CHUNK_SIZE,
                tmp.path(),
                Some(&format!("index={index},offset={offset}")),
                None,
            )?;
            tmp.read_exact(&mut out[offset..offset + Self::CHUNK_SIZE])?;
        }

        let remain = out.len() % Self::CHUNK_SIZE;
        if remain != 0 {
            let offset = out.len() - remain;
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.get_chunk(
                "cert",
                remain,
                tmp.path(),
                Some(&format!("index={index},offset={offset}")),
                None,
            )?;
            tmp.read_exact(&mut out[offset..])?;
        }

        Ok(())
    }

    /// Get measurement log. This function assumes that the slice provided
    /// is sufficiently large to hold the log.
    fn log(&self, out: &mut [u8]) -> Result<(), AttestHiffyError> {
        for offset in
            (0..out.len() - Self::CHUNK_SIZE).step_by(Self::CHUNK_SIZE)
        {
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.get_chunk(
                "log",
                Self::CHUNK_SIZE,
                tmp.path(),
                Some(&format!("offset={offset}")),
                None,
            )?;
            tmp.read_exact(&mut out[offset..offset + Self::CHUNK_SIZE])?;
        }

        let remain = out.len() % Self::CHUNK_SIZE;
        if remain != 0 {
            let offset = out.len() - remain;
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.get_chunk(
                "log",
                remain,
                tmp.path(),
                Some(&format!("offset={offset}")),
                None,
            )?;
            tmp.read_exact(&mut out[offset..])?;
        }

        Ok(())
    }

    /// Get length of the measurement log in bytes.
    fn log_len(&self) -> Result<u32, AttestHiffyError> {
        self.get_len_cmd("log_len", None)
    }

    /// Record the sha3 hash of a file.
    fn record(&self, data: &[u8]) -> Result<(), AttestHiffyError> {
        let digest = Sha3_256::digest(data);
        let mut tmp = NamedTempFile::new()?;
        tmp.write_all(digest.as_slice())?;

        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg(format!("--call={}.record", self.task));
        cmd.arg(format!("--input={}", tmp.path().to_string_lossy()));
        cmd.arg("--arguments=algorithm=Sha3_256");

        let output = cmd.output()?;
        if output.status.success() {
            Ok(())
        } else {
            Err(AttestHiffyError::ExitStatus(output.status))
        }
    }
}

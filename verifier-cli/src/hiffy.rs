// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{AttestSprot, Interface};
use anyhow::{anyhow, Context, Result};
use attest_data::Nonce;
use hubpack::SerializedSize;
use log::{debug, info};
use sha3::{Digest, Sha3_256};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Command, Output},
};
use tempfile::NamedTempFile;

/// A type to simplify the execution of the HIF operations exposed by the RoT
/// Attest task.
pub struct AttestHiffy {
    /// The Attest task can be reached either directly through the `hiffy`
    /// task in the RoT or through the `Sprot` task in the Sp. This member
    /// determins which is used.
    interface: Interface,
}

impl AttestHiffy {
    const CHUNK_SIZE: usize = 256;

    pub fn new(interface: Interface) -> Self {
        AttestHiffy { interface }
    }

    /// `humility` returns u32s as hex strings prefixed with "0x". This
    /// function expects a string formatted like an output string from hiffy
    /// returning a u32. If the string is not prefixed with "0x" it is assumed
    /// to be decimal. Currently this function ignores the interface and
    /// operation names from the string. Future work may check that these are
    /// consistent with the operation executed.
    fn u32_from_cmd_output(output: Output) -> Result<u32> {
        if output.status.success() {
            // check interface & operation name?
            let output = String::from_utf8_lossy(&output.stdout);
            let output: Vec<&str> = output.trim().split(' ').collect();
            let output = output[output.len() - 1];
            debug!("output: {}", output);

            let (output, radix) = match output.strip_prefix("0x") {
                Some(s) => {
                    debug!("prefix stripped: \"{}\"", s);
                    (s, 16)
                }
                None => (output, 10),
            };

            let log_len =
                u32::from_str_radix(output, 16).with_context(|| {
                    format!("Failed to parse \"{output}\" as base {radix} u32",)
                })?;

            debug!("output u32: {log_len}");

            Ok(log_len)
        } else {
            Err(anyhow!(
                "command failed with status: {}\nstdout: \"{}\"\nstderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    /// This convenience function encapsulates a pattern common to
    /// the hiffy command line for the `Attest` operations that get the
    /// lengths of the data returned in leases.
    fn get_len_cmd(&self, op: &str, args: Option<String>) -> Result<u32> {
        // rely on environment for target & archive?
        // check that they are set before continuing
        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg("--call");
        cmd.arg(format!("{}.{}", self.interface, op));
        if let Some(a) = args {
            cmd.arg(format!("--arguments={a}"));
        }
        debug!("executing command: {:?}", cmd);

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
    ) -> Result<()> {
        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg(format!("--call={}.{}", self.interface, op));
        cmd.arg(format!("--num={length}"));
        cmd.arg(format!("--output={}", output.to_string_lossy()));
        if let Some(args) = args {
            cmd.arg("--arguments");
            cmd.arg(args);
        }
        if let Some(i) = input {
            cmd.arg(format!("--input={i}"));
        }
        debug!("executing command: {:?}", cmd);

        let output = cmd.output()?;
        if output.status.success() {
            debug!("output: {}", String::from_utf8_lossy(&output.stdout));
            Ok(())
        } else {
            Err(anyhow!(
                "command failed with status: {}\nstdout: \"{}\"\nstderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

impl AttestSprot for AttestHiffy {
    fn attest(&self, nonce: &Nonce, out: &mut [u8]) -> Result<()> {
        let mut attestation_tmp = tempfile::NamedTempFile::new()?;
        let mut nonce_tmp = tempfile::NamedTempFile::new()?;

        let mut buf = [0u8; Nonce::MAX_SIZE];
        hubpack::serialize(&mut buf, &nonce)
            .map_err(|_| anyhow!("failed to serialize Nonce"))?;
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
    fn attest_len(&self) -> Result<u32> {
        self.get_len_cmd("attest_len", None)
    }

    /// Get length of the certificate chain from the Attest task. This cert
    /// chain may be self signed or will terminate at the intermediate before
    /// the root.
    fn cert_chain_len(&self) -> Result<u32> {
        self.get_len_cmd("cert_chain_len", None)
    }

    /// Get length of the certificate at the provided index in bytes.
    fn cert_len(&self, index: u32) -> Result<u32> {
        self.get_len_cmd("cert_len", Some(format!("index={index}")))
    }

    fn cert(&self, index: u32, out: &mut [u8]) -> Result<()> {
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
    fn log(&self, out: &mut [u8]) -> Result<()> {
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
    fn log_len(&self) -> Result<u32> {
        self.get_len_cmd("log_len", None)
    }

    /// Record the sha3 hash of a file.
    fn record(&self, data: &[u8]) -> Result<()> {
        let digest = Sha3_256::digest(data);
        info!("Recording measurement: {:?}", digest);
        let mut tmp = NamedTempFile::new()?;
        if digest.as_slice().len() != tmp.write(digest.as_slice())? {
            return Err(anyhow!("failed to write all data to disk"));
        }

        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg(format!("--call={}.record", self.interface));
        cmd.arg(format!("--input={}", tmp.path().to_string_lossy()));
        cmd.arg("--arguments=algorithm=Sha3_256");
        debug!("executing command: {:?}", cmd);

        let output = cmd.output()?;
        if output.status.success() {
            debug!("output: {}", String::from_utf8_lossy(&output.stdout));
            Ok(())
        } else {
            Err(anyhow!(
                "command failed with status: {}\nstdout: \"{}\"\nstderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

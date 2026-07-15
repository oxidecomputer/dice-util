// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{Attestation, Log, Nonce, Nonce32};
use hubpack::SerializedSize;
use thiserror::Error;
use x509_cert::{der::Decode, Certificate, PkiPath};

use crate::{Attest, AttestError};
use humility_core::hubris::HubrisArchive;
use humility_probes_core::{HubrisAttach, ProbeCore};
use slog::Logger;

use humility_hiffy::HiffyContext;
use humility_idol::{HubrisIdol, IdolArgument};

/// The `AttestHiffy` type can speak to the `Attest` tasks via either the RoT
/// directly or through SpRot task in the SP. This enum is used to control
/// which.
#[derive(Clone, Debug)]
pub enum AttestTask {
    Rot,
    Sprot,
}

impl AttestTask {
    fn get_command(&self, cmd: &str) -> String {
        let task = match self {
            AttestTask::Rot => "Attest",
            AttestTask::Sprot => "SpRot",
        };
        format!("{task}.{cmd}")
    }
}

/// Possible errors produced while iteracting with the attest task using the
/// `humility hiffy` interface.
#[derive(Debug, Error)]
pub enum AttestHiffyError {
    /// Failure from idol
    #[error("idol error")]
    Idol(#[source] anyhow::Error),
    /// Failure from hiffy context
    #[error("hiffy context error")]
    HiffyContext(#[source] anyhow::Error),
    /// Failure from hiffy
    #[error("hiffy error")]
    Hiffy(#[source] humility_hiffy::HiffyError),
    /// Error calling idol function
    #[error("idol call error")]
    IdolCall(#[source] humility_hiffy::HiffyError),
}

/// A type to simplify the execution of the HIF operations exposed by the RoT
/// Attest task.
pub struct AttestHiffy {
    core: ProbeCore,
    hubris: HubrisArchive,
    log: Logger,
    target: AttestTask,
}

impl AttestHiffy {
    pub fn new(target: AttestTask, log: &Logger) -> Self {
        // This matches the existing behavior but do we want to make this better?
        let hubris = std::env::var("HUMILITY_ARCHIVE").unwrap();
        let probe = std::env::var("HUMILITY_PROBE").unwrap();

        let hubris = HubrisArchive::load_from_path(&hubris, &log).unwrap();

        let core = hubris.attach_probe(&probe, &log).unwrap();

        let log = log.new(slog::o!());

        Self {
            core,
            hubris,
            log,
            target,
        }
    }
}

const TRANSFER_SIZE: usize = 128;

#[async_trait::async_trait]
impl Attest for AttestHiffy {
    async fn get_measurement_log(&mut self) -> Result<Log, AttestError> {
        let mut context = HiffyContext::new(
            &self.hubris,
            &mut self.core,
            std::time::Duration::from_secs(5),
            &self.log,
        )
        .map_err(AttestHiffyError::HiffyContext)?;

        let log_len_op = self
            .hubris
            .get_idol_command(self.target.get_command("log_len").as_str())
            .map_err(AttestHiffyError::Idol)?;

        let log_op = self
            .hubris
            .get_idol_command(self.target.get_command("log").as_str())
            .map_err(AttestHiffyError::Idol)?;

        let log_len = context
            .call::<u32>(&mut self.core, &log_len_op, &[], None, None)
            .map_err(AttestHiffyError::Hiffy)? as usize;

        let mut log = vec![0u8; log_len];
        let mut offset = 0;

        for chunk in log.chunks_mut(TRANSFER_SIZE) {
            context
                .call::<()>(
                    &mut self.core,
                    &log_op,
                    &[("offset", IdolArgument::Scalar(offset as u64))],
                    None,
                    Some(chunk),
                )
                .map_err(AttestHiffyError::IdolCall)?;
            offset += chunk.len();
        }

        let (log, _): (Log, _) =
            hubpack::deserialize(&log).map_err(AttestError::Deserialize)?;

        Ok(log)
    }

    async fn get_certificates(&mut self) -> Result<PkiPath, AttestError> {
        let mut cert_chain = PkiPath::new();

        let mut context = HiffyContext::new(
            &self.hubris,
            &mut self.core,
            std::time::Duration::from_secs(5),
            &self.log,
        )
        .map_err(AttestHiffyError::HiffyContext)?;

        let cert_chain_len_op = self
            .hubris
            .get_idol_command(
                self.target.get_command("cert_chain_len").as_str(),
            )
            .map_err(AttestHiffyError::Idol)?;

        let cert_len_op = self
            .hubris
            .get_idol_command(self.target.get_command("cert_len").as_str())
            .map_err(AttestHiffyError::Idol)?;

        let cert_op = self
            .hubris
            .get_idol_command(self.target.get_command("cert").as_str())
            .map_err(AttestHiffyError::Idol)?;

        let cert_count = context
            .call::<u32>(&mut self.core, &cert_chain_len_op, &[], None, None)
            .map_err(AttestHiffyError::Hiffy)?
            as usize;

        for cert_index in 0..cert_count {
            let cert_len = context
                .call::<u32>(
                    &mut self.core,
                    &cert_len_op,
                    &[("index", IdolArgument::Scalar(cert_index as u64))],
                    None,
                    None,
                )
                .map_err(AttestHiffyError::IdolCall)?;
            let mut offset = 0;
            let mut cert = vec![0u8; cert_len as usize];
            for chunk in cert.chunks_mut(TRANSFER_SIZE) {
                context
                    .call::<()>(
                        &mut self.core,
                        &cert_op,
                        &[
                            ("index", IdolArgument::Scalar(cert_index as u64)),
                            ("offset", IdolArgument::Scalar(offset as u64)),
                        ],
                        None,
                        Some(chunk),
                    )
                    .map_err(AttestHiffyError::IdolCall)?;
                offset += chunk.len();
            }

            let cert = Certificate::from_der(&cert)?;
            cert_chain.push(cert);
        }

        Ok(cert_chain)
    }

    async fn attest(
        &mut self,
        nonce: &Nonce,
    ) -> Result<Attestation, AttestError> {
        let nonce: &Nonce32 = nonce.try_into()?;

        let mut buf = [0u8; Nonce32::MAX_SIZE];
        hubpack::serialize(&mut buf, &nonce).map_err(AttestError::Serialize)?;

        let mut context = HiffyContext::new(
            &self.hubris,
            &mut self.core,
            std::time::Duration::from_secs(5),
            &self.log,
        )
        .map_err(AttestHiffyError::HiffyContext)?;

        let attest_len_op = self
            .hubris
            .get_idol_command(self.target.get_command("attest_len").as_str())
            .map_err(AttestHiffyError::Idol)?;

        let attest_op = self
            .hubris
            .get_idol_command(self.target.get_command("attest").as_str())
            .map_err(AttestHiffyError::Idol)?;

        let attest_len = context
            .call::<u32>(&mut self.core, &attest_len_op, &[], None, None)
            .map_err(AttestHiffyError::Hiffy)?
            as usize;

        let mut attest = vec![0u8; attest_len];

        context
            .call::<()>(
                &mut self.core,
                &attest_op,
                &[],
                Some(&buf),
                Some(&mut attest),
            )
            .map_err(AttestHiffyError::IdolCall)?;

        let (attestation, _): (Attestation, _) =
            hubpack::deserialize(&attest).map_err(AttestError::Deserialize)?;

        Ok(attestation)
    }
}

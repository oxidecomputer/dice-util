// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{Attestation, Log, QualifyingData, QualifyingData32};
use hubpack::SerializedSize;
use thiserror::Error;
use x509_cert::{Certificate, PkiPath, der::Decode};

use crate::{OxideRot, OxideRotError};
use humility_core::hubris::HubrisArchive;
use humility_hiffy::HiffyContext;
use humility_idol::{HubrisIdol, IdolArgument};
use humility_probes_core::{HubrisAttach, ProbeCore};
use slog::Logger;

/// The `OxideRotHiffy` type can speak to the `Attest` tasks via either the RoT
/// directly or through SpRot task in the SP. This enum is used to control
/// which.
#[derive(Clone, Debug)]
pub enum OxideRotTask {
    Rot,
    Sprot,
}

impl OxideRotTask {
    fn get_command(&self, cmd: &str) -> String {
        let task = match self {
            OxideRotTask::Rot => "Attest",
            OxideRotTask::Sprot => "SpRot",
        };
        format!("{task}.{cmd}")
    }
}

/// Possible errors produced while iteracting with the attest task using the
/// `humility hiffy` interface.
#[derive(Debug, Error)]
pub enum OxideRotHiffyError {
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
    #[error("HUMILITY_ARCHIVE unset")]
    HumilityArchiveUnset(#[source] std::env::VarError),
    #[error("HUMILTIY_PROBE unset")]
    HumilityProbeUnset(#[source] std::env::VarError),
    #[error("Hubris archive load failed")]
    HubrisArchive(#[source] anyhow::Error),
    #[error("probe attach failed")]
    ProbeAttach(#[source] anyhow::Error),
}

/// A type to simplify the execution of the HIF operations exposed by the RoT
/// Attest task. We intentionally do not attach the probe to avoid the
/// need to have &mut everywhere on functions
pub struct OxideRotHiffy {
    log: Logger,
    target: OxideRotTask,
    //probe: String,
}

impl OxideRotHiffy {
    pub fn new(target: OxideRotTask, log: &Logger) -> Self {
        let log = log.new(slog::o!());

        Self { log, target }
    }

    pub fn new_hiffy(
        &self,
    ) -> Result<(ProbeCore, HubrisArchive), OxideRotHiffyError> {
        // This matches the behavior of the old humility binary behavior.
        // Passing in the paths directly requires some clap/CLI rework.
        // We also can't currently do this at creation time due to
        // some underlying issues with humility + async
        let hubris = std::env::var("HUMILITY_ARCHIVE")
            .map_err(OxideRotHiffyError::HumilityArchiveUnset)?;
        let probe = std::env::var("HUMILITY_PROBE")
            .map_err(OxideRotHiffyError::HumilityProbeUnset)?;

        let hubris = HubrisArchive::load_from_path(&hubris, &self.log)
            .map_err(OxideRotHiffyError::HubrisArchive)?;

        let core = hubris.attach_probe(&probe, 8000, &self.log).unwrap();

        Ok((core, hubris))
    }
}

const TRANSFER_SIZE: usize = 128;

#[async_trait::async_trait]
impl OxideRot for OxideRotHiffy {
    async fn get_measurement_log(&self) -> Result<Log, OxideRotError> {
        let (mut core, hubris) = self.new_hiffy()?;

        let mut context = HiffyContext::new(
            &hubris,
            &mut core,
            std::time::Duration::from_secs(5),
            &self.log,
        )
        .map_err(OxideRotHiffyError::HiffyContext)?;

        let log_len_op = hubris
            .get_idol_command(self.target.get_command("log_len").as_str())
            .map_err(OxideRotHiffyError::Idol)?;

        let log_op = hubris
            .get_idol_command(self.target.get_command("log").as_str())
            .map_err(OxideRotHiffyError::Idol)?;

        let log_len = context
            .call::<u32>(&mut core, &log_len_op, &[], None, None)
            .map_err(OxideRotHiffyError::Hiffy)? as usize;

        let mut log = vec![0u8; log_len];
        let mut offset = 0;

        for chunk in log.chunks_mut(TRANSFER_SIZE) {
            context
                .call::<()>(
                    &mut core,
                    &log_op,
                    &[("offset", IdolArgument::Scalar(offset as u64))],
                    None,
                    Some(chunk),
                )
                .map_err(OxideRotHiffyError::IdolCall)?;
            offset += chunk.len();
        }

        let (log, _): (Log, _) =
            hubpack::deserialize(&log).map_err(OxideRotError::Deserialize)?;

        Ok(log)
    }

    async fn get_certificates(&self) -> Result<PkiPath, OxideRotError> {
        let mut cert_chain = PkiPath::new();

        let (mut core, hubris) = self.new_hiffy()?;

        let mut context = HiffyContext::new(
            &hubris,
            &mut core,
            std::time::Duration::from_secs(5),
            &self.log,
        )
        .map_err(OxideRotHiffyError::HiffyContext)?;

        let cert_chain_len_op = hubris
            .get_idol_command(
                self.target.get_command("cert_chain_len").as_str(),
            )
            .map_err(OxideRotHiffyError::Idol)?;

        let cert_len_op = hubris
            .get_idol_command(self.target.get_command("cert_len").as_str())
            .map_err(OxideRotHiffyError::Idol)?;

        let cert_op = hubris
            .get_idol_command(self.target.get_command("cert").as_str())
            .map_err(OxideRotHiffyError::Idol)?;

        let cert_count = context
            .call::<u32>(&mut core, &cert_chain_len_op, &[], None, None)
            .map_err(OxideRotHiffyError::Hiffy)?
            as usize;

        for cert_index in 0..cert_count {
            let cert_len = context
                .call::<u32>(
                    &mut core,
                    &cert_len_op,
                    &[("index", IdolArgument::Scalar(cert_index as u64))],
                    None,
                    None,
                )
                .map_err(OxideRotHiffyError::IdolCall)?;
            let mut offset = 0;
            let mut cert = vec![0u8; cert_len as usize];
            for chunk in cert.chunks_mut(TRANSFER_SIZE) {
                context
                    .call::<()>(
                        &mut core,
                        &cert_op,
                        &[
                            ("index", IdolArgument::Scalar(cert_index as u64)),
                            ("offset", IdolArgument::Scalar(offset as u64)),
                        ],
                        None,
                        Some(chunk),
                    )
                    .map_err(OxideRotHiffyError::IdolCall)?;
                offset += chunk.len();
            }

            let cert = Certificate::from_der(&cert)?;
            cert_chain.push(cert);
        }

        Ok(cert_chain)
    }

    async fn attest(
        &self,
        qdata: &QualifyingData,
    ) -> Result<Attestation, OxideRotError> {
        let qdata: &QualifyingData32 = qdata.try_into()?;

        let (mut core, hubris) = self.new_hiffy()?;

        let mut buf = [0u8; QualifyingData32::MAX_SIZE];
        hubpack::serialize(&mut buf, &qdata)
            .map_err(OxideRotError::Serialize)?;

        let mut context = HiffyContext::new(
            &hubris,
            &mut core,
            std::time::Duration::from_secs(5),
            &self.log,
        )
        .map_err(OxideRotHiffyError::HiffyContext)?;

        let attest_len_op = hubris
            .get_idol_command(self.target.get_command("attest_len").as_str())
            .map_err(OxideRotHiffyError::Idol)?;

        let attest_op = hubris
            .get_idol_command(self.target.get_command("attest").as_str())
            .map_err(OxideRotHiffyError::Idol)?;

        let attest_len = context
            .call::<u32>(&mut core, &attest_len_op, &[], None, None)
            .map_err(OxideRotHiffyError::Hiffy)?
            as usize;

        let mut attest = vec![0u8; attest_len];

        context
            .call::<()>(
                &mut core,
                &attest_op,
                &[],
                Some(&buf),
                Some(&mut attest),
            )
            .map_err(OxideRotHiffyError::IdolCall)?;

        let (attestation, _): (Attestation, _) = hubpack::deserialize(&attest)
            .map_err(OxideRotError::Deserialize)?;

        Ok(attestation)
    }
}

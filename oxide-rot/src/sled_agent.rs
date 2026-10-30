// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{OxideRot, OxideRotError};

use std::net::SocketAddrV6;

use attest_data::{Attestation, Log, Measurement, QualifyingData};
use sled_agent_client::Client as SledAgentClient;
use sled_agent_types_versions::latest::rot as SledAgentTypes;
use x509_cert::{Certificate, PkiPath, der::DecodePem};

pub struct OxideRotSledAgent {
    client: SledAgentClient,
}

impl OxideRotSledAgent {
    pub fn new(addr: SocketAddrV6, log: &slog::Logger) -> Self {
        let client = SledAgentClient::new(
            &format!("http://{addr}"),
            log.new(slog::o!("SledAgentClient" => addr.to_string())),
        );
        Self { client }
    }
}

#[async_trait::async_trait]
impl OxideRot for OxideRotSledAgent {
    async fn get_measurement_log(&self) -> Result<Log, OxideRotError> {
        let mut log = Log::default();
        let measurments = self
            .client
            .rot_measurement_log(&SledAgentTypes::Rot::Oxide)
            .await?
            .into_inner();
        for m in measurments.0 {
            assert!(log.push(match m {
                SledAgentTypes::Measurement::Sha3_256(d) => {
                    Measurement::Sha3_256(d.0.into())
                }
            }));
        }
        Ok(log)
    }

    async fn get_certificates(&self) -> Result<PkiPath, OxideRotError> {
        let certs = self
            .client
            .rot_certificate_chain(&SledAgentTypes::Rot::Oxide)
            .await?
            .into_inner();
        Ok(certs
            .0
            .into_iter()
            .map(Certificate::from_pem)
            .collect::<Result<Vec<_>, _>>()?)
    }

    async fn attest(
        &self,
        qdata: &QualifyingData,
    ) -> Result<Attestation, OxideRotError> {
        let &QualifyingData::Q32(qdata) = qdata;
        let attestation = self
            .client
            .rot_attest(
                &SledAgentTypes::Rot::Oxide,
                &SledAgentTypes::Nonce::N32(qdata.0),
            )
            .await?
            .into_inner();
        let attestation = match attestation {
            SledAgentTypes::Attestation::Ed25519(d) => {
                Attestation::Ed25519(d.0.into())
            }
        };
        Ok(attestation)
    }
}

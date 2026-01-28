// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{Attest, AttestError};

use std::net::SocketAddrV6;

use attest_data::{Attestation, Log, Measurement, Nonce};
use sled_agent_client::Client as SledAgentClient;
use sled_agent_types_versions::latest::rot as SledAgentTypes;
use tokio::runtime::{Builder, Runtime};
use x509_cert::{der::DecodePem, Certificate, PkiPath};

pub struct AttestSledAgent {
    client: SledAgentClient,
    rt: Runtime,
}

impl AttestSledAgent {
    pub fn new(addr: SocketAddrV6, log: &slog::Logger) -> Self {
        let rt = Builder::new_current_thread()
            .enable_time()
            .enable_io()
            .build()
            .unwrap();
        let client = SledAgentClient::new(
            &format!("http://{addr}"),
            log.new(slog::o!("SledAgentClient" => addr.to_string())),
        );
        Self { client, rt }
    }
}

impl Attest for AttestSledAgent {
    fn get_measurement_log(&self) -> Result<Log, AttestError> {
        let mut log = Log::default();
        let measurments = self
            .rt
            .block_on(
                self.client.rot_measurement_log(&SledAgentTypes::Rot::Oxide),
            )?
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

    fn get_certificates(&self) -> Result<PkiPath, AttestError> {
        let certs = self
            .rt
            .block_on(
                self.client
                    .rot_certificate_chain(&SledAgentTypes::Rot::Oxide),
            )?
            .into_inner();
        Ok(certs
            .0
            .into_iter()
            .map(Certificate::from_pem)
            .collect::<Result<Vec<_>, _>>()?)
    }

    fn attest(&self, nonce: &Nonce) -> Result<Attestation, AttestError> {
        let &Nonce::N32(nonce) = nonce;
        let attestation = self
            .rt
            .block_on(self.client.rot_attest(
                &SledAgentTypes::Rot::Oxide,
                &SledAgentTypes::Nonce::N32(nonce.0),
            ))?
            .into_inner();
        let attestation = match attestation {
            SledAgentTypes::Attestation::Ed25519(d) => {
                Attestation::Ed25519(d.0.into())
            }
        };
        Ok(attestation)
    }
}

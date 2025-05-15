// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::Attest;
use anyhow::{anyhow, Result};
use attest_data::{Attestation, Log, Nonce};
use dice_verifier::hiffy::{AttestHiffy, AttestSprot};
use x509_cert::{der::Decode, Certificate, PkiPath};

impl Attest for AttestHiffy {
    fn get_measurement_log(&self) -> Result<Log> {
        let log_len = self.log_len()?;
        let mut log = vec![0u8; log_len as usize];
        self.log(&mut log)?;
        let (log, _): (Log, _) = hubpack::deserialize(&log)
            .map_err(|e| anyhow!("Failed to deserialize Log: {}", e))?;

        Ok(log)
    }

    fn get_certificates(&self) -> Result<PkiPath> {
        let mut cert_chain = PkiPath::new();
        for index in 0..self.cert_chain_len()? {
            let cert_len = self.cert_len(index)?;
            let mut cert = vec![0u8; cert_len as usize];
            self.cert(index, &mut cert)?;

            let cert = Certificate::from_der(&cert)?;

            cert_chain.push(cert);
        }

        Ok(cert_chain)
    }

    fn attest(&self, nonce: &Nonce) -> Result<Attestation> {
        let attest_len = self.attest_len()?;
        let mut out = vec![0u8; attest_len as usize];
        AttestSprot::attest(self, nonce, &mut out)?;

        let (attestation, _): (Attestation, _) = hubpack::deserialize(&out)
            .map_err(|e| anyhow!("Failed to deserialize Attestation: {}", e))?;

        Ok(attestation)
    }
}

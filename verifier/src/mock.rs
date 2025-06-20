// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{Attest, AttestError};
use attest_data::{Attestation, Ed25519Signature, Log, Nonce};
use ed25519_dalek::{
    pkcs8::{self, DecodePrivateKey},
    Signer, SigningKey,
};
use hubpack::SerializedSize;
use sha3::{Digest, Sha3_256};
use std::{fs, io, path::Path};
use thiserror::Error;
use x509_cert::{der, Certificate, PkiPath};

#[derive(Debug, Error)]
pub enum AttestMockError {
    #[error("Failed to parse certificate: {0}")]
    DerError(#[from] der::Error),
    #[error("Failed to deserialized hubpacked log: {0}")]
    Deserialize(#[from] hubpack::error::Error),
    #[error("Failed to parse key from PKCS8: {0}")]
    Pkcs8(#[from] pkcs8::Error),
    #[error("Failed to read file from Path: {0}")]
    IoError(#[from] io::Error),
}

pub struct AttestMock {
    certs: PkiPath,
    log: Log,
    alias_key: SigningKey,
}

impl AttestMock {
    pub fn load<P: AsRef<Path>, L: AsRef<Path>, A: AsRef<Path>>(
        pki_path: P,
        log_path: L,
        alias_path: A,
    ) -> Result<Self, AttestMockError> {
        let certs = fs::read_to_string(pki_path)?;
        let certs = Certificate::load_pem_chain(certs.as_bytes())?;

        let log = fs::read(&log_path)?;
        let (log, _): (Log, _) = hubpack::deserialize(&log)?;

        let alias_key = SigningKey::read_pkcs8_pem_file(alias_path)?;

        Ok(AttestMock {
            certs,
            log,
            alias_key,
        })
    }
}

impl Attest for AttestMock {
    fn get_measurement_log(&self) -> Result<Log, AttestError> {
        Ok(self.log.clone())
    }

    fn get_certificates(&self) -> Result<PkiPath, AttestError> {
        Ok(self.certs.clone())
    }

    fn attest(&self, nonce: &Nonce) -> Result<Attestation, AttestError> {
        let mut buf = vec![0u8; Log::MAX_SIZE];
        let len = hubpack::serialize(&mut buf, &self.log)
            .map_err(AttestError::Serialize)?;

        let mut digest = Sha3_256::new();
        digest.update(&buf[..len]);
        digest.update(nonce.as_ref());

        let digest = digest.finalize();
        let sig = self.alias_key.sign(&digest);

        Ok(Attestation::Ed25519(Ed25519Signature::from(sig.to_bytes())))
    }
}

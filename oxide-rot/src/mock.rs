// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::{OxideRot, OxideRotError};
use attest_data::{
    Attestation, Ed25519Signature, Log, QualifyingData, QualifyingData32,
};
use ed25519_dalek::{
    Signer, SigningKey,
    pkcs8::{self, DecodePrivateKey},
};
use hubpack::SerializedSize;
use sha3::{Digest, Sha3_256};
use std::{fs, io, path::Path};
use thiserror::Error;
use x509_cert::{Certificate, PkiPath, der};

#[derive(Debug, Error)]
pub enum OxideRotMockError {
    #[error("Failed to parse certificate: {0}")]
    DerError(#[from] der::Error),
    #[error("Failed to deserialized hubpacked log: {0}")]
    Deserialize(#[from] hubpack::error::Error),
    #[error("Failed to parse key from PKCS8: {0}")]
    Pkcs8(#[from] pkcs8::Error),
    #[error("Failed to read file from Path: {0}")]
    IoError(#[from] io::Error),
}

pub struct OxideRotMock {
    certs: PkiPath,
    log: Log,
    alias_key: SigningKey,
}

impl OxideRotMock {
    pub fn load<P: AsRef<Path>, L: AsRef<Path>, A: AsRef<Path>>(
        pki_path: P,
        log_path: L,
        alias_path: A,
    ) -> Result<Self, OxideRotMockError> {
        let certs = fs::read_to_string(pki_path)?;
        let certs = Certificate::load_pem_chain(certs.as_bytes())?;

        let log = fs::read(&log_path)?;
        let (log, _): (Log, _) = hubpack::deserialize(&log)?;

        let alias_key = SigningKey::read_pkcs8_pem_file(alias_path)?;

        Ok(OxideRotMock {
            certs,
            log,
            alias_key,
        })
    }
}

#[async_trait::async_trait]
impl OxideRot for OxideRotMock {
    async fn get_measurement_log(&self) -> Result<Log, OxideRotError> {
        Ok(self.log.clone())
    }

    async fn get_certificates(&self) -> Result<PkiPath, OxideRotError> {
        Ok(self.certs.clone())
    }

    async fn attest(
        &self,
        qdata: &QualifyingData,
    ) -> Result<Attestation, OxideRotError> {
        let qdata: &QualifyingData32 = qdata.try_into()?;
        let mut buf = vec![0u8; Log::MAX_SIZE];
        let len = hubpack::serialize(&mut buf, &self.log)
            .map_err(OxideRotError::Serialize)?;

        let mut digest = Sha3_256::new();
        digest.update(&buf[..len]);
        digest.update(qdata.as_ref());

        let digest = digest.finalize();
        let sig = self.alias_key.sign(&digest);

        Ok(Attestation::Ed25519(Ed25519Signature::from(sig.to_bytes())))
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use std::{env, fs, path::PathBuf};

    const CERT_CHAIN: &str = "root.cert.pem";
    const LOG: &str = "log.bin";
    const SIGNING_KEY: &str = "root.key.pem";

    fn paths() -> (PathBuf, PathBuf, PathBuf) {
        let out = env::var("OUT_DIR").expect("get OUT_DIR from env");
        let out = PathBuf::from(out);

        (out.join(CERT_CHAIN), out.join(LOG), out.join(SIGNING_KEY))
    }

    #[test]
    fn bad_path_to_certs() {
        let (_, log, key) = paths();
        assert!(OxideRotMock::load("foo", &key, &log).is_err());
    }

    #[test]
    fn bad_path_to_log() {
        let (certs, _, key) = paths();
        assert!(OxideRotMock::load(&certs, "foo", &key).is_err());
    }

    #[test]
    fn bad_path_to_key() {
        let (certs, log, _) = paths();
        assert!(OxideRotMock::load(&certs, &log, "foo").is_err());
    }

    #[test]
    fn load() {
        let (certs, log, key) = paths();
        assert!(OxideRotMock::load(&certs, &log, &key).is_ok());
    }

    #[tokio::test]
    async fn attest() {
        use attest_data::QualifyingData32;
        use ed25519_dalek::{
            Signature, SigningKey, Verifier, VerifyingKey,
            pkcs8::DecodePrivateKey,
        };
        use hubpack::SerializedSize;
        use sha3::{Digest, Sha3_256};

        let (cert, log, key) = paths();
        let mock = OxideRotMock::load(&cert, &log, &key)
            .expect("log OxideRotMock from test inputs");

        let qdata =
            QualifyingData::from_platform_rng(32).expect("get Nonce from RNG");
        let attestation = mock.attest(&qdata).await.expect("attest to log");
        let log = mock
            .get_measurement_log()
            .await
            .expect("get measurement log ");

        let signing_key = fs::read_to_string(&key)
            .expect("Read signing key from file to string");
        let signing_key = SigningKey::from_pkcs8_pem(&signing_key)
            .expect("signing_key from pkcs8 string");

        let verifying_key = VerifyingKey::from(&signing_key);
        match attestation {
            Attestation::Ed25519(a) => {
                // the attestation is an ed25519 signature
                let sig = Signature::try_from(a.as_ref())
                    .expect("signature from Attestation::P384 bytes");

                // To verify the attestation we must reconstruct the 'message'
                // signed by the platform RoT. It is the sha3-256 digest over:
                // - the hubpack serialized measurement log
                // - the qdata that we provided to the `attest` function
                let mut buf = vec![0u8; Log::MAX_SIZE];
                let len = hubpack::serialize(&mut buf, &log)
                    .expect("hubpack serialize Log to buffer");

                let qdata: QualifyingData32 = qdata
                    .try_into()
                    .expect("QualifyingData into QualifyingData32");

                let mut digest = Sha3_256::new();
                digest.update(&buf[..len]);
                digest.update(qdata.as_ref());
                let digest = digest.finalize();

                let ret = verifying_key.verify(&digest, &sig);
                assert!(ret.is_ok());
            }
        }
    }
}

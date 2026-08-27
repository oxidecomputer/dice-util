// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub use helios_rot::{Attestation, Nonce, Nonce48};
use thiserror::Error;
use x509_cert::Certificate;

#[derive(Debug, Error)]
pub enum VerifyAttestationError {
    #[error("Failed to construct VerifyingKey from alias Cert SPKI")]
    VerifyingKey(#[from] x509_cert::spki::Error),
    #[error("Failed to construct Signature from Attestation")]
    Signature(#[source] p384::ecdsa::Error),
    #[error("The Attestation provided failed to verify the Nonce")]
    Verify(#[source] p384::ecdsa::Error),
}

// An attestation from the helios rot is: attestation = sign_alias(nonce)
// We must:
// - get the alias public key from the `Certificate`
// - reconstitute the message signed by the alias key (the nonce)
// When illumos supports runtime measurements the nonce will be combined with
// the serialized representation of the log using a hash function.
// NOTE: verify this w/ luqman / luqman's code ... or just test it
// - verify the attestation / signature over the message
pub fn verify_attestation(
    alias: &Certificate,
    attestation: &Attestation,
    nonce: &Nonce,
) -> Result<(), VerifyAttestationError> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use x509_cert::der::referenced::OwnedToRef;

    let spki = &alias.tbs_certificate.subject_public_key_info;
    let verifying_key = VerifyingKey::try_from(spki.owned_to_ref())?;

    let signature = match attestation {
        Attestation::P384(s) => Signature::try_from(&s.0[..])
            .map_err(VerifyAttestationError::Signature)?,
    };

    verifying_key
        .verify(nonce.as_ref(), &signature)
        .map_err(VerifyAttestationError::Verify)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use crate::helios_rot::{self, Nonce};
    use ::helios_rot::{HeliosRot, HeliosRotMock};
    use std::{
        env, fs,
        path::{Path, PathBuf},
    };
    use x509_cert::{der::DecodePem, Certificate};

    fn get_cert_from_file<P: AsRef<Path>>(p: P) -> Certificate {
        let p: &Path = p.as_ref();

        let pem_cert = fs::read(p).expect(&format!(
            "test root cert expected in file: {}",
            p.display()
        ));

        Certificate::from_pem(pem_cert).expect(&format!(
            "expected a PEM encoded cert from file: {}",
            p.display()
        ))
    }

    // Use the `helios_rot::HeliosRotMock` to generate an attestation
    // then verify it with `verify_attestation`
    #[test]
    fn verify_attestation() {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());

        let cert_chain = out.join("helios-rot.certlist.pem");
        let alias_key = out.join("dpe-tcb-0-20b87885cc8c321f.key.pem");

        let rot_mock = HeliosRotMock::load(&cert_chain, &alias_key)
            .expect("Construct HeliosRotMock from files");

        let nonce =
            Nonce::from_platform_rng(48).expect("Nonce from platform RNG");

        let attestation = rot_mock
            .attest(&nonce)
            .expect("Attestation from HeliosRotMock");

        let alias_cert = out.join("dpe-tcb-0-20b87885cc8c321f.cert.pem");
        let alias_cert = get_cert_from_file(&alias_cert);

        let res =
            helios_rot::verify_attestation(&alias_cert, &attestation, &nonce);

        assert!(res.is_ok());
    }

    #[test]
    fn verify_attestation_bad_nonce() {
        use crate::helios_rot::VerifyAttestationError;

        let out = PathBuf::from(env::var("OUT_DIR").unwrap());

        let cert_chain = out.join("helios-rot.certlist.pem");
        let alias_key = out.join("dpe-tcb-0-20b87885cc8c321f.key.pem");

        let rot_mock = HeliosRotMock::load(&cert_chain, &alias_key)
            .expect("Construct HeliosRotMock from files");

        let nonce =
            Nonce::from_platform_rng(48).expect("Nonce from platform RNG");

        let attestation = rot_mock
            .attest(&nonce)
            .expect("Attestation from HeliosRotMock");

        let alias_cert = out.join("dpe-tcb-0-20b87885cc8c321f.cert.pem");
        let alias_cert = get_cert_from_file(&alias_cert);

        // cause verify_attestation to fail by using a different nonce
        let nonce =
            Nonce::from_platform_rng(48).expect("Nonce from platform RNG");

        let res =
            helios_rot::verify_attestation(&alias_cert, &attestation, &nonce);

        assert!(res.is_err());
        // I wanted to `unwrap_err()` on the `Result` and `assert` on the error
        // type but the inner `p384::ecdsa::signature::Error` doesn't implement
        // `PartialEq`
        match res {
            Ok(_) => assert!(false),
            Err(VerifyAttestationError::Verify(p384::ecdsa::Error {
                ..
            })) => assert!(true),
            Err(_) => assert!(false),
        }
    }
}

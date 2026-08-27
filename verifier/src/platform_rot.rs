// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use attest_data::{AttestDataError, DiceTcbInfo, DICE_TCB_INFO};
pub use attest_data::{Attestation, Log, Measurement, Nonce};
use hubpack::SerializedSize;
pub use rats_corim::Corim;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;
use thiserror::Error;
use x509_cert::{
    der::{self, Decode, DecodeValue, Header, SliceReader},
    Certificate, PkiPath,
};

/// Possible errors produced by the `MeasurmentSet` construction process.
#[derive(Debug, Error)]
pub enum MeasurementSetError {
    #[error("failed to create reader from extension value: {0}")]
    ExtensionDecode(der::Error),
    #[error("failed to decode extension header: {0}")]
    HeaderDecode(der::Error),
    #[error("failed to decode TcbInfo extension: {0}")]
    DiceTcbInfoDecode(der::Error),
    #[error("failed to create Measurement from DiceTcbInfo extension: {0}")]
    MeasurementConstruct(#[from] AttestDataError),
}

/// This is a collection to represent the measurements received from an
/// attestor. These measurements will come from the measurement log and the
/// DiceTcbInfo extension(s) in the attestation cert chain / pki path.
#[derive(Debug, PartialEq)]
pub struct MeasurementSet(HashSet<Measurement>);

/// Construct a MeasurementSet from the provided artifacts. The
/// trustworthiness of these artifacts must be established independently
/// (see `verify_cert_chain` and `verify_attestation`).
impl MeasurementSet {
    /// Construct a MeasurementSet from the provided artifacts. The
    /// trustworthiness of these artifacts must be established independently
    /// (see `verify_cert_chain` and `verify_attestation`).
    pub fn from_artifacts(
        pki_path: &PkiPath,
        log: &Log,
    ) -> Result<Self, MeasurementSetError> {
        let mut measurements = HashSet::new();

        for cert in pki_path {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                for ext in extensions {
                    if ext.extn_id == DICE_TCB_INFO {
                        let mut reader =
                            SliceReader::new(ext.extn_value.as_bytes())
                                .map_err(
                                    MeasurementSetError::ExtensionDecode,
                                )?;
                        let header = Header::decode(&mut reader)
                            .map_err(MeasurementSetError::HeaderDecode)?;

                        let tcb_info =
                            DiceTcbInfo::decode_value(&mut reader, header)
                                .map_err(
                                    MeasurementSetError::DiceTcbInfoDecode,
                                )?;
                        if let Some(fwid_vec) = &tcb_info.fwids {
                            for fwid in fwid_vec {
                                let measurement = Measurement::try_from(fwid)?;
                                measurements.insert(measurement);
                            }
                        }
                    }
                }
            }
        }

        for measurement in log.iter() {
            measurements.insert(*measurement);
        }

        Ok(Self(measurements))
    }

    /// Thin wrapper over HashSet.is_subset w/ better type info
    pub fn is_subset(&self, corpus: &ReferenceMeasurements) -> bool {
        self.0.is_subset(&corpus.0)
    }

    /// Return the actual differences from the corpus, useful for debugging
    pub fn difference(
        &self,
        corpus: &ReferenceMeasurements,
    ) -> Option<MeasurementSet> {
        if self.is_subset(corpus) {
            None
        } else {
            let mut measurements = HashSet::new();
            for measurement in self.0.difference(&corpus.0) {
                measurements.insert(*measurement);
            }
            Some(MeasurementSet(measurements))
        }
    }
}

impl std::iter::IntoIterator for MeasurementSet {
    type Item = Measurement;
    type IntoIter = <HashSet<Measurement> as std::iter::IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl std::fmt::Display for MeasurementSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "measurement set")?;
        for m in &self.0 {
            writeln!(f, " {}", m)?;
        }
        if self.0.is_empty() {
            writeln!(f, "(set is empty)")?;
        }
        Ok(())
    }
}

/// A collection of measurement values that is used as a source of truth when
/// appraising the set of measurements derived from an attestation.
pub struct ReferenceMeasurements(pub(crate) HashSet<Measurement>);

/// Possible errors produced by the `ReferenceMeasurements` construction
/// process.
#[derive(Debug, Error)]
pub enum ReferenceMeasurementsError {
    #[error("Digest is not the expected length")]
    BadDigest(#[from] AttestDataError),
}

impl TryFrom<&[Corim]> for ReferenceMeasurements {
    type Error = ReferenceMeasurementsError;

    /// Construct a collection of `ReferenceMeasurements` from the provided
    /// `Corim` documents. The trustworthiness of these inputs must be
    /// established independently
    fn try_from(corims: &[Corim]) -> Result<Self, Self::Error> {
        let mut set = HashSet::new();

        for corim in corims {
            for d in corim.iter_digests() {
                set.insert(d.try_into()?);
            }
        }

        Ok(Self(set))
    }
}

impl std::fmt::Display for ReferenceMeasurements {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Reference measurements")?;
        for m in &self.0 {
            writeln!(f, " {}", m)?;
        }
        if self.0.is_empty() {
            writeln!(f, "(set is empty)")?;
        }
        Ok(())
    }
}

/// Errors produced by the `verify_attestation` function
#[derive(Debug, Error)]
pub enum VerifyAttestationError {
    #[error("Failed to hubpack the log: {0}")]
    Serialize(#[from] hubpack::error::Error),
    #[error(
        "Alias public key is malformed: \
        spki bit string does not end on octet boundary"
    )]
    OddKey,
    #[error("Failed to construct VerifyingKey from alias public key: {0}")]
    KeyConversion(ed25519_dalek::ed25519::Error),
    #[error("Failed to verify Attestation with alias public key: {0}")]
    VerificationFailed(ed25519_dalek::ed25519::Error),
}

/// This function uses the provided artifacts to establish trust in the Log.
/// The trustworthiness of the alias certificate and the attestation / nonce
/// must be established independently (see
pub fn verify_attestation(
    alias: &Certificate,
    attestation: &Attestation,
    log: &Log,
    nonce: &Nonce,
) -> Result<(), VerifyAttestationError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    // To verify an attestation we need to extract and construct a few
    // things before we can verify the attestation:
    // - signature: the attestation produced by the RoT when
    //   `alias_priv` is used to sign `message`
    let signature = match attestation {
        Attestation::Ed25519(s) => Signature::from_bytes(&s.0),
    };

    let mut buf = vec![0u8; Log::MAX_SIZE];
    hubpack::serialize(&mut buf, log)?;
    let log = buf;

    // - message: the data that's signed by the RoT to produce an
    //   attestation `sha3_256(log | nonce)`
    let mut message = Sha3_256::new();
    message.update(log);
    message.update(nonce);
    let message = message.finalize();

    let alias = alias
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(VerifyAttestationError::OddKey)?;
    let alias = VerifyingKey::try_from(alias)
        .map_err(VerifyAttestationError::KeyConversion)?;

    alias
        .verify(message.as_slice(), &signature)
        .map_err(VerifyAttestationError::VerificationFailed)
}

/// Possible errors produced by the measurement verification / appraisal
/// process.
#[derive(Debug, Error)]
pub enum VerifyMeasurementsError {
    #[error("Measurements are not a subset of reference measurements: {0}")]
    NotSubset(MeasurementSet),
}

/// This function implements the core of our attestation appraisal policy.
/// The trustworthiness of the parameters provided must be established
/// independently.
pub fn verify_measurements(
    measurements: &MeasurementSet,
    corpus: &ReferenceMeasurements,
) -> Result<(), VerifyMeasurementsError> {
    // This should be equivallent to measurements.subset(corpus) but
    // give us the entries that are not in the corpus for debugging
    // purposes
    if let Some(diff) = measurements.difference(corpus) {
        Err(VerifyMeasurementsError::NotSubset(diff))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::platform_rot::*;
    use crate::*;

    use std::collections::HashSet;

    const MEASUREMENT_A: [u8; 32] = [0x1; 32];
    const MEASUREMENT_B: [u8; 32] = [0x2; 32];
    const MEASUREMENT_C: [u8; 32] = [0x3; 32];

    #[test]
    fn basic_measurement_set_tests() {
        let measurement_a = Measurement::fake(MEASUREMENT_A);
        let measurement_b = Measurement::fake(MEASUREMENT_B);
        let measurement_c = Measurement::fake(MEASUREMENT_C);

        let mut corpus = HashSet::new();

        corpus.insert(measurement_a);
        corpus.insert(measurement_b);
        corpus.insert(measurement_c);

        let corpus = ReferenceMeasurements(corpus);

        let mut set_a = HashSet::new();
        set_a.insert(measurement_a);
        let set_a = MeasurementSet(set_a);

        assert!(set_a.is_subset(&corpus));

        let mut set_b = HashSet::new();
        set_b.insert(measurement_b);
        let set_b = MeasurementSet(set_b);

        assert!(set_b.is_subset(&corpus));

        let mut set_c = HashSet::new();
        set_c.insert(measurement_c);
        let set_c = MeasurementSet(set_c);

        assert!(verify_measurements(&set_c, &corpus).is_ok());
    }

    #[test]
    fn missing_measurement_set_tests() {
        let measurement_a = Measurement::fake(MEASUREMENT_A);
        let measurement_b = Measurement::fake(MEASUREMENT_B);
        let measurement_c = Measurement::fake(MEASUREMENT_C);

        let mut corpus = HashSet::new();

        corpus.insert(measurement_a);
        corpus.insert(measurement_b);

        let corpus = ReferenceMeasurements(corpus);

        let mut set_c = HashSet::new();
        set_c.insert(measurement_c);
        let set_c = MeasurementSet(set_c);

        let mut other_c = HashSet::new();
        other_c.insert(measurement_c);
        let other_c = MeasurementSet(other_c);

        match verify_measurements(&set_c, &corpus) {
            Ok(()) => panic!("expected an error"),
            Err(e) => match e {
                VerifyMeasurementsError::NotSubset(set) => {
                    assert!(other_c == set)
                }
            },
        }
    }
}

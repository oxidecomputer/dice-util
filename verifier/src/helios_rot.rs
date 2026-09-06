// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use der::{
    self,
    asn1::{BitString, Int, OctetString},
    Sequence,
};
pub use helios_rot::{Attestation, Nonce, Nonce48};
pub use rats_corim::{Corim, Digest};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha2::{
    digest::{
        const_oid::{AssociatedOid, ObjectIdentifier},
        typenum::Unsigned,
        OutputSizeUser,
    },
    Sha384,
};
use std::{collections::HashMap, fmt};
use thiserror::Error;
use x509_cert::{
    der::{Decode, DecodeValue, Header, SliceReader},
    Certificate, PkiPath,
};

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

pub const DICE_TCB_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.1");

// DICE Attestation Architecture §6.1.1:
// FWID ::== SEQUENCE {
#[derive(Debug, Sequence)]
pub struct Fwid {
    // hashAlg OBJECT IDENTIFIER,
    hash_algorithm: ObjectIdentifier,

    // digest OCTET STRING
    digest: OctetString,
}

// DICE Attestation Architecture §6.1.1:
// FWIDLIST ::== SEQUENCE SIZE (1..MAX) OF FWID
#[derive(Debug, Sequence)]
pub struct FwidList {
    fwids: Vec<Fwid>,
}

// NOTE: This structure represents an x509 extension defined by the TCG. This
// particular version is the one used by the AMD DPE that underlies the Helios
// RoT. It comes from an early draft of the TCG spec and is not compatible
// with published versions of the spec.
#[derive(Debug, Sequence)]
pub struct DiceTcbInfo {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    vendor: Option<String>,

    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    model: Option<String>,

    #[asn1(context_specific = "4", tag_mode = "EXPLICIT", optional = "true")]
    layer: Option<Int>,

    #[asn1(context_specific = "5", tag_mode = "EXPLICIT", optional = "true")]
    index: Option<Int>,

    #[asn1(context_specific = "6", tag_mode = "IMPLICIT", optional = "true")]
    fwids: Option<FwidList>,

    #[asn1(context_specific = "7", tag_mode = "EXPLICIT", optional = "true")]
    flags: Option<BitString>,

    #[asn1(context_specific = "9", tag_mode = "EXPLICIT", optional = "true")]
    r#type: Option<OctetString>,
}

#[derive(Debug, Error)]
pub enum ArrayError {
    #[error("Slice is the wrong length")]
    TryFromSliceError(std::array::TryFromSliceError),
}

/// Array is the type we use as a base for types that are constant sized byte
/// buffers.
#[serde_as]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct Array<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl<const N: usize> Array<N> {
    pub const LENGTH: usize = N;
}

impl<const N: usize> fmt::Display for Array<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<const N: usize> Default for Array<N> {
    /// Create and initialize an `Array<N>` to 0's.
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> From<[u8; N]> for Array<N> {
    /// Create an Array from the provided array.
    fn from(item: [u8; N]) -> Self {
        Self(item)
    }
}

impl<const N: usize> TryFrom<&[u8]> for Array<N> {
    type Error = ArrayError;

    /// Attempt to create an `Array<N>` from the slice provided.
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
        let array: [u8; N] =
            item.try_into().map_err(Self::Error::TryFromSliceError)?;
        Ok(Array::<N>(array))
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for Array<N> {
    type Error = ArrayError;

    /// Attempt to create an `Array<N>` from the `Vec<u8>` provided.
    fn try_from(item: Vec<u8>) -> Result<Self, Self::Error> {
        item[..].try_into()
    }
}

impl<const N: usize> AsRef<[u8]> for Array<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

const SHA384_DIGEST_SIZE: usize = <Sha384 as OutputSizeUser>::OutputSize::USIZE;
pub type Sha384Digest = Array<SHA384_DIGEST_SIZE>;

#[derive(Debug, Error)]
pub enum MeasurementError {
    #[error("Deserialization failed")]
    Deserialize,
    #[error("Bad size for measurement: {size}")]
    BadSize { size: usize, source: ArrayError },
    #[error("Fwid provided contains unsupported digest value")]
    UnsupportedDigest,
    #[error("CoRIM Digest contained tagged value")]
    TaggedDigest,
}

/// Measurement is an enum that can hold any of the hash algorithms that we support
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Measurement {
    Sha384(Sha384Digest),
}

impl Default for Measurement {
    fn default() -> Self {
        Measurement::Sha384(Sha384Digest::default())
    }
}

impl fmt::Display for Measurement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Sha384(digest) => {
                write!(f, "sha-384;{digest}")
            }
        }
    }
}

impl TryFrom<&Fwid> for Measurement {
    type Error = MeasurementError;

    /// Attempt to create an `Array<N>` from the slice provided.
    fn try_from(fwid: &Fwid) -> Result<Self, Self::Error> {
        // map from fwid.hash_algorithm ObjectIdentifier to Measurement enum
        if fwid.hash_algorithm == Sha384::OID {
            // pull the associated data from fwid.digest OctetString
            let digest = fwid.digest.as_bytes();
            let digest = Sha384Digest::try_from(digest).map_err(|e| {
                Self::Error::BadSize {
                    size: digest.len(),
                    source: e,
                }
            })?;

            Ok(Measurement::Sha384(digest))
        } else {
            Err(Self::Error::UnsupportedDigest)
        }
    }
}

impl TryFrom<rats_corim::Digest> for Measurement {
    type Error = MeasurementError;

    /// Attempt to create a Measurement from the `rats_corim::Digest` provided.
    fn try_from(digest: rats_corim::Digest) -> Result<Self, Self::Error> {
        match digest.alg {
            7 => {
                let bytes = match &digest.val {
                    rats_corim::TaggedBytes::Bytes(v) => v,
                    rats_corim::TaggedBytes::Tagged(_, _) => {
                        return Err(Self::Error::TaggedDigest)
                    }
                };
                Ok(Measurement::Sha384(bytes[..].try_into().map_err(|e| {
                    MeasurementError::BadSize {
                        size: bytes.len(),
                        source: e,
                    }
                })?))
            }
            _ => Err(Self::Error::UnsupportedDigest),
        }
    }
}

/// This is a collection to represent the measurements received from an
/// attestor. These measurements will come from the measurement log and the
/// DiceTcbInfo extension(s) in the attestation cert chain / pki path.
#[derive(Debug, PartialEq)]
pub struct MeasurementList(Vec<Measurement>);

/// Possible errors produced by the `MeasurmentSet` construction process.
#[derive(Debug, Error)]
pub enum MeasurementListError {
    #[error("failed to create reader from extension value")]
    ExtensionDecode(#[source] der::Error),
    #[error("failed to decode extension header")]
    HeaderDecode(#[source] der::Error),
    #[error("failed to decode TcbInfo extension")]
    DiceTcbInfoDecode(#[source] der::Error),
    #[error("failed to create Measurement from DiceTcbInfo extension")]
    MeasurementConstruct(#[from] MeasurementError),
}

/// Construct a MeasurementList from the provided artifacts. The
/// trustworthiness of these artifacts must be established independently
/// (see `verify_cert_chain` and `verify_attestation`).
impl MeasurementList {
    /// Construct a MeasurementList from the provided artifacts. The
    /// trustworthiness of these artifacts must be established independently
    /// (see `verify_cert_chain` and `verify_attestation`).
    pub fn from_artifacts(
        pki_path: &PkiPath,
    ) -> Result<Self, MeasurementListError> {
        let mut measurements = Vec::new();

        for cert in pki_path {
            if let Some(extensions) = &cert.tbs_certificate.extensions {
                for ext in extensions {
                    if ext.extn_id == DICE_TCB_INFO {
                        let mut reader =
                            SliceReader::new(ext.extn_value.as_bytes())
                                .map_err(
                                    MeasurementListError::ExtensionDecode,
                                )?;
                        let header = Header::decode(&mut reader)
                            .map_err(MeasurementListError::HeaderDecode)?;

                        let tcb_info =
                            DiceTcbInfo::decode_value(&mut reader, header)
                                .map_err(
                                    MeasurementListError::DiceTcbInfoDecode,
                                )?;
                        if let Some(fwid_vec) = &tcb_info.fwids {
                            for fwid in &fwid_vec.fwids {
                                let measurement = Measurement::try_from(fwid)?;
                                measurements.push(measurement);
                            }
                        }
                    }
                }
            }
        }

        Ok(Self(measurements))
    }
}

impl<'a> std::iter::IntoIterator for &'a MeasurementList {
    type Item = &'a Measurement;
    type IntoIter = std::slice::Iter<'a, Measurement>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl std::fmt::Display for MeasurementList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "measurement list")?;
        for m in &self.0 {
            writeln!(f, " {}", m)?;
        }
        if self.0.is_empty() {
            writeln!(f, "(set is empty)")?;
        }
        Ok(())
    }
}

// collection that maps a `Measurement` to the CoRIM `mkey` / string
// identifier assigned to this digest
pub struct ReferenceMeasurementMap(HashMap<Measurement, String>);

#[derive(Debug, Error)]
pub enum ReferenceMeasurementMapError {
    #[error("Digest is not the expected length")]
    BadDigest(#[from] MeasurementError),
    #[error("No such measurement found in ReferenceMeasurementMap: {0}")]
    NotFound(Measurement),
    #[error("CoRIM measurement map has no values")]
    NoDigest,
    // we currently assume that there is a 1:1 correspondence between each
    // measurement key and value
    #[error("CoRIM measurement map has multiple digests")]
    MultipleDigests,
    #[error("CoRIM measurement map mkey is not Text")]
    KeyNotText,
    #[error("CoRIM measurement map has no mkey")]
    NoKey,
}

impl TryFrom<&[Corim]> for ReferenceMeasurementMap {
    type Error = ReferenceMeasurementMapError;

    fn try_from(corims: &[Corim]) -> Result<Self, Self::Error> {
        use rats_corim::TypeChoice;

        let mut set = HashMap::new();

        // iterate such that we get the label (whatever it's called in CoRIM
        // speak)
        for corim in corims {
            let comid = corim.tags.wrapped.clone().into_iter();
            let reference_triple =
                comid.flat_map(|x| x.triples.reference_triple.into_iter());
            let reference_triple =
                reference_triple.flat_map(|x| x.wrapped.into_iter());
            let measurement_maps =
                reference_triple.flat_map(|x| x.ref_claims.into_iter());

            for measurement_map in measurement_maps {
                let measurement_key = measurement_map.mkey;
                let mkey = if let Some(t) = measurement_key {
                    match t {
                        TypeChoice::Text(s) => s,
                        _ => return Err(Self::Error::KeyNotText),
                    }
                } else {
                    return Err(Self::Error::NoKey);
                };

                let measurement_values = measurement_map.mval;
                if let Some(d) = measurement_values.digests {
                    let digests: Vec<rats_corim::Digest> = d
                        .into_iter()
                        .flat_map(|x| x.wrapped.into_iter())
                        .collect();
                    if digests.is_empty() {
                        return Err(Self::Error::NoDigest);
                    } else if digests.len() > 1 {
                        return Err(Self::Error::MultipleDigests);
                    }
                    for digest in digests {
                        set.insert(digest.try_into()?, mkey.clone());
                    }
                } else {
                    return Err(Self::Error::NoDigest);
                };
            }
        }

        Ok(Self(set))
    }
}

impl std::fmt::Display for ReferenceMeasurementMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Reference measurements")?;
        for (key, val) in &self.0 {
            writeln!(f, " label: {val}, measurement: {key}")?;
        }
        if self.0.is_empty() {
            writeln!(f, "(ReferenceMeasurementMap is empty)")?;
        }
        Ok(())
    }
}

impl ReferenceMeasurementMap {
    pub fn get_id(&self, m: &Measurement) -> Option<String> {
        //TODO: do this w/o all of the clones
        self.0.get(m).cloned()
    }
}

/// Possible errors produced by the measurement verification / appraisal
/// process.
#[derive(Debug, Error)]
pub enum VerifyMeasurementsError {
    #[error("Measurements are not a subset of reference measurements: {0}")]
    NotSubset(MeasurementList),
    #[error("Policy not satisfied")]
    PolicyNotSatisfied,
}

// This is the FnPolicy that most closely matches what we expect to enforce
// initially. This policy is effectively:
// the measurements from the leaf and last intermediate (the first and second
// measurement in the MeasurementList) must correspond to reference
// measurements with the mkeys "phase2" & "hbs" respectively
#[cfg(feature = "unittest")]
fn test_policy(
    measurements: &MeasurementList,
    corpus: &ReferenceMeasurementMap,
) -> bool {
    let mut labeled_measurements = Vec::new();

    // for each measurement in the MeasurementList
    for (i, m) in measurements.into_iter().enumerate() {
        // if it's in the corpus, we:
        // - get the mkey string
        if let Some(l) = corpus.get_id(m) {
            // store the mkey & index of the measurement in the MeasurementList
            labeled_measurements.push((l, i));
        }
    }

    // The list of (mkey, index) tuples that we require the attested
    // measurements to match.
    let required_measurements =
        vec![("phase2".to_string(), 0), ("hbs".to_string(), 1)];

    if labeled_measurements == required_measurements {
        true
    } else {
        false
    }
}

// our default `FnPolicy` that will always fail till we have mkeys tracked in
// OANA: https://github.com/oxidecomputer/oana/issues/44
fn fail_policy(
    _measurements: &MeasurementList,
    _corpus: &ReferenceMeasurementMap,
) -> bool {
    false
}

// our measurement appraisal policy is a function with this signature
type FnPolicy = fn(&MeasurementList, &ReferenceMeasurementMap) -> bool;

#[cfg(feature = "unittest")]
const POLICY: FnPolicy = test_policy;
#[cfg(not(feature = "unittest"))]
const POLICY: FnPolicy = fail_policy;

/// This function implements the core of our attestation appraisal policy.
/// The trustworthiness of the parameters provided must be established
/// independently.
pub fn verify_measurements(
    measurements: &MeasurementList,
    corpus: &ReferenceMeasurementMap,
) -> Result<(), VerifyMeasurementsError> {
    if POLICY(measurements, corpus) {
        Ok(())
    } else {
        Err(VerifyMeasurementsError::PolicyNotSatisfied)
    }
}

#[cfg(test)]
mod test {
    use crate::helios_rot::{
        self, MeasurementList, Nonce, ReferenceMeasurementMap,
    };
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
    #[tokio::test]
    async fn verify_attestation() {
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());

        let cert_chain = out.join("helios-rot.certlist.pem");
        let alias_key = out.join("dpe-tcb-0-20b87885cc8c321f.key.pem");

        let rot_mock = HeliosRotMock::load(&cert_chain, &alias_key)
            .expect("Construct HeliosRotMock from files");

        let nonce =
            Nonce::from_platform_rng(48).expect("Nonce from platform RNG");

        let attestation = rot_mock
            .attest(&nonce)
            .await
            .expect("Attestation from HeliosRotMock");

        let alias_cert = out.join("dpe-tcb-0-20b87885cc8c321f.cert.pem");
        let alias_cert = get_cert_from_file(&alias_cert);

        let res =
            helios_rot::verify_attestation(&alias_cert, &attestation, &nonce);

        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn verify_attestation_bad_nonce() {
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
            .await
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

    #[test]
    fn appraise_measurements() {
        use rats_corim::Corim;
        use std::{fs, slice};

        // load alias cert chain
        let out = PathBuf::from(env::var("OUT_DIR").unwrap());

        let cert_chain = out.join("helios-rot.certlist.pem");
        let cert_chain = fs::read_to_string(&cert_chain)
            .expect("read cert chain pem from file");
        let cert_chain = Certificate::load_pem_chain(cert_chain.as_ref())
            .expect("certificate chain from pem");

        // create `MeasurementList` from cert chain
        let measurements = MeasurementList::from_artifacts(&cert_chain)
            .expect("measurement set from cert chain");
        println!("MeasurementList: {measurements}");

        // load the corims
        let corim = out.join("test-corim.cbor");
        let corim = Corim::from_file(&corim).expect("load corim from file");

        // create `ReferenceMeasurementMap
        let reference_measurements =
            ReferenceMeasurementMap::try_from(slice::from_ref(&corim))
                .expect("ReferenceMeasurementMap from CoRIMs");
        println!("ReferenceMeasurementMap: {reference_measurements}");

        helios_rot::verify_measurements(&measurements, &reference_measurements)
            .expect("Verify measurement set against reference measurements");
    }
}

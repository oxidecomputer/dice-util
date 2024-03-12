// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use clap::{Parser, ValueEnum};
use clap_verbosity_flag::{Verbosity, WarnLevel};
use const_oid::{
    db::{
        rfc4519,
        rfc5912::{ECDSA_WITH_SHA_384, ID_EC_PUBLIC_KEY, SECP_384_R_1},
        rfc8410::ID_ED_25519,
    },
    AssociatedOid,
};
use ed25519_dalek::{
    Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use env_logger::Builder;
use flagset::FlagSet;
use getrandom::getrandom;
use log::{debug, info, warn};
use p384::ecdsa::{
    signature::{SignatureEncoding, Signer},
    SigningKey,
};
use pkcs8::{
    DecodePrivateKey, // the p384 crate is using this trait but not reexporting it?
    LineEnding,
};
use sha1::{Digest, Sha1};
use std::{
    fmt::Debug,
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    str::{self, FromStr},
    time::SystemTime,
};
use x509_cert::{
    certificate,
    der::{
        asn1::{BitString, GeneralizedTime, OctetString, UtcTime},
        DateTime, Decode, DecodePem, Encode, EncodePem, Tag, Tagged,
    },
    ext::{
        pkix::{
            certpolicy::PolicyInformation, AuthorityKeyIdentifier,
            BasicConstraints, CertificatePolicies, KeyUsage,
            SubjectKeyIdentifier,
        },
        Extension,
    },
    request::{self, CertReq},
    serial_number::SerialNumber,
    spki::{
        AlgorithmIdentifierOwned, ObjectIdentifier, SubjectPublicKeyInfoOwned,
    },
    time::Validity,
    Certificate, TbsCertificate,
};

#[derive(Clone, Debug, ValueEnum)]
enum Hash {
    Sha384,
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// verbosity
    #[command(flatten)]
    verbose: Verbosity<WarnLevel>,

    /// Certificate signing request
    #[clap(long, env)]
    csr: Option<PathBuf>,

    /// Hash function
    #[clap(value_enum, long, env)]
    hash: Option<Hash>,

    /// Output file for generated certificate
    #[clap(long, env)]
    out: Option<PathBuf>,

    /// Path to file holding the certificate chain / PkiPath from issuer cert
    /// to the first intermediate before the root.
    #[clap(env)]
    issuer_cert_chain: PathBuf,

    /// Signing key in PEM encoded PKCS#8
    #[clap(env)]
    issuer_key: PathBuf,

    /// Path to file holding the CA root certificate / trust anchor
    #[clap(env)]
    ca_cert: Option<PathBuf>,
}

/// The expected value of the RFC 4519 `c` / X.520 `countryName`.
const COUNTRY: &str = "US";

/// The expected value of the RFC 4519 `o` / X.520 `organizationName`.
const ORGANIZATION: &str = "Oxide Computer Company";

/// Check the signature over the provided CSR. This requires:
/// - checking that the public key / signing algorithm are supported
/// - extract the public key & the signature
/// - verify the signature
fn check_signature(csr: &CertReq) -> Result<()> {
    let spki = &csr.info.public_key;
    if spki.algorithm.oid != ID_ED_25519 {
        return Err(anyhow!(
            "wrong algorithm OID from CSR SPKI: {}",
            spki.algorithm.oid
        ));
    }
    let verifying_key: [u8; PUBLIC_KEY_LENGTH] = spki
        .subject_public_key
        .as_bytes()
        .context("Failed to get public key as bytes")?
        .try_into()
        .context("Failed to convert public key from CSR to sized array")?;
    // CSRs from an RoT will always contain ed25519 public keys & be signed by
    // the corresponding private key.
    let verifying_key = VerifyingKey::from_bytes(&verifying_key)?;

    let signature: [u8; SIGNATURE_LENGTH] = csr
        .signature
        .as_bytes()
        .context("Failed to get signature as bytes")?
        .try_into()
        .context("Failed to convert signatyre from CSR to sized array")?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature);

    let req_info = csr.info.to_der()?;
    // verify signature
    verifying_key
        .verify(&req_info, &signature)
        .context("Failed to verify signature over CSR")
}

/// Verify that the subject field from the provided CSR has the required form.
fn check_subject(csr: &CertReq) -> Result<()> {
    for rdn in csr.info.subject.0.iter() {
        // We typcially think of each `RelativeDistinguishedName` in the
        // `RdnSequence` as the tuple `(attribute, value)` when they're
        // actually a sequence of this tuple. In our use case this sequence
        // is always a sequence of 1.
        if rdn.0.len() != 1 {
            return Err(anyhow!("RDN has more than one (attribute, value)"));
        }

        let atv = &rdn.0.as_slice()[0];
        match atv.oid {
            rfc4519::COUNTRY_NAME => {
                // 2.5.4.6 is defined as a `PrintableString` which is a
                // subset of utf8
                let tag = atv.value.tag();
                if tag != Tag::PrintableString {
                    return Err(anyhow!(
                        "Subject has invalid tag for `Country`: {}",
                        tag
                    ));
                }
                let country = str::from_utf8(atv.value.value()).context(
                    "Failed to decode `Country` value as UTF8 string",
                )?;
                if country != COUNTRY {
                    return Err(anyhow!(format!(
                        "Subject contains invalid `country`: {}",
                        country
                    )));
                }
            }
            rfc4519::ORGANIZATION_NAME => {
                // 2.5.4.10 is defined as a `UTF8String`
                let tag = atv.value.tag();
                if tag != Tag::Utf8String {
                    return Err(anyhow!(
                        "Subject has invalid tag for `Organization`: {}",
                        tag
                    ));
                }
                let org = str::from_utf8(atv.value.value()).context(
                    "Failed to decode `Organization` value as UTF8 string",
                )?;
                if org != ORGANIZATION {
                    return Err(anyhow!(format!(
                        "Subject contains invalid `organization`: {}",
                        org
                    )));
                }
            }
            rfc4519::COMMON_NAME => {
                // 2.5.4.3 is defined as a `UTF8String`
                let tag = atv.value.tag();
                if tag != Tag::Utf8String {
                    return Err(anyhow!(
                        "Subject has invalid tag for `CommonName`: {}",
                        tag
                    ));
                }
                let cn = str::from_utf8(atv.value.value()).context(
                    "Failed to decode `CommonName` value as UTF8 string",
                )?;
                dice_mfg_msgs::validate_pdv2(cn).with_context(|| {
                    format!(
                        "Subject `CommonName` is not valid PDV2 string: {}",
                        cn
                    )
                })?;
            }
            _ => return Err(anyhow!("Unexpected oid in RDN")),
        }
    }

    Ok(())
}

/// Verify that the provided CSR meets the requirements defined for platform
/// identity certification.
fn check_csr(csr: &CertReq) -> Result<()> {
    check_signature(csr)?;
    // version field must be 1: only a single version number is valid so I
    // think the CSR will fail to parse if the version isn't 1 ... but we
    // check anyway
    if csr.info.version != request::Version::V1 {
        return Err(anyhow!("CSR version is not 1"));
    };

    check_subject(csr)?;

    // Alternatively we could evaluate the attributes for validity & copy them
    // like we do the subject. This is what a "normal" CA would do but since
    // we only care about creating one type of cert we can keep things simple.
    let len = csr.info.attributes.len();
    if len != 0 {
        return Err(anyhow!("Expected CSR to have no extensions, got {}", len));
    }

    Ok(())
}

/// Build an appropriately populated `AlgorithmIdentifierOwned` suitable for
/// use in the `signature` field of a `Certificate` signed by the key
/// certified in `issuer_cert` using the provided `hash`.
fn get_sig_alg(
    issuer_cert: &Certificate,
    hash: Option<Hash>,
) -> Result<AlgorithmIdentifierOwned> {
    let issuer_key_type = &issuer_cert
        .tbs_certificate
        .subject_public_key_info
        .algorithm;
    match &issuer_key_type.oid {
        &ID_EC_PUBLIC_KEY => match &issuer_key_type.parameters {
            Some(p) => {
                if p.tag() != Tag::ObjectIdentifier {
                    return Err(anyhow!(
                        "unexpected tag for ID_EC_PUBLIC_KEY: {:?}",
                        p.tag()
                    ));
                }

                let oid: ObjectIdentifier = p.decode_as()?;
                if oid != SECP_384_R_1 {
                    return Err(anyhow!(
                        "unsupported params for ID_EC_PUBLIC_KEY: {:?}",
                        oid
                    ));
                }

                match hash {
                    // return AlgorithmIdentifier `ecdsa-with-SHA384`
                    Some(Hash::Sha384) => Ok(AlgorithmIdentifierOwned {
                        oid: ECDSA_WITH_SHA_384,
                        parameters: None,
                    }),
                    _ => Err(anyhow!(
                        "ECC keys require a hash \
                            function for signing but non provided, see \
                            `--help`"
                    )),
                }
            }
            None => Err(anyhow!("ID_EC_PUBLIC_KEY missing required params")),
        },
        _ => {
            todo!("unsupported signing key: {:?}", issuer_key_type);
        }
    }
}

/// Generate OctetString holding the sha1 hash of the provided public key.
/// This is suitable for use as the
fn keyid_from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<OctetString> {
    let csr_pub = &spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| anyhow!("SPKI has invalid / unaligned public key"))?;

    let mut hasher = Sha1::new();
    hasher.update(csr_pub);
    let skid = hasher.finalize();

    // &*skid is some magic to convert a GenericArray<u8, blah ...> to a
    // Vec<u8> even though .into / .try_into can't
    Ok(OctetString::new(&*skid)?)
}

/// Generate platform identity certificate from the provided data.
fn tbs_cert_from_csr(
    csr: &CertReq,
    issuer_cert: &Certificate,
    sig_alg: &AlgorithmIdentifierOwned,
) -> Result<TbsCertificate> {
    // TbsCertificate fields:

    // signature: AlgorithmIdentifier appropriate for the signing key. We get
    // this from the caller

    // version: 0x3
    let version = certificate::Version::V3;

    // serial number: random value, ensure uniqueness eventually
    let mut serial_number = [0u8; 20];
    getrandom(&mut serial_number)?;

    // ensure leading bit in value is clear to get 20 byte encoded value
    // see: https://rfd.shared.oxide.computer/rfd/0387#_tbscertificate
    serial_number[0] &= 0b0111_1111;
    let serial_number = SerialNumber::new(&serial_number)?;
    debug!("serial_number: {:#?}", serial_number);

    // issuer: get from cert for signing key
    let issuer = &issuer_cert.tbs_certificate.subject;
    debug!("issuer: {:#?}", issuer);

    // validity
    // - notBefore: current system time
    // - notAfter: 9999-12-31T23:59:59Z
    let not_before = DateTime::from_system_time(SystemTime::now())?;
    let not_before = if not_before.year() >= 2050 {
        GeneralizedTime::from(not_before).into()
    } else {
        UtcTime::try_from(not_before)?.into()
    };
    let not_after = DateTime::from_str("9999-12-31T23:59:59Z")?;
    let not_after = GeneralizedTime::from(not_after).into();
    let validity = Validity {
        not_before,
        not_after,
    };
    debug!("validity: {:#?}", validity);

    // subject: copy from csr.info.subject
    let subject = &csr.info.subject;
    debug!("subject: {:#}", subject);

    // subject_public_key_info (aka spki): copy from csr.info.public_key
    let spki = &csr.info.public_key;
    debug!("subject_public_key_info: {:#?}", spki);

    // extensions
    let mut extensions = Vec::new();

    // authority_key_identifier: Copy OctetString from subject key identifier
    // from issuer cert.
    let mut issuer_keyid = None;
    if let Some(exts) = &issuer_cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == x509_cert::ext::pkix::SubjectKeyIdentifier::OID {
                // The extension value / extn_val is the OctetString that
                // contains the DER encoded SubjectKeyIdentifier structure.
                // We need to pull out the 20 byte hash from
                let keyid = ext.extn_value.as_bytes();
                let keyid = SubjectKeyIdentifier::from_der(keyid).context(
                    "failed to parse SubjectKeyIdentifier from DER in extension"
                )?;
                issuer_keyid = Some(keyid.0)
            }
        }
    }
    let issuer_keyid = issuer_keyid
        .context("Issuer cert is missing Authority Key Identifier extension")?;
    warn!("keyid from parent: {:#0x?}", issuer_keyid);

    let aki_from_pub = x509_cert::ext::pkix::AuthorityKeyIdentifier {
        key_identifier: Some(issuer_keyid),
        authority_cert_issuer: None,
        authority_cert_serial_number: None,
    }
    .to_der()
    .context("failed to encode AuthorityKeyIdentifier as DER")?;

    let aik_from_pub = OctetString::new(aki_from_pub).context(
        "failed to create OctetString from AuthorityKeyIdentifier DER",
    )?;

    extensions.push(Extension {
        extn_id: AuthorityKeyIdentifier::OID,
        critical: false,
        extn_value: aik_from_pub,
    });

    // subject_key_identifier = sha1(csr.info.public_key.subject_public_key)
    let key_id = keyid_from_spki(&csr.info.public_key)?;
    warn!("ski: {:#0x?}", key_id);
    let extn_value = x509_cert::ext::pkix::SubjectKeyIdentifier(key_id)
        .to_der()
        .context("failed to encode SubjectKeyIdentifier as DER")?;
    let extn_value = OctetString::new(extn_value)
        .context("Failed to create OctetString from SubjectKeyIdentifier")?;
    let ext = Extension {
        extn_id: SubjectKeyIdentifier::OID,
        critical: false,
        extn_value,
    };
    warn!("ski extension: {:#0x?}", ext);
    extensions.push(ext);

    // basic constraints
    let basic_constraints = BasicConstraints {
        ca: true,
        path_len_constraint: None,
    };
    let ext = Extension {
        extn_id: BasicConstraints::OID,
        critical: true,
        extn_value: OctetString::new(basic_constraints.to_der()?)?,
    };
    debug!("basic_constraints: {:#?}", ext);
    extensions.push(ext);

    // key usage
    let mut key_usage_flags = FlagSet::default();
    key_usage_flags |= x509_cert::ext::pkix::KeyUsages::KeyCertSign;
    key_usage_flags |= x509_cert::ext::pkix::KeyUsages::CRLSign;
    let der = KeyUsage(key_usage_flags)
        .to_der()
        .context("Failed to convert KeyUsage to der")?;
    let ext = Extension {
        extn_id: KeyUsage::OID,
        critical: true,
        extn_value: OctetString::new(der)?,
    };
    debug!("key_usage: {:#?}", ext);
    extensions.push(ext);

    // policy
    let mut policies = Vec::new();

    // OANA Platform Identity policy
    let policy_info = PolicyInformation {
        policy_identifier: ObjectIdentifier::new("1.3.6.1.4.1.57551.1.3")?,
        policy_qualifiers: None,
    };
    policies.push(policy_info);

    // TCG / DICE initial identity
    let policy_info = PolicyInformation {
        policy_identifier: ObjectIdentifier::new("2.23.133.5.4.100.6")?,
        policy_qualifiers: None,
    };
    policies.push(policy_info);

    // TCG / DICE initial attestation
    let policy_info = PolicyInformation {
        policy_identifier: ObjectIdentifier::new("2.23.133.5.4.100.8")?,
        policy_qualifiers: None,
    };
    policies.push(policy_info);

    // TCG /DICE embeded certificate authority
    let policy_info = PolicyInformation {
        policy_identifier: ObjectIdentifier::new("2.23.133.5.4.100.12")?,
        policy_qualifiers: None,
    };
    policies.push(policy_info);

    let der = CertificatePolicies(policies)
        .to_der()
        .context("Failed to convert CertificatePolicies to DER")?;
    let ext = Extension {
        extn_id: CertificatePolicies::OID,
        critical: true,
        extn_value: OctetString::new(der)?,
    };
    debug!("certificate_policies: {:#?}", ext);
    extensions.push(ext);

    Ok(TbsCertificate {
        version,
        serial_number,
        signature: sig_alg.clone(),
        issuer: issuer.clone(),
        validity,
        subject: subject.clone(),
        subject_public_key_info: spki.clone(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    })
}

/// Perform a series of checks on the certificate associated with the issuer's
/// signing key. Failed checks result in errors.
fn check_issuer_cert(cert: &Certificate) -> Result<()> {
    // if cert.tbs_certificate.extensions contains the `SubjectKeyIdentifier`
    // OID check that the value is the sha1 digest of the public key. If
    // these values disagree
    // X509v3 Authority Key Identifier:
    //     70:D7:A7:C5:2B:17:1C:0C:82:9F:E7:DC:04:05:3A:2D:F7:36:4E:94
    //
    // cert 'authority_key_identifier' = subject key identifier from cert for signing key
    // get the Authority Key Identifier / 2.5.29.35 from the cert for the
    // signing key
    let mut ski = None;
    if let Some(exts) = &cert.tbs_certificate.extensions {
        for ext in exts {
            if ext.extn_id == x509_cert::ext::pkix::SubjectKeyIdentifier::OID {
                // The extension value / extn_val is the OctetString that
                // contains the DER encoded SubjectKeyIdentifier structure.
                let val = ext.extn_value.as_bytes();
                let id = SubjectKeyIdentifier::from_der(val).context(
                    "failed to parse SubjectKeyIdentifier from DER in \
                        extension",
                )?;
                ski = Some(id.0);
            }
        }
    }
    let ski = ski.context(
        "issuer certificate does not have a SubjectKeyIdentifier extension",
    )?;
    debug!("subject_key_identifier: {:#?}", ski);

    let aki = keyid_from_spki(&cert.tbs_certificate.subject_public_key_info)?;

    if ski == aki {
        Ok(())
    } else {
        Err(anyhow!(
            "SubjectKeyIdentifier from issuer cert doesn't match \
            sha1 digest of public key from same"
        ))
    }
}

fn csr_from_arg<P: AsRef<Path>>(csr: Option<P>) -> Result<CertReq> {
    let mut reader: Box<dyn Read> = match csr {
        Some(p) => Box::new(File::open(&p)?),
        None => Box::new(io::stdin()),
    };

    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf)?;
    let buf = buf;

    Ok(CertReq::from_pem(buf)?)
}

/// A very procedural way to turn a very specific CSR into a very specific
/// Cert.
fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();
    builder.filter_level(args.verbose.log_level_filter()).init();

    // load CSR and check it
    let csr = csr_from_arg(args.csr.as_ref())
        .context(format!("Failed to parse CSR from path: {:?}", args.csr))?;
    info!("csr: {:#0x?}", csr);
    check_csr(&csr)?;

    // load issuer cert chain & check it
    let issuer_cert_chain =
        fs::read(&args.issuer_cert_chain).context(format!(
            "Failed to read PkiPath from file: {}",
            args.issuer_cert_chain.display()
        ))?;
    let issuer_cert_chain = Certificate::load_pem_chain(&issuer_cert_chain)
        .context(format!(
            "Failed to decode cert from PEM read from file {}",
            args.issuer_cert_chain.display()
        ))?;
    warn!("issuer_cert: {:#0x?}", issuer_cert_chain);
    check_issuer_cert(&issuer_cert_chain[0])?;

    let sig_alg = get_sig_alg(&issuer_cert_chain[0], args.hash)?;
    info!("sig_alg: {:#0x?}", sig_alg);

    // generate platform identity cert body from CSR
    let tbs_certificate =
        tbs_cert_from_csr(&csr, &issuer_cert_chain[0], &sig_alg)?;
    warn!("tbs_certificate: {:#0x?}", tbs_certificate);

    // TODO: Persist certificate subject & serial number which must be unique
    // across all certs generated.

    // generate signature over DER encoded cert body

    // TODO: Add support for signing keys on YubiHSM. Pulling keys from files
    // on disk is only suitable for testing.
    let pem = fs::read_to_string(&args.issuer_key).context(format!(
        "Failed to read file: {}",
        args.issuer_key.display()
    ))?;

    // TODO: p384 signing keys are what we're currently using. We'll need
    // to support ed25519 eventually.
    let signing_key = SigningKey::from_pkcs8_pem(&pem).context(format!(
        "failed to create p384 signing key from pem: {}",
        args.issuer_key.display()
    ))?;
    info!("signing_key: {:#0x?}", &signing_key);

    let der = tbs_certificate
        .to_der()
        .context("failed to encode generated TbsCertificate to DER")?;
    let signature: p384::ecdsa::Signature = signing_key.sign(&der);
    let signature = BitString::from_bytes(&signature.to_der().to_vec())
        .context("failed to make BitString from signature")?;

    // create final certificate structure
    let cert = Certificate {
        tbs_certificate,
        signature_algorithm: sig_alg,
        signature,
    };
    info!("generated Cert: {:#0x?}", &cert);

    let pem = cert
        .to_pem(LineEnding::CRLF)
        .context("failed to encode generated certificate as PEM")?;

    // write to stdout if args.out file not provided
    let mut writer: Box<dyn Write> = match args.out {
        Some(o) => {
            // truncate existing files
            let file = File::create_new(&o)
                .context(format!("Failed to create file: {}", o.display()))?;
            Box::new(file)
        }
        None => Box::new(io::stdout()),
    };

    writer
        .write_all(pem.as_bytes())
        .context("failed to write certificate")?;

    Ok(())
}

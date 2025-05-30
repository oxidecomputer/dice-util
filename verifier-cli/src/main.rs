// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use attest_data::{Attestation, Log, Nonce};
use clap::{Parser, Subcommand, ValueEnum};
use dice_mfg_msgs::PlatformId;
#[cfg(feature = "ipcc")]
use dice_verifier::ipcc::AttestIpcc;
use dice_verifier::{
    hiffy::{AttestHiffy, AttestTask},
    Attest, MeasurementSet, ReferenceMeasurements,
};
use env_logger::Builder;
use log::{info, warn, LevelFilter};
use pem_rfc7468::LineEnding;
use rats_corim::Corim;
use std::{
    fmt::{self, Debug},
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};
use x509_cert::{
    der::{DecodePem, EncodePem},
    Certificate, PkiPath,
};

fn get_attest(interface: Interface) -> Result<Box<dyn Attest>> {
    match interface {
        #[cfg(feature = "ipcc")]
        Interface::Ipcc => Ok(Box::new(AttestIpcc::new()?)),
        Interface::Rot => Ok(Box::new(AttestHiffy::new(AttestTask::Rot))),
        Interface::Sprot => Ok(Box::new(AttestHiffy::new(AttestTask::Sprot))),
    }
}

/// Execute HIF operations exposed by the RoT Attest task.
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Interface used for communication with the Attest task.
    #[clap(value_enum, long, env, default_value_t = Interface::Rot)]
    interface: Interface,

    /// Attest task command to execute.
    #[command(subcommand)]
    command: AttestCommand,

    /// verbosity
    #[clap(long, env)]
    verbose: bool,
}

/// An enum of the HIF operations supported by the `Attest` interface.
#[derive(Debug, Subcommand)]
enum AttestCommand {
    /// Get an attestation, this is a signature over the serialized measurement log and the
    /// provided nonce: `sha3_256(log | nonce)`.
    Attest {
        /// Path to file holding the nonce
        #[clap(env)]
        nonce: PathBuf,
    },
    /// Get the full cert chain from the RoT encoded per RFC 6066 (PKI path)
    CertChain,
    /// Get the log of measurements recorded by the RoT.
    Log,
    /// Get the PlatformId string from the provided PkiPath
    PlatformId {
        /// Path to file holding the certificate chain / PkiPath
        #[clap(env)]
        cert_chain: PathBuf,
    },
    Verify {
        /// Path to file holding trust anchor for the associated PKI.
        #[clap(
            long,
            env = "VERIFIER_CLI_CA_CERT",
            conflicts_with = "self_signed"
        )]
        ca_cert: Option<PathBuf>,

        /// Verify the final cert in the provided PkiPath against itself.
        #[clap(long, env, conflicts_with = "ca_cert")]
        self_signed: bool,

        /// Caller provided directory where artifacts are stored. If this
        /// option is provided it will be used by this tool to store
        /// artifacts retrieved from the RoT as part of the attestation
        /// process. If omitted a temp directory will be used instead.
        #[clap(long, env = "VERIFIER_CLI_WORK_DIR")]
        work_dir: Option<PathBuf>,

        /// Path to file holding the reference measurement corpus
        #[clap(env, env = "VERIFIER_CLI_CORPUS")]
        corpus: PathBuf,
    },
    /// Verify signature over Attestation
    VerifyAttestation {
        /// Path to file holding the alias cert
        #[clap(long, env)]
        alias_cert: PathBuf,

        /// Path to file holding the attestation
        #[clap(env)]
        attestation: PathBuf,

        /// Path to file holding the log
        #[clap(long, env)]
        log: PathBuf,

        /// Path to file holding the nonce
        #[clap(long, env)]
        nonce: PathBuf,
    },
    /// Walk the PkiPath formatted certificate chain verifying each link.
    VerifyCertChain {
        /// Path to file holding trust anchor for the associated PKI.
        #[clap(long, env, conflicts_with = "self_signed")]
        ca_cert: Option<PathBuf>,

        /// Verify the final cert in the provided PkiPath against itself.
        #[clap(long, env, conflicts_with = "ca_cert")]
        self_signed: bool,

        /// Path to file holding the certificate chain / PkiPath.
        #[clap(env)]
        cert_chain: PathBuf,
    },
    /// Verify the measurements from the log and cert chain against the
    /// provided measurement corpus.
    VerifyMeasurements {
        /// Path to file holding the certificate chain / PkiPath.
        #[clap(env)]
        cert_chain: PathBuf,

        /// Path to file holding the log
        #[clap(env)]
        log: PathBuf,

        /// Path to file holding the reference measurement corpus
        #[clap(env)]
        corpus: PathBuf,
    },
}

/// An enum of the possible routes to the `Attest` task.
#[derive(Clone, Debug, ValueEnum)]
pub enum Interface {
    #[cfg(feature = "ipcc")]
    Ipcc,
    Rot,
    Sprot,
}

/// An enum of the possible certificate encodings.
#[derive(Clone, Debug, ValueEnum)]
enum Encoding {
    Der,
    Pem,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Encoding::Der => write!(f, "der"),
            Encoding::Pem => write!(f, "pem"),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Warn
    };
    builder.filter(None, level).init();

    let attest = get_attest(args.interface)?;

    match args.command {
        AttestCommand::Attest { nonce } => {
            let nonce = fs::read(&nonce)
                .context(format!("Nonce bytes from: {}", nonce.display()))?;
            let nonce =
                Nonce::try_from(nonce).context("Nonce from file contents")?;
            let attestation = attest
                .attest(&nonce)
                .context("Getting attestation with provided Nonce")?;

            // serialize attestation to json & write to file
            let mut attestation = serde_json::to_string(&attestation)
                .context("Attestation to JSON")?;
            attestation.push('\n');

            io::stdout()
                .write_all(attestation.as_bytes())
                .context("Write Attestation as JSON to stdout")?;
            io::stdout().flush().context("Flush stdout")?;
        }
        AttestCommand::CertChain => {
            let cert_chain = attest
                .get_certificates()
                .context("Getting attestation certificate chain")?;
            for cert in cert_chain {
                let cert = cert
                    .to_pem(LineEnding::default())
                    .context("Encode certificate as PEM")?;

                io::stdout()
                    .write_all(cert.as_bytes())
                    .context("Write cert chain to stdout")?;
            }
            io::stdout().flush().context("Flush stdout")?;
        }
        AttestCommand::Log => {
            let log = attest
                .get_measurement_log()
                .context("Getting attestation measurement log")?;
            let mut log = serde_json::to_string(&log)
                .context("Encode measurement log as JSON")?;
            log.push('\n');

            io::stdout()
                .write_all(log.as_bytes())
                .context("Write measurement log to stdout")?;
            io::stdout().flush().context("Flush stdout")?;
        }
        AttestCommand::PlatformId { cert_chain } => {
            let cert_chain = fs::read(&cert_chain).context(format!(
                "Read attestation certificate chain bytes from file: {}",
                cert_chain.display()
            ))?;
            let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)
                .context("Parse certificate chain")?;

            let platform_id = PlatformId::try_from(&cert_chain)
                .context("PlatformId from attestation cert chain")?;
            let platform_id = platform_id
                .as_str()
                .map_err(|_| anyhow!("Invalid PlatformId"))?;

            println!("{platform_id}");
        }
        AttestCommand::Verify {
            ca_cert,
            corpus,
            self_signed,
            work_dir,
        } => {
            // Use the directory provided by the caller to hold intermediate
            // files, or fall back to a temp dir.
            let platform_id = match work_dir {
                Some(w) => verify(
                    attest.as_ref(),
                    ca_cert.as_deref(),
                    &corpus,
                    self_signed,
                    &w,
                )?,
                None => {
                    let work_dir = tempfile::tempdir()?;
                    verify(
                        attest.as_ref(),
                        ca_cert.as_deref(),
                        &corpus,
                        self_signed,
                        work_dir.as_ref(),
                    )?
                }
            };
            let platform_id = platform_id
                .as_str()
                .map_err(|_| anyhow!("Invalid PlatformId"))?;

            println!("{platform_id}");
        }
        AttestCommand::VerifyAttestation {
            alias_cert,
            attestation,
            log,
            nonce,
        } => {
            verify_attestation(&alias_cert, &attestation, &log, &nonce)?;
        }
        AttestCommand::VerifyCertChain {
            cert_chain,
            ca_cert,
            self_signed,
        } => {
            verify_cert_chain(ca_cert.as_deref(), &cert_chain, self_signed)?;
        }
        AttestCommand::VerifyMeasurements {
            cert_chain,
            log,
            corpus,
        } => {
            verify_measurements(&cert_chain, &log, &corpus)?;
        }
    }

    Ok(())
}

// Check that the measurments in `cert_chain` and `log` are all present in
// the `corpus`.
// NOTE: The output of this function is only as trustworthy as its inputs.
// These must be verified independently.
fn verify_measurements(
    cert_chain: &Path,
    log: &Path,
    corpus: &Path,
) -> Result<()> {
    let corpus = Corim::from_file(corpus)
        .context(format!("Corim from file path: {}", corpus.display()))?;
    let corpus = ReferenceMeasurements::try_from(corpus)
        .context("ReferenceMeasurements from CoRIM")?;

    let cert_chain = fs::read(cert_chain).context(format!(
        "Read cert chain from file: {}",
        cert_chain.display()
    ))?;
    let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)
        .context("loading PkiPath from PEM cert chain")?;

    let log = fs::read_to_string(log).context(format!(
        "Reading measurement log from file: {}",
        log.display()
    ))?;
    let log: Log =
        serde_json::from_str(&log).context("Deserialize Log from JSON")?;

    let measurements = MeasurementSet::from_artifacts(&cert_chain, &log)
        .context("MeasurementSet from PkiPath")?;

    dice_verifier::verify_measurements(&measurements, &corpus)
        .context("Verify measurements")
}

fn verify(
    attest: &dyn Attest,
    ca_cert: Option<&Path>,
    corpus: &Path,
    self_signed: bool,
    work_dir: &Path,
) -> Result<PlatformId> {
    // generate nonce from RNG
    info!("getting Nonce from platform RNG");
    let nonce =
        Nonce::from_platform_rng().context("Nonce from platform RNG")?;

    // write nonce to temp dir
    let nonce_path = work_dir.join("nonce.bin");
    info!("writing nonce to: {}", nonce_path.display());
    fs::write(&nonce_path, nonce)
        .context(format!("Write nonce to file: {}", nonce_path.display()))?;

    // get attestation
    info!("getting attestation");
    let attestation = attest
        .attest(&nonce)
        .context("Get attestation with nonce")?;

    // serialize attestation to json & write to file
    let mut attestation = serde_json::to_string(&attestation)
        .context("Serialize attestation to JSON")?;
    attestation.push('\n');

    let attestation_path = work_dir.join("attest.json");
    info!("writing attestation to: {}", attestation_path.display());
    fs::write(&attestation_path, &attestation).context(format!(
        "Write attestation to file: {}",
        attestation_path.display()
    ))?;

    // get log
    info!("getting measurement log");
    let log = attest
        .get_measurement_log()
        .context("Get measurement log from attestor")?;
    let mut log = serde_json::to_string(&log)
        .context("Serialize measurement log to JSON")?;
    log.push('\n');

    let log_path = work_dir.join("log.json");
    info!("writing measurement log to: {}", log_path.display());
    fs::write(&log_path, &log).context(format!(
        "Write measurement log to file: {}",
        log_path.display()
    ))?;

    // get cert chain
    info!("getting cert chain");
    let cert_chain_path = work_dir.join("cert-chain.pem");
    let mut cert_chain = File::create(&cert_chain_path).context(format!(
        "Create file for cert chain: {}",
        cert_chain_path.display()
    ))?;
    let alias_cert_path = work_dir.join("alias.pem");

    let certs = attest
        .get_certificates()
        .context("Get certificate chain from attestor")?;

    // the first cert in the chain / the leaf cert is the one
    // used to sign attestations
    info!("writing alias cert to: {}", alias_cert_path.display());
    let pem = certs[0]
        .to_pem(LineEnding::default())
        .context("Encode alias cert as PEM")?;
    fs::write(&alias_cert_path, pem)?;

    for (index, cert) in certs.iter().enumerate() {
        info!("writing cert[{}] to: {}", index, cert_chain_path.display());
        let pem = cert
            .to_pem(LineEnding::default())
            .context(format!("Encode cert {index} as PEM"))?;
        cert_chain.write_all(pem.as_bytes()).context(format!(
            "Write cert {index} to file: {}",
            cert_chain_path.display()
        ))?;
    }

    verify_cert_chain(ca_cert, &cert_chain_path, self_signed)?;
    info!("cert chain verified");

    verify_attestation(
        &alias_cert_path,
        &attestation_path,
        &log_path,
        &nonce_path,
    )?;
    info!("attestation verified");

    verify_measurements(&cert_chain_path, &log_path, corpus)?;
    info!("measurements verified");

    let cert_chain = fs::read(&cert_chain_path).context(format!(
        "read cert chain from path: {}",
        cert_chain_path.display()
    ))?;
    let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)
        .context("Parse cert chain from PEM")?;

    let platform_id = PlatformId::try_from(&cert_chain)
        .context("PlatformId from attestation cert chain")?;

    Ok(platform_id)
}

fn verify_attestation(
    alias_cert: &Path,
    attestation: &Path,
    log: &Path,
    nonce: &Path,
) -> Result<()> {
    info!("verifying attestation");
    let attestation = fs::read_to_string(attestation).context(format!(
        "Read Attestation from file: {}",
        attestation.display()
    ))?;
    let attestation: Attestation = serde_json::from_str(&attestation)
        .context("Deserialize Attestation from JSON")?;

    let log = fs::read_to_string(log)
        .context(format!("Read Log from file: {}", log.display()))?;
    let log: Log =
        serde_json::from_str(&log).context("Deserialize Log from JSON")?;

    let nonce = fs::read(nonce)
        .context(format!("Read Nonce from file: {}", nonce.display()))?;
    let nonce =
        Nonce::try_from(nonce).context("Deserialize Nonce from JSON")?;

    let alias = fs::read(alias_cert).context(format!(
        "Read alias cert from file: {}",
        alias_cert.display()
    ))?;
    let alias =
        Certificate::from_pem(&alias).context("Parse alias cert from PEM")?;

    dice_verifier::verify_attestation(&alias, &attestation, &log, &nonce)
        .context("Verify attestation")
}

fn verify_cert_chain(
    ca_cert: Option<&Path>,
    cert_chain: &Path,
    self_signed: bool,
) -> Result<()> {
    info!("veryfying cert chain");
    if !self_signed && ca_cert.is_none() {
        return Err(anyhow!("`ca-cert` or `self-signed` is required"));
    }

    let cert_chain = fs::read(cert_chain).context(format!(
        "Reading certs from file: {}",
        cert_chain.display()
    ))?;
    let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)
        .context("Parsing certs from PEM")?;

    match ca_cert {
        Some(r) => {
            let root = fs::read(r)?;
            let root = Certificate::from_pem(root)?;
            let root = Some(std::slice::from_ref(&root));
            let _ = dice_verifier::verify_cert_chain(&cert_chain, root)
                .context("Verify cert chain")?;
        }
        None => {
            warn!("allowing self-signed cert chain");
            let _ = dice_verifier::verify_cert_chain(&cert_chain, None)
                .context("Verify self signed cert chain")?;
        }
    }

    Ok(())
}

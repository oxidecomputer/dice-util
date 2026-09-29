// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use attest_data::{Attestation, Log, Nonce};
use clap::{Parser, Subcommand, ValueEnum};
use dice_mfg_msgs::PlatformId;
use dice_verifier::oxide_rot::{MeasurementSet, ReferenceMeasurements};
use helios_rot::HeliosRot;
use log::{info, warn};
#[cfg(feature = "hiffy")]
use oxide_rot::hiffy::{AttestHiffy, AttestTask};
#[cfg(feature = "ipcc")]
use oxide_rot::ipcc::AttestIpcc;
#[cfg(feature = "sled-agent")]
use oxide_rot::sled_agent::AttestSledAgent;
use rats_corim::Corim;
use slog::{Drain, FilterLevel, Logger};
use std::{
    fmt::{self, Debug},
    path::{Path, PathBuf},
};
use x509_cert::{der::DecodePem, Certificate, PkiPath};

/// Perform operations from the attestation appraisal process
#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// verbosity
    #[clap(long, env)]
    verbose: bool,

    /// Groupings of similar operations from the appraisal process
    #[command(subcommand)]
    command_group: CommandGroup,
}

/// Top level subcommand structure for Clap UI
#[derive(Clone, Debug, Subcommand)]
enum CommandGroup {
    /// Run a command specific to the Helios RoT
    Helios {
        #[command(subcommand)]
        group: HeliosRotGroup,
    },

    /// Execute a command against the Oxide RoT
    #[cfg(any(feature = "ipcc", feature = "hiffy", feature = "sled-agent"))]
    Oxide {
        #[command(subcommand)]
        interface: OxideRotInterface,
    },

    /// Perform a miscelanous opeartion on some set of attestation artifacts
    Util {
        #[command(subcommand)]
        command: UtilCommand,
    },
}

/// Groups of things we do using either the Helios RoT, or artifacts produced by it
#[derive(Clone, Debug, Subcommand)]
enum HeliosRotGroup {
    /// Perform operations from the appraisal process
    Appraise {
        /// Command to execute against the Helios RoT
        #[command(subcommand)]
        command: HeliosRotAppraise,
    },
    /// Send commands to the Helios Rot through the IOCTL interface
    Ioctl {
        /// Command to execute against the Helios RoT
        #[command(subcommand)]
        command: HeliosRotCommand,
    },
    /// Send commands to a mock instance of the Helios Rot
    Mock {
        /// Certificate chain that links the signing_key back to the first
        /// intermediate before the PKI root
        #[clap(short, long, env)]
        cert_chain: PathBuf,

        /// PEM encoded, PKCS#8 structured signing key
        #[clap(short, long, env)]
        signing_key: PathBuf,

        /// Command to execute against the Helios RoT
        #[command(subcommand)]
        command: HeliosRotCommand,
    },
}

/// Commands executed as part of the appraisal process
#[derive(Clone, Debug, Subcommand)]
enum HeliosRotAppraise {
    /// Verify an attestation / signature produced by the Helios RoT using the
    /// artifacts provided
    Attestation {
        /// Path to file holding the attestation
        #[clap(env)]
        attestation: PathBuf,

        /// Path to file holding the qualifying data
        #[clap(long, env)]
        qdata: PathBuf,

        /// Path to file holding the alias cert
        #[clap(long, env)]
        signer_cert: PathBuf,
    },
    /// Verify the provided cert chain produced by the Helios RoT using the
    /// artifacts provided
    CertChain {
        /// Path to file holding trust anchor for the associated PKI.
        #[clap(long, env)]
        ca_cert: PathBuf,

        /// Path to file holding the certificate chain
        #[clap(env)]
        cert_chain: PathBuf,
    },
    /// Appraise the measurements from `cert_chain` against the provided `corpus`
    Measurements {
        /// Path to file holding the certificate chain / PkiPath.
        #[clap(env)]
        cert_chain: PathBuf,

        /// Path to CoRIM file holding the reference measurement corpus
        #[clap(env)]
        corpus: PathBuf,
    },
}

/// Commands that require interaction with the Helios RoT
#[derive(Clone, Debug, Subcommand)]
enum HeliosRotCommand {
    /// Provide your own nonce, get back an attestation
    Attest {
        /// Path to file holding the nonce
        #[clap(env)]
        nonce: PathBuf,
    },
    /// Get the full cert chain from the RoT
    CertChain,
    /// Get an attestation from the RoT, verify the cert chain, the attestation
    /// and appraise the measurements
    Verify {
        /// Path to file holding trust anchor for the associated PKI.
        #[clap(long, env = "VERIFIER_CLI_CA_CERT")]
        ca_cert: PathBuf,

        /// Caller provided directory where artifacts are stored. If this
        /// option is provided it will be used by this tool to store
        /// artifacts retrieved from the RoT as part of the attestation
        /// process. If omitted a temp directory will be used instead.
        #[clap(long, env = "VERIFIER_CLI_WORK_DIR")]
        work_dir: Option<PathBuf>,

        /// Path to file holding the reference measurement corpus
        #[clap(long, env = "VERIFIER_CLI_CORPUS")]
        corpus: PathBuf,
    },
}

/// An enum of the interfaces available for communication with the oxide rot
#[cfg(any(feature = "ipcc", feature = "hiffy", feature = "sled-agent"))]
#[derive(Clone, Debug, Subcommand)]
enum OxideRotInterface {
    /// Perform operations from the appraisal process
    Appraise {
        /// Command from the appraisal process
        #[command(subcommand)]
        command: OxideRotAppraise,
    },
    /// Execute some operation from the appraisal process that requires
    /// communication with the RoT through the IPCC interface
    #[cfg(feature = "ipcc")]
    Ipcc {
        #[command(subcommand)]
        command: AttestCommand,
    },

    /// Execute some operation from the appraisal process by communicating
    /// with the Oxide RoT through the HIFFY RoT interface
    #[cfg(feature = "hiffy")]
    Rot {
        #[command(subcommand)]
        command: AttestCommand,
    },

    /// Execute some operation from the appraisal process that requires
    /// communication with the RoT through the SledAgent interface
    #[cfg(feature = "sled-agent")]
    SledAgent {
        #[clap(short, long, env)]
        addr: std::net::SocketAddrV6,
        #[command(subcommand)]
        command: AttestCommand,
    },

    /// Execute some operation from the appraisal process that requires
    /// communication with the RoT through the HIFFY SpRot interface
    #[cfg(feature = "hiffy")]
    Sprot {
        #[command(subcommand)]
        command: AttestCommand,
    },
}

/// An enum of the HIF operations supported by the `Attest` interface.
#[derive(Clone, Debug, Subcommand)]
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

        /// Skip measurement log appraisal.
        #[clap(
            long,
            default_value_t = false,
            env = "VERIFIER_CLI_SKIP_APPRAISAL"
        )]
        skip_appraisal: bool,

        /// Path to file holding the reference measurement corpus
        #[clap(env, env = "VERIFIER_CLI_CORPUS")]
        corpus: Option<PathBuf>,
    },
}

/// Commands that perform a step in the appraisal process. These commands
/// operate on the attestation artifacts directly. They do not communicate
/// with the RoT.
#[derive(Clone, Debug, Subcommand)]
enum OxideRotAppraise {
    /// Appraise the measurements from the artifacts provided
    Measurements {
        /// Path to file holding the certificate chain / PkiPath.
        #[clap(env)]
        cert_chain: PathBuf,

        /// Path to file holding the log
        #[clap(env)]
        log: PathBuf,

        /// Path to CoRIM file holding the reference measurement corpus
        #[clap(env)]
        corpus: PathBuf,
    },
    /// Verify signature over Attestation
    Attestation {
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
    CertChain {
        /// Path to file holding trust anchor for the associated PKI.
        #[clap(long, env, conflicts_with = "self_signed")]
        ca_cert: Option<PathBuf>,

        /// Path to file holding the certificate chain / PkiPath.
        #[clap(env)]
        cert_chain: PathBuf,

        /// Verify the final cert in the provided PkiPath against itself.
        #[clap(long, env, conflicts_with = "ca_cert")]
        self_signed: bool,
    },
}

/// Utility commands that operate on data from the attestation artifacts.
/// These commands do not interact with the RoT.
#[derive(Clone, Debug, Subcommand)]
enum UtilCommand {
    /// Show the set of measurements recorded in the provided artifacts
    MeasurementSet {
        /// Path to file holding the certificate chain / PkiPath
        #[clap(long, env)]
        cert_chain: PathBuf,

        /// Path to file holding the log
        #[clap(long, env)]
        log: PathBuf,
    },
    /// Get the PlatformId string from the provided cert chain
    PlatformId {
        /// Path to file holding the certificate chain
        #[clap(long, env)]
        cert_chain: PathBuf,
    },
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();

    let stderr_decorator = slog_term::TermDecorator::new().build();
    let stderr_drain =
        slog_term::FullFormat::new(stderr_decorator).build().fuse();
    let drain = slog_envlogger::LogBuilder::new(stderr_drain)
        .parse("RUST_LOG")
        .filter(
            None,
            if args.verbose {
                FilterLevel::Debug
            } else {
                FilterLevel::Warning
            },
        )
        .build()
        .fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let logger = Logger::root(drain, slog::o!());

    match args.command_group {
        CommandGroup::Helios { group } => {
            helios_rot_group(group, &logger).await
        }
        #[cfg(any(
            feature = "ipcc",
            feature = "hiffy",
            feature = "sled-agent"
        ))]
        CommandGroup::Oxide { interface } => {
            oxide_rot_interface(interface, &logger).await
        }
        CommandGroup::Util { command } => util_command(&command),
    }
}

/// Handle data from the caller received via `HeliosRotGroup`
async fn helios_rot_group(
    group: HeliosRotGroup,
    logger: &Logger,
) -> Result<()> {
    match group {
        HeliosRotGroup::Appraise { command } => {
            helios_rot_appraise_command(command)
        }
        HeliosRotGroup::Ioctl { command } => {
            use helios_rot::HeliosOsRot;

            let rot = HeliosOsRot::new()?;
            helios_rot_command(&rot, command, logger).await
        }
        HeliosRotGroup::Mock {
            cert_chain,
            signing_key,
            command,
        } => {
            use helios_rot::HeliosRotMock;

            let mock = HeliosRotMock::load(cert_chain, signing_key)?;
            helios_rot_command(&mock, command, logger).await
        }
    }
}

/// Execute the requested command using the provided `HeliosRot` impl
async fn helios_rot_command<R: HeliosRot>(
    rot: &R,
    command: HeliosRotCommand,
    logger: &Logger,
) -> Result<()>
where
    <R as HeliosRot>::Error: 'static,
{
    use dice_verifier::helios_rot::{MeasurementList, ReferenceMeasurementMap};
    use helios_rot::{Nonce, Nonce48};
    use pem_rfc7468::LineEnding;
    use std::{
        fs,
        io::{self, Write},
    };
    use x509_cert::der::EncodePem;

    slog::info!(logger, "executing command: {command:?}");

    match command {
        HeliosRotCommand::Attest { nonce } => {
            slog::info!(
                logger,
                "getting attestation HeliosRot w/ nonce from: {}",
                nonce.display()
            );

            let nonce = fs::read(&nonce).with_context(|| {
                format!("Nonce bytes from file: {}", nonce.display())
            })?;
            let nonce = Nonce::try_from(&nonce[..]).with_context(|| {
                format!("HeliosRot Nonce from file {:?}", nonce)
            })?;

            let attestation = rot
                .attest(&nonce)
                .await
                .context("Getting attestation with provided Nonce")?;
            let mut attestation = serde_json::to_string(&attestation)
                .context("HeliosRot attestation to JSON")?;
            attestation.push('\n');

            io::stdout()
                .write_all(attestation.as_bytes())
                .context("Write Attestation as JSON to stdout")?;
            io::stdout().flush().context("Flush stdout")
        }
        HeliosRotCommand::CertChain => {
            slog::info!(logger, "getting certificate chain from HeliosRot");
            for cert in rot.get_certificates().await? {
                let cert = cert
                    .to_pem(LineEnding::default())
                    .context("Encode certificate as PEM")?;

                io::stdout()
                    .write_all(cert.as_bytes())
                    .context("Write cert chain to stdout")?;
            }

            io::stdout().flush().context("Flush stdout")
        }
        HeliosRotCommand::Verify {
            ca_cert,
            work_dir,
            corpus,
        } => {
            slog::info!(
                logger,
                "collecting and verifying attestation from HeliosRot: \
                ca_cert: {}, corpus: {}",
                ca_cert.display(),
                corpus.display()
            );

            let ca_cert = fs::read(&ca_cert).with_context(|| {
                format!("Read CA cert from file: {}", ca_cert.display())
            })?;
            let ca_cert = Certificate::from_pem(&ca_cert)
                .context("Parse alias cert from PEM")?;

            // get nonce
            let nonce = Nonce::from_platform_rng(Nonce48::LENGTH)
                .context("Nonce from platform RNG")?;

            if let Some(ref work_dir) = work_dir {
                let out = work_dir.join("nonce.bin");
                fs::write(&out, nonce).context(format!(
                    "Write nonce to file: {}",
                    out.display()
                ))?;
            }

            let attestation = rot
                .attest(&nonce)
                .await
                .context("get attestation with nonce")?;
            if let Some(ref work_dir) = work_dir {
                // serialize attestation to json & write to file
                let mut attestation = serde_json::to_string(&attestation)
                    .context("Serialize attestation to JSON")?;
                attestation.push('\n');

                let out = work_dir.join("attest.json");
                fs::write(&out, &attestation).context(format!(
                    "Write attestation to file: {}",
                    out.display()
                ))?;
            }

            let cert_chain = rot
                .get_certificates()
                .await
                .context("Get certificate chain from HeliosRot")?;
            if let Some(work_dir) = work_dir {
                let out = work_dir.join("cert-chain.pem");
                certs_to_path(&cert_chain, &out).with_context(|| {
                    format!("Write cert chain to: {}", out.display())
                })?;
            }

            dice_verifier::verify_cert_chain(
                &cert_chain,
                Some(std::slice::from_ref(&ca_cert)),
            )
            .context("Verify HeliosRot cert chain")?;

            dice_verifier::helios_rot::verify_attestation(
                &cert_chain[0],
                &attestation,
                &nonce,
            )
            .context("Verify HeliosRot attestation")?;

            let corpus = Corim::from_file(&corpus).context(format!(
                "Corim from file path: {}",
                corpus.display()
            ))?;
            let corpus = ReferenceMeasurementMap::try_from(
                std::slice::from_ref(&corpus),
            )
            .context("ReferenceMeasurements from CoRIM")?;

            let measurements = MeasurementList::from_artifacts(&cert_chain)
                .context("MeasurementSet from PkiPath")?;

            dice_verifier::helios_rot::verify_measurements(
                &measurements,
                &corpus,
            )
            .context("Appraise HealiosRot measurements")
        }
    }
}

#[cfg(any(feature = "ipcc", feature = "hiffy", feature = "sled-agent"))]
async fn oxide_rot_interface(
    interface: OxideRotInterface,
    logger: &Logger,
) -> Result<()> {
    match interface {
        OxideRotInterface::Appraise { command } => {
            let _ = logger;
            appraise_command(&command)
        }
        #[cfg(feature = "ipcc")]
        OxideRotInterface::Ipcc { command } => {
            let _ = logger;
            let rot = AttestIpcc::new();
            rot_command(&rot, &command).await
        }
        #[cfg(feature = "hiffy")]
        OxideRotInterface::Rot { command } => {
            let rot = AttestHiffy::new(AttestTask::Rot, logger);
            rot_command(&rot, &command).await
        }
        #[cfg(feature = "sled-agent")]
        OxideRotInterface::SledAgent { addr, command } => {
            let rot = AttestSledAgent::new(addr, logger);
            rot_command(&rot, &command).await
        }
        #[cfg(feature = "hiffy")]
        OxideRotInterface::Sprot { command } => {
            let rot = AttestHiffy::new(AttestTask::Sprot, logger);
            rot_command(&rot, &command).await
        }
    }
}

fn appraise_command(command: &OxideRotAppraise) -> Result<()> {
    match command {
        OxideRotAppraise::Measurements {
            cert_chain,
            log,
            corpus,
        } => verify_measurements(cert_chain, log, corpus),
        OxideRotAppraise::Attestation {
            alias_cert,
            attestation,
            log,
            nonce,
        } => verify_attestation(alias_cert, attestation, log, nonce),
        OxideRotAppraise::CertChain {
            ca_cert,
            cert_chain,
            self_signed,
        } => verify_cert_chain(ca_cert.as_deref(), cert_chain, *self_signed),
    }
}

fn util_command(command: &UtilCommand) -> Result<()> {
    use std::fs;

    match command {
        UtilCommand::MeasurementSet { cert_chain, log } => {
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
            let log: Log = serde_json::from_str(&log)
                .context("Deserialize Log from JSON")?;

            let measurements =
                MeasurementSet::from_artifacts(&cert_chain, &log)
                    .context("MeasurementSet from artifacts")?;

            for measurement in measurements.into_iter() {
                println!("* {measurement}");
            }
        }
        UtilCommand::PlatformId { cert_chain } => {
            let cert_chain = fs::read(cert_chain).context(format!(
                "Read attestation certificate chain bytes from file: {}",
                cert_chain.display()
            ))?;
            let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)
                .context("Parse certificate chain")?;

            let platform_id = PlatformId::try_from(&cert_chain)
                .context("PlatformId from attestation cert chain")?;
            let platform_id = platform_id.as_str();

            println!("{platform_id}");
        }
    }

    Ok(())
}

#[cfg(any(feature = "ipcc", feature = "hiffy", feature = "sled-agent",))]
async fn rot_command<A: oxide_rot::Attest>(
    attest: &A,
    command: &AttestCommand,
) -> Result<()> {
    use pem_rfc7468::LineEnding;
    use std::{
        fs,
        io::{self, Write},
    };
    use x509_cert::der::EncodePem;

    match command {
        AttestCommand::Attest { nonce } => {
            let nonce = fs::read(nonce)
                .context(format!("Nonce bytes from: {}", nonce.display()))?;
            let nonce =
                Nonce::try_from(nonce).context("Nonce from file contents")?;
            let attestation = attest
                .attest(&nonce)
                .await
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
                .await
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
                .await
                .context("Getting attestation measurement log")?;
            let mut log = serde_json::to_string(&log)
                .context("Encode measurement log as JSON")?;
            log.push('\n');

            io::stdout()
                .write_all(log.as_bytes())
                .context("Write measurement log to stdout")?;
            io::stdout().flush().context("Flush stdout")?;
        }
        AttestCommand::Verify {
            ca_cert,
            corpus,
            self_signed,
            skip_appraisal,
            work_dir,
        } => {
            if corpus.is_none() && !skip_appraisal {
                return Err(anyhow!(
                    "no corpus provided but not instructed to skip \
                    measurement log appraisal"
                ));
            }
            let platform_id = verify(
                attest,
                ca_cert.as_deref(),
                corpus.as_deref(),
                *self_signed,
                work_dir.as_deref(),
            )
            .await?;
            println!("{platform_id}");
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
    use std::fs;

    let corpus = Corim::from_file(corpus)
        .context(format!("Corim from file path: {}", corpus.display()))?;
    let corpus = ReferenceMeasurements::try_from(std::slice::from_ref(&corpus))
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

    dice_verifier::oxide_rot::verify_measurements(&measurements, &corpus)
        .context("Verify measurements")
}

#[cfg(any(feature = "ipcc", feature = "hiffy", feature = "sled-agent",))]
async fn verify<A: oxide_rot::Attest>(
    attest: &A,
    ca_cert: Option<&Path>,
    corpus: Option<&Path>,
    self_signed: bool,
    work_dir: Option<&Path>,
) -> Result<PlatformId> {
    use attest_data::Nonce32;
    use pem_rfc7468::LineEnding;
    use std::fs;
    use x509_cert::der::EncodePem;

    // generate nonce from RNG
    info!("getting Nonce from platform RNG");
    let nonce = Nonce::from_platform_rng(Nonce32::LENGTH)
        .context("Nonce from platform RNG")?;

    if let Some(work_dir) = work_dir {
        let nonce_path = work_dir.join("nonce.bin");
        info!("writing nonce to: {}", nonce_path.display());
        fs::write(&nonce_path, nonce).context(format!(
            "Write nonce to file: {}",
            nonce_path.display()
        ))?;
    }

    // get attestation
    info!("getting attestation");
    let attestation = attest
        .attest(&nonce)
        .await
        .context("Get attestation with nonce")?;

    if let Some(work_dir) = work_dir {
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
    }

    // get log
    info!("getting measurement log");
    let log = attest
        .get_measurement_log()
        .await
        .context("Get measurement log from attestor")?;

    if let Some(work_dir) = work_dir {
        let mut log = serde_json::to_string(&log)
            .context("Serialize measurement log to JSON")?;
        log.push('\n');

        let log_path = work_dir.join("log.json");
        info!("writing measurement log to: {}", log_path.display());
        fs::write(&log_path, &log).context(format!(
            "Write measurement log to file: {}",
            log_path.display()
        ))?;
    }

    // get cert chain
    info!("getting cert chain");

    let certs = attest
        .get_certificates()
        .await
        .context("Get certificate chain from attestor")?;

    if let Some(work_dir) = work_dir {
        let cert_chain_path = work_dir.join("cert-chain.pem");
        certs_to_path(&certs, &cert_chain_path)
            .context("writing cert chain to disk")?;

        let alias_cert_path = work_dir.join("alias.pem");

        // the first cert in the chain / the leaf cert is the one
        // used to sign attestations
        info!("writing alias cert to: {}", alias_cert_path.display());
        let pem = certs[0]
            .to_pem(LineEnding::default())
            .context("Encode alias cert as PEM")?;
        fs::write(&alias_cert_path, pem)?;
    }

    if !self_signed && ca_cert.is_none() {
        return Err(anyhow!("`ca-cert` or `self-signed` is required"));
    }
    let roots = if let Some(p) = ca_cert {
        let cert = fs::read(p).with_context(|| {
            format!("Reading CA cert from file: {}", p.display())
        })?;
        let cert =
            Certificate::from_pem(cert).context("Certificate from PEM")?;
        Some(vec![cert])
    } else {
        warn!("allowing self-signed cert chain");
        None
    };

    let _ = dice_verifier::verify_cert_chain(&certs, roots.as_deref())
        .context("Verify cert chain")?;
    info!("cert chain verified");

    dice_verifier::oxide_rot::verify_attestation(
        &certs[0],
        &attestation,
        &log,
        &nonce,
    )
    .context("Verify attestation")?;
    info!("attestation verified");

    if let Some(corpus) = corpus {
        let measurements = MeasurementSet::from_artifacts(&certs, &log)
            .context("MeasurementSet from artifacts")?;
        let corpus = Corim::from_file(corpus).with_context(|| {
            format!("Corim from file path: {}", corpus.display())
        })?;
        let corpus =
            ReferenceMeasurements::try_from(std::slice::from_ref(&corpus))
                .context("ReferenceMeasurements from CoRIM")?;

        dice_verifier::oxide_rot::verify_measurements(&measurements, &corpus)
            .context("Verify measurements")?;
        info!("measurements verified");
    } else {
        warn!("measurement corpus is None: skipping measurement appraisal");
    }

    PlatformId::try_from(&certs)
        .context("PlatformId from attestation cert chain")
}

fn verify_attestation(
    alias_cert: &Path,
    attestation: &Path,
    log: &Path,
    nonce: &Path,
) -> Result<()> {
    use std::fs;

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

    dice_verifier::oxide_rot::verify_attestation(
        &alias,
        &attestation,
        &log,
        &nonce,
    )
    .context("Verify attestation")
}

fn verify_cert_chain(
    ca_cert: Option<&Path>,
    cert_chain: &Path,
    self_signed: bool,
) -> Result<()> {
    use std::fs;

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

    let roots = if let Some(p) = ca_cert {
        let cert = fs::read(p)?;
        let cert = Certificate::from_pem(cert)?;
        Some(vec![cert])
    } else {
        warn!("allowing self-signed cert chain");
        None
    };

    let _ = dice_verifier::verify_cert_chain(&cert_chain, roots.as_deref())
        .context("Verify cert chain")?;

    Ok(())
}

/// Handle data from the caller received via `HeliosRotAppraise`
fn helios_rot_appraise_command(command: HeliosRotAppraise) -> Result<()> {
    match command {
        HeliosRotAppraise::Attestation {
            signer_cert,
            attestation,
            qdata,
        } => helios_rot_verify_attestation(&attestation, &qdata, &signer_cert),
        HeliosRotAppraise::CertChain {
            ca_cert,
            cert_chain,
        } => helios_rot_verify_cert_chain(&ca_cert, &cert_chain),
        HeliosRotAppraise::Measurements { cert_chain, corpus } => {
            helios_rot_appraise_measurements(&cert_chain, &corpus)
        }
    }
}

fn helios_rot_appraise_measurements<P: AsRef<Path>>(
    cert_chain: P,
    corpus: P,
) -> Result<()> {
    use dice_verifier::helios_rot::{MeasurementList, ReferenceMeasurementMap};

    use std::fs;

    let cert_chain = fs::read(&cert_chain).context(format!(
        "Read cert chain from file: {}",
        cert_chain.as_ref().display()
    ))?;
    let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)
        .context("loading PkiPath from PEM cert chain")?;

    let corpus = Corim::from_file(&corpus).context(format!(
        "Corim from file path: {}",
        corpus.as_ref().display()
    ))?;
    let corpus =
        ReferenceMeasurementMap::try_from(std::slice::from_ref(&corpus))
            .context("ReferenceMeasurements from CoRIM")?;

    let measurements = MeasurementList::from_artifacts(&cert_chain)
        .context("MeasurementSet from PkiPath")?;

    dice_verifier::helios_rot::verify_measurements(&measurements, &corpus)
        .context("Appraise measurements from Helios RoT artifacts")
}

fn helios_rot_verify_cert_chain<P: AsRef<Path>>(
    ca_cert: P,
    cert_chain: P,
) -> Result<()> {
    use std::fs;

    let ca_cert = fs::read(&ca_cert).context(format!(
        "Read cert chain from file: {}",
        ca_cert.as_ref().display()
    ))?;
    let ca_cert =
        Certificate::from_pem(&ca_cert).context("CA cert from PEM")?;

    let cert_chain = fs::read(&cert_chain).context(format!(
        "Read cert chain from file: {}",
        cert_chain.as_ref().display()
    ))?;
    let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)
        .context("loading PkiPath from PEM cert chain")?;

    dice_verifier::verify_cert_chain(
        &cert_chain,
        Some(std::slice::from_ref(&ca_cert)),
    )
    .context("Verify cert chain")
    .map(|_| ())
}

fn helios_rot_verify_attestation<P: AsRef<Path>>(
    attestation: P,
    qdata: P,
    signer_cert: P,
) -> Result<()> {
    use helios_rot::{Attestation, Nonce};
    use std::fs;

    let attestation = fs::read_to_string(&attestation).context(format!(
        "Read Attestation from file: {}",
        attestation.as_ref().display()
    ))?;
    let attestation: Attestation = serde_json::from_str(&attestation)
        .context("Deserialize Attestation from JSON")?;

    let qdata = fs::read(&qdata).context(format!(
        "Read Nonce from file: {}",
        qdata.as_ref().display()
    ))?;
    let qdata = Nonce::try_from(qdata.as_slice())
        .context("Deserialize Nonce from binary")?;

    let signer_cert = fs::read(&signer_cert).context(format!(
        "Read alias cert from file: {}",
        signer_cert.as_ref().display()
    ))?;
    let signer_cert = Certificate::from_pem(&signer_cert)
        .context("Parse alias cert from PEM")?;

    dice_verifier::helios_rot::verify_attestation(
        &signer_cert,
        &attestation,
        &qdata,
    )
    .context("Verify HeliosRotAttestation")
}

fn certs_to_path(certs: &PkiPath, out: &Path) -> Result<()> {
    use pem_rfc7468::LineEnding;
    use std::{fs::File, io::Write};
    use x509_cert::der::EncodePem;

    let mut cert_chain = File::create(out)
        .context(format!("Create file for cert chain: {}", out.display()))?;

    for (index, cert) in certs.iter().enumerate() {
        info!("writing cert[{}] to: {}", index, out.display());
        let pem = cert
            .to_pem(LineEnding::default())
            .context(format!("Encode cert {index} as PEM"))?;
        cert_chain.write_all(pem.as_bytes()).context(format!(
            "Write cert {index} to file: {}",
            out.display()
        ))?;
    }

    Ok(())
}

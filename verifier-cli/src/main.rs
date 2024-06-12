// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use attest_data::{Attestation, Nonce};
use clap::{Parser, Subcommand, ValueEnum};
use dice_verifier::PkiPathSignatureVerifier;
use env_logger::Builder;
use hubpack::SerializedSize;
use log::{debug, error, info, warn, LevelFilter};
use pem_rfc7468::{LineEnding, PemLabel};
use sha3::{Digest, Sha3_256};
use std::{
    fmt::{self, Debug, Formatter},
    fs::{self, File},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::NamedTempFile;
use x509_cert::{
    der::{Decode, DecodePem},
    Certificate, PkiPath,
};

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
    /// Get the length in bytes of attestations.
    AttestLen,
    /// Get a certificate from the Attest task.
    Cert {
        /// Target encoding for certificate.
        #[clap(long, env, default_value_t = Encoding::Pem)]
        encoding: Encoding,

        /// Index of certificate in certificate chain.
        #[clap(env)]
        index: u32,
    },
    /// Get the full cert chain from the RoT encoded per RFC 6066 (PKI path)
    CertChain,
    /// Get the length of the certificate chain that ties the key used by the
    /// `Attest` task to sign attestations back to some PKI. This chain may be
    /// self signed or will terminate at the intermediate before the root.
    CertChainLen,
    /// get the length of the certificate at the provided index.
    CertLen {
        /// Index of certificate in certificate chain.
        #[clap(env)]
        index: u32,
    },
    /// Get the log of measurements recorded by the RoT.
    Log,
    /// Get the length in bytes of the Log.
    LogLen,
    /// Report a measurement to the `Attest` task for recording in the
    /// measurement log.
    Record {
        /// Path to file holding the digest to record
        #[clap(env)]
        digest: PathBuf,
    },
    Verify {
        /// Path to file holding trust anchor for the associated PKI.
        #[clap(
            long,
            env = "VERIFIER_CLI_CA_CERT",
            conflicts_with = "self_signed"
        )]
        ca_cert: Option<PathBuf>,

        /// Preserve temporary / intermediate files. The path to the
        /// temp directory will be written to stderr.
        #[clap(long, env)]
        persist: bool,

        /// Verify the final cert in the provided PkiPath against itself.
        #[clap(long, env, conflicts_with = "ca_cert")]
        self_signed: bool,
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
}

/// An enum of the possible routes to the `Attest` task.
#[derive(Clone, Debug, ValueEnum)]
enum Interface {
    Rot,
    Sprot,
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Interface::Rot => write!(f, "Attest"),
            Interface::Sprot => write!(f, "SpRot"),
        }
    }
}

/// An enum of the possible certificate encodings.
#[derive(Clone, Debug, ValueEnum)]
enum Encoding {
    Der,
    Pem,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Encoding::Der => write!(f, "der"),
            Encoding::Pem => write!(f, "pem"),
        }
    }
}

/// A type to simplify the execution of the HIF operations exposed by the RoT
/// Attest task.
struct AttestHiffy {
    /// The Attest task can be reached either directly through the `hiffy`
    /// task in the RoT or through the `Sprot` task in the Sp. This member
    /// determins which is used.
    interface: Interface,
}

impl AttestHiffy {
    const CHUNK_SIZE: usize = 256;

    fn new(interface: Interface) -> Self {
        AttestHiffy { interface }
    }

    /// `humility` returns u32s as hex strings prefixed with "0x". This
    /// function expects a string formatted like an output string from hiffy
    /// returning a u32. If the string is not prefixed with "0x" it is assumed
    /// to be decimal. Currently this function ignores the interface and
    /// operation names from the string. Future work may check that these are
    /// consistent with the operation executed.
    fn u32_from_cmd_output(output: Output) -> Result<u32> {
        if output.status.success() {
            // check interface & operation name?
            let output = String::from_utf8_lossy(&output.stdout);
            let output: Vec<&str> = output.trim().split(' ').collect();
            let output = output[output.len() - 1];
            debug!("output: {}", output);

            let (output, radix) = match output.strip_prefix("0x") {
                Some(s) => {
                    debug!("prefix stripped: \"{}\"", s);
                    (s, 16)
                }
                None => (output, 10),
            };

            let log_len =
                u32::from_str_radix(output, 16).with_context(|| {
                    format!(
                        "Failed to parse \"{}\" as base {} u32",
                        output, radix
                    )
                })?;

            debug!("output u32: {}", log_len);

            Ok(log_len)
        } else {
            Err(anyhow!(
                "command failed with status: {}\nstdout: \"{}\"\nstderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    /// This convenience function encapsulates a pattern common to
    /// the hiffy command line for the `Attest` operations that get the
    /// lengths of the data returned in leases.
    fn get_len_cmd(&self, op: &str, args: Option<String>) -> Result<u32> {
        // rely on environment for target & archive?
        // check that they are set before continuing
        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg("--call");
        cmd.arg(format!("{}.{}", self.interface, op));
        if let Some(a) = args {
            cmd.arg(format!("--arguments={}", a));
        }
        debug!("executing command: {:?}", cmd);

        let output = cmd.output()?;
        Self::u32_from_cmd_output(output)
    }

    /// This convenience function encapsulates a pattern common to the hiffy
    /// command line for the `Attest` operations that return blobs in chunks.
    fn get_chunk(
        &self,
        op: &str,
        length: usize,
        output: &Path,
        args: Option<&str>,
        input: Option<&str>,
    ) -> Result<()> {
        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg(format!("--call={}.{}", self.interface, op));
        cmd.arg(format!("--num={}", length));
        cmd.arg(format!("--output={}", output.to_string_lossy()));
        if let Some(args) = args {
            cmd.arg("--arguments");
            cmd.arg(args);
        }
        if let Some(i) = input {
            cmd.arg(format!("--input={}", i));
        }
        debug!("executing command: {:?}", cmd);

        let output = cmd.output()?;
        if output.status.success() {
            debug!("output: {}", String::from_utf8_lossy(&output.stdout));
            Ok(())
        } else {
            Err(anyhow!(
                "command failed with status: {}\nstdout: \"{}\"\nstderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    fn attest(&self, nonce: Nonce, out: &mut [u8]) -> Result<()> {
        let mut attestation_tmp = tempfile::NamedTempFile::new()?;
        let mut nonce_tmp = tempfile::NamedTempFile::new()?;

        let mut buf = [0u8; Nonce::MAX_SIZE];
        hubpack::serialize(&mut buf, &nonce)
            .map_err(|_| anyhow!("failed to serialize Nonce"))?;
        nonce_tmp.write_all(&buf)?;

        self.get_chunk(
            "attest",
            out.len(),
            attestation_tmp.path(),
            None,
            Some(&nonce_tmp.path().to_string_lossy()),
        )?;
        Ok(attestation_tmp.read_exact(&mut out[..])?)
    }

    /// Get length of the measurement log in bytes.
    fn attest_len(&self) -> Result<u32> {
        self.get_len_cmd("attest_len", None)
    }

    /// Get length of the certificate chain from the Attest task. This cert
    /// chain may be self signed or will terminate at the intermediate before
    /// the root.
    fn cert_chain_len(&self) -> Result<u32> {
        self.get_len_cmd("cert_chain_len", None)
    }

    /// Get length of the certificate at the provided index in bytes.
    fn cert_len(&self, index: u32) -> Result<u32> {
        self.get_len_cmd("cert_len", Some(format!("index={}", index)))
    }

    fn cert(&self, index: u32, out: &mut [u8]) -> Result<()> {
        for offset in
            (0..out.len() - Self::CHUNK_SIZE).step_by(Self::CHUNK_SIZE)
        {
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.get_chunk(
                "cert",
                Self::CHUNK_SIZE,
                tmp.path(),
                Some(&format!("index={},offset={}", index, offset)),
                None,
            )?;
            tmp.read_exact(&mut out[offset..offset + Self::CHUNK_SIZE])?;
        }

        let remain = out.len() % Self::CHUNK_SIZE;
        if remain != 0 {
            let offset = out.len() - remain;
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.get_chunk(
                "cert",
                remain,
                tmp.path(),
                Some(&format!("index={},offset={}", index, offset)),
                None,
            )?;
            tmp.read_exact(&mut out[offset..])?;
        }

        Ok(())
    }

    /// Get measurement log. This function assumes that the slice provided
    /// is sufficiently large to hold the log.
    fn log(&self, out: &mut [u8]) -> Result<()> {
        for offset in
            (0..out.len() - Self::CHUNK_SIZE).step_by(Self::CHUNK_SIZE)
        {
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.get_chunk(
                "log",
                Self::CHUNK_SIZE,
                tmp.path(),
                Some(&format!("offset={}", offset)),
                None,
            )?;
            tmp.read_exact(&mut out[offset..offset + Self::CHUNK_SIZE])?;
        }

        let remain = out.len() % Self::CHUNK_SIZE;
        if remain != 0 {
            let offset = out.len() - remain;
            let mut tmp = tempfile::NamedTempFile::new()?;
            self.get_chunk(
                "log",
                remain,
                tmp.path(),
                Some(&format!("offset={}", offset)),
                None,
            )?;
            tmp.read_exact(&mut out[offset..])?;
        }

        Ok(())
    }

    /// Get length of the measurement log in bytes.
    fn log_len(&self) -> Result<u32> {
        self.get_len_cmd("log_len", None)
    }

    /// Record the sha3 hash of a file.
    fn record(&self, data: &[u8]) -> Result<()> {
        let digest = Sha3_256::digest(data);
        info!("Recording measurement: {:?}", digest);
        let mut tmp = NamedTempFile::new()?;
        if digest.as_slice().len() != tmp.write(digest.as_slice())? {
            return Err(anyhow!("failed to write all data to disk"));
        }

        let mut cmd = Command::new("humility");

        cmd.arg("hiffy");
        cmd.arg(format!("--call={}.record", self.interface));
        cmd.arg(format!("--input={}", tmp.path().to_string_lossy()));
        cmd.arg("--arguments=algorithm=Sha3_256");
        debug!("executing command: {:?}", cmd);

        let output = cmd.output()?;
        if output.status.success() {
            debug!("output: {}", String::from_utf8_lossy(&output.stdout));
            Ok(())
        } else {
            Err(anyhow!(
                "command failed with status: {}\nstdout: \"{}\"\nstderr: \"{}\"",
                output.status,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }
}

fn get_cert(
    attest: &AttestHiffy,
    encoding: Encoding,
    index: u32,
) -> Result<Vec<u8>> {
    let cert_len = attest.cert_len(index)?;
    let mut out = vec![0u8; cert_len as usize];
    attest.cert(index, &mut out)?;

    Ok(match encoding {
        Encoding::Der => out,
        Encoding::Pem => {
            let pem = pem_rfc7468::encode_string(
                Certificate::PEM_LABEL,
                LineEnding::default(),
                &out,
            )?;
            pem.as_bytes().to_vec()
        }
    })
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

    let attest = AttestHiffy::new(args.interface);

    match args.command {
        AttestCommand::Attest { nonce } => {
            let nonce = fs::read(nonce)?;
            let nonce = Nonce::try_from(&nonce[..])?;
            let attest_len = attest.attest_len()?;
            let mut out = vec![0u8; attest_len as usize];
            attest.attest(nonce, &mut out)?;

            io::stdout().write_all(&out)?;
            io::stdout().flush()?;
        }
        AttestCommand::AttestLen => println!("{}", attest.attest_len()?),
        AttestCommand::Cert { encoding, index } => {
            let out = get_cert(&attest, encoding, index)?;

            io::stdout().write_all(&out)?;
            io::stdout().flush()?;
        }
        AttestCommand::CertChain => {
            for index in 0..attest.cert_chain_len()? {
                let out = get_cert(&attest, Encoding::Pem, index)?;

                io::stdout().write_all(&out)?;
            }
            io::stdout().flush()?;
        }
        AttestCommand::CertChainLen => println!("{}", attest.cert_chain_len()?),
        AttestCommand::CertLen { index } => {
            println!("{}", attest.cert_len(index)?)
        }
        AttestCommand::Log => {
            let log_len = attest.log_len()?;
            let mut out = vec![0u8; log_len as usize];
            attest.log(&mut out)?;

            io::stdout().write_all(&out)?;
            io::stdout().flush()?;
        }
        AttestCommand::LogLen => println!("{}", attest.log_len()?),
        AttestCommand::Record { digest } => {
            let digest = fs::read(digest)?;
            attest.record(&digest)?;
        }
        AttestCommand::Verify {
            ca_cert,
            persist,
            self_signed,
        } => {
            // generate nonce from RNG
            info!("getting Nonce from platform RNG");
            let nonce = Nonce::from_platform_rng()?;

            // make tempdir, write nonce to temp dir
            let tmp_dir = tempfile::tempdir()?;
            let nonce_path = tmp_dir.path().join("nonce.bin");
            info!("writing nonce to: {}", nonce_path.display());
            fs::write(&nonce_path, nonce)?;

            // get attestation
            info!("getting attestation");
            let mut attestation = vec![0u8; attest.attest_len()? as usize];
            attest.attest(nonce, &mut attestation)?;
            let attestation_path = tmp_dir.path().join("attest.bin");
            info!("writing attestation to: {}", attestation_path.display());
            fs::write(&attestation_path, &attestation)?;

            // get log
            info!("getting measurement log");
            let mut log = vec![0u8; attest.log_len()? as usize];
            attest.log(&mut log)?;
            let log_path = tmp_dir.path().join("log.bin");
            info!("writing measurement log to: {}", log_path.display());
            fs::write(&log_path, &log)?;

            // get cert chain
            info!("getting cert chain");
            let cert_chain_path = tmp_dir.path().join("cert-chain.pem");
            let mut cert_chain = File::create(&cert_chain_path)?;
            let alias_cert_path = tmp_dir.path().join("alias.pem");
            for index in 0..attest.cert_chain_len()? {
                let encoding = Encoding::Pem;
                info!("getting cert[{}] encoded as {}", index, encoding);
                let cert = get_cert(&attest, encoding, index)?;

                // the first cert in the chain / the leaf cert is the one
                // used to sign attestations
                if index == 0 {
                    info!(
                        "writing alias cert to: {}",
                        alias_cert_path.display()
                    );
                    fs::write(&alias_cert_path, &cert)?;
                }

                info!(
                    "writing cert[{}] to: {}",
                    index,
                    cert_chain_path.display()
                );
                cert_chain.write_all(&cert)?;
            }

            verify_attestation(
                &alias_cert_path,
                &attestation_path,
                &log_path,
                &nonce_path,
            )?;
            info!("attestation verified");
            verify_cert_chain(&ca_cert, &cert_chain_path, self_signed)?;
            info!("cert chain verified");

            // persist the temp dir and write path to stderr if requested
            if persist {
                let tmp_path = tmp_dir.into_path();
                eprintln!("{}", tmp_path.display());
            }
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
            verify_cert_chain(&ca_cert, &cert_chain, self_signed)?;
        }
    }

    Ok(())
}

fn verify_attestation(
    alias_cert: &PathBuf,
    attestation: &PathBuf,
    log: &PathBuf,
    nonce: &PathBuf,
) -> Result<()> {
    info!("verifying attestation");
    let attestation = fs::read(attestation)?;
    let (attestation, _): (Attestation, _) = hubpack::deserialize(&attestation)
        .map_err(|e| anyhow!("Failed to deserialize Attestation: {}", e))?;

    let log = fs::read(log)?;

    let nonce: Nonce = fs::read(nonce)?.try_into()?;

    let alias = fs::read(alias_cert)?;
    let alias = match pem_rfc7468::decode_vec(&alias) {
        Ok((l, v)) => {
            debug!("decoded pem w/ label: \"{}\"", l);
            if l != Certificate::PEM_LABEL {
                error!("got cert w/ unsupported pem label");
            }

            v
        }
        Err(e) => {
            debug!("error decoding PEM: {}", e);
            alias
        }
    };

    let alias = Certificate::from_der(&alias)?;

    dice_verifier::verify_attestation(&alias, &attestation, &log, &nonce)
}

fn verify_cert_chain(
    ca_cert: &Option<PathBuf>,
    cert_chain: &PathBuf,
    self_signed: bool,
) -> Result<()> {
    info!("veryfying cert chain");
    if !self_signed && ca_cert.is_none() {
        return Err(anyhow!("`ca-cert` or `self-signed` is required"));
    }

    let cert_chain = fs::read(cert_chain)?;
    let cert_chain: PkiPath = Certificate::load_pem_chain(&cert_chain)?;

    let root = match ca_cert {
        Some(r) => {
            let root = fs::read(r)?;
            Some(Certificate::from_pem(root)?)
        }
        None => {
            warn!("allowing self-signed cert chain");
            None
        }
    };

    let verifier = PkiPathSignatureVerifier::new(root)?;
    verifier.verify(&cert_chain)
}

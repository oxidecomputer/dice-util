// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, ValueEnum};
use env_logger::Builder;
use hex::ToHex;
use log::{debug, error, info, LevelFilter};
use pem_rfc7468::{LineEnding, PemLabel};
use std::{fs, path::PathBuf, process};
use x509_cert::{
    der::{Decode, DecodePem, Encode, EncodePem},
    Certificate,
};

use dice_cert_check::{Signature, VerifierFactory};

/// Transform an x509 cert between DER and PEM encoding.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Noisy output.
    #[clap(long)]
    verbose: bool,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
#[clap(name = "command")]
enum Command {
    /// Convert the provided cert to the requested format.
    Convert {
        /// Input file holding certificate.
        #[clap(long = "in")]
        infile: PathBuf,

        /// Output file for certificate.
        #[clap(long = "out")]
        outfile: PathBuf,

        /// Write certificate out in this format.
        #[clap(long)]
        encoding: Encoding,
    },
    /// Verify signatures in the provided cert chain back to the provided
    /// root CA.
    Verify {
        /// Input file holding certificate chain.
        #[clap(long = "in")]
        infile: PathBuf,

        /// Input file holding certificate chain.
        #[clap(long = "root")]
        cafile: PathBuf,
    },
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, ValueEnum)]
enum Encoding {
    DER,
    PEM,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Debug
    } else {
        LevelFilter::Error
    };
    builder.filter(None, level).init();

    match args.command {
        Command::Convert {
            infile,
            outfile,
            encoding,
        } => convert(&infile, &outfile, encoding),
        Command::Verify { infile, cafile } => {
            let mut cert_chain = parse_pem_cert_chain(&infile)?;
            let ca_cert = fs::read_to_string(cafile)?;
            let ca_cert = Certificate::from_pem(ca_cert)?;
            cert_chain.push(ca_cert);

            let code = match verify(&cert_chain) {
                Ok(_) => 0,
                Err(e) => {
                    error!("Error: {}", e);
                    1
                }
            };
            process::exit(code)
        }
    }
}

fn convert(
    infile: &PathBuf,
    outfile: &PathBuf,
    encoding: Encoding,
) -> Result<()> {
    let cert = fs::read(infile)?;

    let cert = match Certificate::from_pem(&cert) {
        Ok(c) => c,
        Err(_) => {
            info!("failed to parse input as PEM, trying DER ...");
            Certificate::from_der(&cert)?
        }
    };

    // this is a bit weird, but there's a reason ...
    let cert_vec = match encoding {
        Encoding::DER => cert.to_vec()?,
        // If we get the PEM encoded cert by just calling 'to_vec' it will
        // be preceded by 5 bytes of ... something not PEM. We work around
        // this by calling 'as_bytes' first.
        Encoding::PEM => {
            cert.to_pem(LineEnding::default())?.as_bytes().to_vec()
        }
    };

    fs::write(outfile, cert_vec)?;

    Ok(())
}

// look into rfc 6066 PkiPath encoding?
// This is gross but ... it works
fn parse_pem_cert_chain(infile: &PathBuf) -> Result<Vec<Certificate>> {
    let mut tmp = String::new();
    let boundary: String =
        String::from("-----END ") + Certificate::PEM_LABEL + "-----";
    let mut chain = Vec::<Certificate>::new();

    for line in fs::read_to_string(infile)?.lines() {
        tmp.push_str(line);
        tmp.push('\n');
        if line.contains(&boundary) {
            // tmp string now holds one PEM encoded Certificate
            chain.push(Certificate::from_pem(&tmp)?);
            tmp.clear();
        }
    }

    Ok(chain)
}

fn verify(cert_chain: &[Certificate]) -> Result<()> {
    // It's possible we may be handed a self signed cert and asked to verify
    // it. For now this is an edge case.
    if cert_chain.len() < 2 {
        todo!("not enough certs");
    }

    let signature = Signature::new(
        &cert_chain[0].signature_algorithm,
        &cert_chain[0].signature,
    )?;
    debug!("Initial signature: {}", signature);

    let message = cert_chain[0].tbs_certificate.to_vec()?;
    debug!("Initial message: {}", message.encode_hex::<String>());

    _verify(&cert_chain[1..], &message, &signature)
}

/// This function should only be called from the 'verify' function. Where
/// 'verify' handles the initial condition for recusrion, this function is
/// the primary recursion.
fn _verify(
    cert_chain: &[Certificate],
    message: &[u8],
    signature: &Signature,
) -> Result<()> {
    debug!("cert_chain.len(): {}", cert_chain.len());
    if cert_chain.is_empty() {
        error!("Cert chain has no certs. This shouldn't happen.");
        process::exit(1);
    }

    let verifier = VerifierFactory::get_verifier(
        &cert_chain[0].tbs_certificate.subject_public_key_info,
    )?;

    // verify signature from previous cert with verifier from current cert
    verifier.verify(message, signature)?;

    // prepare data to be verified by next recursion or terminal condition
    let signature = Signature::new(
        &cert_chain[0].signature_algorithm,
        &cert_chain[0].signature,
    )?;
    let message = cert_chain[0].tbs_certificate.to_vec()?;

    if cert_chain.len() > 1 {
        _verify(&cert_chain[1..], &message, &signature)
    } else {
        // the terminal condition (no more certs in the chain) requires that
        // we verify the signature on the final cert with the private key from
        // the same cert. We've already prepared the signature & message from
        // this cert in preparation for the next recursion. Instead of calling
        // ourselves again however we do the verification and return.
        info!("terminal condition");

        // verify signature from previous cert with verifier from current cert
        Ok(verifier.verify(&message, &signature)?)
    }
}

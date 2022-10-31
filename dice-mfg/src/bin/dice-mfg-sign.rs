// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::Parser;
use dice_mfg::{Error, Result};
use env_logger::Builder;
use log::{info, LevelFilter};
use std::{path::PathBuf, process::Command};

/// Use provided openssl config and CSR files to generate a signed cert.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// verbosity
    #[clap(long)]
    verbose: bool,

    /// Path where Cert is written.
    #[clap(long)]
    cert_out: PathBuf,

    /// Path to openssl.cnf file used for signing operation.
    #[clap(long)]
    openssl_cnf: PathBuf,

    /// CA section from openssl.cnf used for signing operation.
    /// If omitted default from openssl.cnf is used.
    #[clap(long)]
    ca_section: Option<String>,

    /// x509 v3 extension section from openssl.cnf used for signing operation.
    /// If omitted default from openssl.cnf is used.
    #[clap(long)]
    v3_section: Option<String>,

    #[clap(long, default_value_t = false)]
    yubi: bool,

    /// Path to input CSR file.
    #[clap(long)]
    csr_in: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Info
    } else {
        LevelFilter::Warn
    };

    builder.filter(None, level).init();

    let mut cmd = Command::new("openssl");

    cmd.arg("ca")
        .arg("-config")
        .arg(args.openssl_cnf)
        .arg("-batch")
        .arg("-notext")
        .arg("-in")
        .arg(args.csr_in)
        .arg("-out")
        .arg(args.cert_out);

    if args.ca_section.is_some() {
        cmd.arg("-name").arg(args.ca_section.unwrap());
    }
    if args.v3_section.is_some() {
        cmd.arg("-extensions").arg(args.v3_section.unwrap());
    }

    if args.yubi {
        // -key $OPENSSL_KEY \
        cmd.arg("-engine")
            .arg("pkcs11")
            .arg("-keyform")
            .arg("engine")
            .arg("-md")
            .arg("sha384");
    }

    info!("cmd: {:?}", cmd);

    print!("signing CSR ... ");
    let output = cmd.output()?;

    if output.status.success() {
        println!("success");
        Ok(())
    } else {
        println!("failed");
        eprintln!("command failed with status: {}", output.status);
        eprintln!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        Err(Box::new(Error::CertGenFail))
    }
}

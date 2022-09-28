// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::Parser;
use dice_mfg::{Error, Result};
use std::{env, fs, path::PathBuf, process::Command};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to input CSR file
    #[clap(long, default_value = "csr.pem")]
    csr_in: PathBuf,

    /// Path to output DevcieId cert
    #[clap(long, default_value = "cert.pem")]
    cert_out: PathBuf,

    /// directory hosting CA
    #[clap(long)]
    ca_dir: Option<PathBuf>,

    /// OpenSSL config file
    #[clap(long, default_value = "openssl.cnf")]
    openssl_cnf: PathBuf,

    /// config file section with CA config
    #[clap(long, default_value = "default_ca")]
    ca_section: String,

    /// config file section defining v3 extensions added to cert
    #[clap(long, default_value = "x509_extensions")]
    v3_section: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // When we execute the openssl-ca command we change the current directory
    // to args.ca_dir. Paths passed in should be relative to the pwd and so
    // they'll be wrong if we pass them to the openssl command. As a workaround
    // we convert them to absolute paths here.
    let csr_in = fs::canonicalize(&args.csr_in)?;
    let openssl_cnf = fs::canonicalize(&args.openssl_cnf)?;

    let cert_out = if args.cert_out.is_relative() {
        let mut cert_out = env::current_dir()?;
        cert_out.push(args.cert_out);
        cert_out
    } else {
        args.cert_out
    };

    let ca_dir = args
        .ca_dir
        .unwrap_or_else(|| env::current_dir().expect("no PWD?"));
    println!("openssl pwd: {}", ca_dir.display());

    // generate / sign cert
    println!("ca_dir: {}", ca_dir.display());
    let mut cmd = Command::new("openssl");

    cmd.current_dir(ca_dir)
        .arg("ca")
        .arg("-batch")
        .arg("-notext")
        .arg("-config")
        .arg(&openssl_cnf)
        .arg("-name")
        .arg(&args.ca_section)
        .arg("-extensions")
        .arg(&args.v3_section)
        // no expiration for DeviceId certs
        .arg("-enddate")
        .arg("99991231235959Z")
        .arg("-notext")
        .arg("-md")
        .arg("sha3-256")
        .arg("-in")
        .arg(&csr_in)
        .arg("-out")
        .arg(&cert_out);

    let output = cmd.output()?;
    if output.status.success() {
        println!("command succeeded with status: {}", output.status);
        println!("stdout: \"{}\"", String::from_utf8_lossy(&output.stdout));
        Ok(())
    } else {
        println!("command failed with status: {}", output.status);
        println!("stderr: \"{}\"", String::from_utf8_lossy(&output.stderr));
        Err(Box::new(Error::CertGenFail))
    }
}

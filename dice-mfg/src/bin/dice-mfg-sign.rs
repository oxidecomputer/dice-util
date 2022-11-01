// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::Parser;
use dice_mfg::Result;
use env_logger::Builder;
use log::LevelFilter;
use std::path::PathBuf;

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

    print!("signing CSR ... ");
    match dice_mfg::sign_cert(
        args.openssl_cnf,
        args.csr_in,
        args.cert_out,
        args.ca_section,
        args.v3_section,
        args.yubi,
    ) {
        Ok(_) => {
            println!("success");
            Ok(())
        }
        Err(e) => {
            println!("failed");
            Err(e)
        }
    }
}

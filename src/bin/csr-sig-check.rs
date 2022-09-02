use clap::Parser;
use dice_cert_tmpl::{Csr, Encoding, MissingFieldError, encoding};
use std::{path::PathBuf, process};

use salty::{
    constants::{PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH},
    signature::Signature,
    PublicKey,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// CSR input format: pem|der
    #[clap(long, default_value = "pem")]
    encoding: Encoding,

    /// Path to CSR file.
    csr_path: PathBuf,
}

fn main() -> Result<(), MissingFieldError> {
    let args = Args::parse();

    let mut csr_der = match args.csr_path.to_str() {
        Some(csr_path) => {
            encoding::decode_csr(csr_path, args.encoding).expect("decode_csr")
        }
        None => {
            eprintln!("Invalid path");
            process::exit(1);
        }
    };

    let csr = Csr::from_slice(&mut csr_der);

    let public: &[u8; PUBLICKEY_SERIALIZED_LENGTH] = 
        csr.get_pub()?.try_into().unwrap();

    let pubkey: PublicKey = public.try_into().unwrap();

    let sig: &[u8; SIGNATURE_SERIALIZED_LENGTH] =
        csr.get_sig()?.try_into().unwrap();
    let sig: Signature = sig.into();

    let data = csr.get_signdata()?;

    print!("Checking signature ... ");
    if pubkey.verify(data, &sig).is_ok() {
        println!("Success!");
    } else {
        println!("FAIL");
    }

    Ok(())
}

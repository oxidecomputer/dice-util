use clap::Parser;
use dice_cert_tmpl::{Csr, Encoding, encoding};
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut csr = encoding::decode_csr(&args.csr_path, args.encoding)?;
    let csr = Csr::from_slice(&mut csr);

    let public: &[u8; PUBLICKEY_SERIALIZED_LENGTH] = 
        csr.get_pub()?.try_into()?;

    let pubkey: PublicKey = match public.try_into() {
        Ok(pubkey) => pubkey,
        Err(_) => {
            eprintln!("Bad public key.");
            process::exit(1);
        }
    };

    let sig: &[u8; SIGNATURE_SERIALIZED_LENGTH] =
        csr.get_sig()?.try_into()?;
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

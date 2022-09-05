use clap::Parser;
use dice_cert_tmpl::{encoding, Cert, Encoding};
use std::path::PathBuf;

use salty::{constants::SIGNATURE_SERIALIZED_LENGTH, signature::Signature, Keypair};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to cert file.
    cert: PathBuf,

    /// input format: pem|der
    #[clap(long, default_value = "pem")]
    encoding: Encoding,

    /// Path to key file.
    #[clap(long)]
    key: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let key = encoding::decode_key(&args.key, &args.encoding)?;
    let key: &[u8; 32] = &key[..].try_into()?;
    let keypair: Keypair = key.try_into()?;

    let mut cert = encoding::decode_cert(&args.cert, &args.encoding)?;
    let cert = Cert::from_slice(&mut cert);

    let sig: &[u8; SIGNATURE_SERIALIZED_LENGTH] = cert.get_sig()?.try_into()?;
    let sig: Signature = sig.into();

    let data = cert.get_signdata()?;

    print!("Checking signature ... ");
    if keypair.public.verify(data, &sig).is_ok() {
        println!("Success!");
    } else {
        println!("FAIL");
    }

    Ok(())
}

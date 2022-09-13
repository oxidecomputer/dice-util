use clap::Parser;
use dice_cert_tmpl::{encoding, Cert, Encoding};
use std::{io, io::Write, path::PathBuf};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// cert encoding: pem|der
    #[clap(long, default_value = "pem")]
    encoding: Encoding,

    /// Path to cert file.
    cert_path: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut cert = encoding::decode_cert(&args.cert_path, &args.encoding)?;
    let cert = Cert::from_slice(&mut cert);
    let sig = cert.get_sig()?;

    io::stdout().write_all(&sig)?;

    Ok(())
}

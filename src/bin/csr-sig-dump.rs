use clap::Parser;
use dice_cert_tmpl::{encoding, Csr, Encoding};
use std::{io, io::Write, path::PathBuf};

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

    let mut csr = encoding::decode_csr(&args.csr_path, &args.encoding)?;
    let csr = Csr::from_slice(&mut csr);
    let sig = csr.get_sig()?;

    io::stdout().write_all(&sig)?;

    Ok(())
}

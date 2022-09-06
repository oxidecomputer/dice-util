use clap::Parser;
use dice_cert_tmpl::{encoding, Csr, Encoding};
use std::{fs, io::Write, path::PathBuf};
use tempfile::NamedTempFile;

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
    let mut out = NamedTempFile::new()?;

    println!("{:?}", out.path());

    let mut csr = Csr::from_slice(&mut csr);

    writeln!(out, "const SIZE: usize = {};", csr.len())?;

    let (start, end) = csr.get_pub_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "PUB", start, end)?;
    csr.clear_range(start, end);

    let (start, end) = csr.get_subject_sn_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "SUBJECT_SN", start, end)?;
    csr.clear_range(start, end);

    let (start, end) = csr.get_sig_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "SIG", start, end)?;
    csr.clear_range(start, end);

    let (start, end) = csr.get_signdata_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "SIGNDATA", start, end)?;
    // don't clear sign data

    writeln!(out, "const CSR_TMPL: [u8; {}] = {};", csr.len(), csr)?;

    dice_cert_tmpl::rustfmt(out.path())?;
    let data = fs::read_to_string(out.path())?;

    println!("{}", data);

    Ok(())
}

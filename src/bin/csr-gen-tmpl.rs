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

    let (start, end) = csr.get_pub_offsets()?;
    writeln!(out, "const PUB_START: usize = {};", start)?;
    writeln!(out, "const PUB_END: usize = {};", end)?;
    writeln!(out, "const PUB_LENGTH: usize = {};", end - start)?;
    csr.clear_range(start, end);

    let (start, end) = csr.get_subject_sn_offsets()?;
    writeln!(out, "const SN_START: usize = {};", start)?;
    writeln!(out, "const SN_END: usize = {};", end)?;
    writeln!(out, "const SN_LENGTH: usize = {};", end - start)?;
    csr.clear_range(start, end);

    let (start, end) = csr.get_sig_offsets()?;
    writeln!(out, "const SIG_START: usize = {};", start)?;
    writeln!(out, "const SIG_END: usize = {};", end)?;
    writeln!(out, "const SIG_LENGTH: usize = {};", end - start)?;
    csr.clear_range(start, end);

    let (start, end) = csr.get_signdata_offsets()?;
    writeln!(out, "const SIGNDATA_START: usize = {};", start)?;
    writeln!(out, "const SIGNDATA_END: usize = {};", end)?;
    writeln!(out, "const SIGNDATA_LENGTH: usize = {};", end - start)?;

    writeln!(out, "const CSR_TMPL: [u8; {}] = {};", csr.len(), csr)?;

    dice_cert_tmpl::rustfmt(out.path())?;
    let data = fs::read_to_string(out.path())?;

    println!("{}", data);

    Ok(())
}

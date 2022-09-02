use clap::Parser;
use dice_cert_tmpl::{Csr, Encoding, MissingFieldError, encoding};
use std::{fs, io, io::Write, path::PathBuf, process};
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

    let mut csr_der = match args.csr_path.to_str() {
        Some(csr_path) => {
            encoding::decode_csr(csr_path, args.encoding).expect("decode_csr")
        }
        None => {
            eprintln!("Invalid path");
            process::exit(1);
        }
    };

    let mut out = NamedTempFile::new()?;
    
    println!("{:?}", out.path());

    let mut csr = Csr::from_slice(&mut csr_der);

    let (start, end) = csr.get_pub_offsets()?;
    writeln!(out, "const PUB_START: usize = {};", start);
    writeln!(out, "const PUB_END: usize = {};", end);
    writeln!(out, "const PUB_LENGTH: usize = {};", end - start);
    csr.clear_range(start, end);

    let (start, end) = csr.get_subject_sn_offsets()?;
    writeln!(out, "const SN_START: usize = {};", start);
    writeln!(out, "const SN_END: usize = {};", end);
    writeln!(out, "const SN_LENGTH: usize = {};", end - start);
    csr.clear_range(start, end);

    let (start, end) = csr.get_sig_offsets()?;
    writeln!(out, "const SIG_START: usize = {};", start);
    writeln!(out, "const SIG_END: usize = {};", end);
    writeln!(out, "const SIG_LENGTH: usize = {};", end - start);
    csr.clear_range(start, end);

    let (start, end) = csr.get_signdata_offsets()?;
    writeln!(out, "const SIGNDATA_START: usize = {};", start);
    writeln!(out, "const SIGNDATA_END: usize = {};", end);
    writeln!(out, "const SIGNDATA_LENGTH: usize = {};", end - start);

    writeln!(out, "const CSR_TMPL: [u8; {}] = {};", csr.len(), csr);

    dice_cert_tmpl::rustfmt(out.path());
    let data = fs::read_to_string(out.path())?;

    println!("{}", data);

    Ok(())
}

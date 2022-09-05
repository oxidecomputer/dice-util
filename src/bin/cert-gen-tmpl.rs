use clap::Parser;
use dice_cert_tmpl::{encoding, Cert, Encoding};
use std::{fs, io::Write, path::PathBuf};
use tempfile::NamedTempFile;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// cert input encoding: pem|der
    #[clap(long, default_value = "pem")]
    encoding: Encoding,

    /// Path to cert file.
    cert_path: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut cert = encoding::decode_cert(&args.cert_path, &args.encoding)?;
    let mut out = NamedTempFile::new()?;

    println!("{:?}", out.path());

    let mut cert = Cert::from_slice(&mut cert);

    writeln!(out, "const SIZE: usize = {};", cert.len())?;

    let (start, end) = cert.get_serial_number_offsets()?;
    writeln!(out, "const SERIAL_NUMBER_START: usize = {};", start)?;
    writeln!(out, "const SERIAL_NUMBER_LENGTH: usize = {};", end - start)?;
    writeln!(
        out,
        "const SERIAL_NUMBER_END: usize = \
             SERIAL_NUMBER_START + SERIAL_NUMBER_LENGTH;"
    )?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_issuer_sn_offsets()?;
    writeln!(out, "const ISSUER_SN_START: usize = {};", start)?;
    writeln!(out, "const ISSUER_SN_LENGTH: usize = {};", end - start)?;
    writeln!(
        out,
        "const ISSUER_SN_END: usize = ISSUER_SN_START + ISSUER_SN_LENGTH;"
    )?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_notbefore_offsets()?;
    writeln!(out, "const NOTBEFORE_START: usize = {};", start)?;
    writeln!(out, "const NOTBEFORE_LENGTH: usize = {};", end - start)?;
    writeln!(
        out,
        "const NOTBEFORE_END: usize = NOTBEFORE_START + NOTBEFORE_LENGTH;"
    )?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_subject_sn_offsets()?;
    writeln!(out, "const SUBJECT_SN_START: usize = {};", start)?;
    writeln!(out, "const SUBJECT_SN_LENGTH: usize = {};", end - start)?;
    writeln!(
        out,
        "const SUBJECT_SN_END: usize = SUBJECT_SN_START + SUBJECT_SN_LENGTH;"
    )?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_pub_offsets()?;
    writeln!(out, "const PUB_START: usize = {};", start)?;
    writeln!(out, "const PUB_LENGTH: usize = {};", end - start)?;
    writeln!(out, "const PUB_END: usize = PUB_START + PUB_LENGTH;")?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_sig_offsets()?;
    writeln!(out, "const SIG_START: usize = {};", start)?;
    writeln!(out, "const SIG_LENGTH: usize = {};", end - start)?;
    writeln!(out, "const SIG_END: usize = SIG_START + SIG_LENGTH;")?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_signdata_offsets()?;
    writeln!(out, "const SIGNDATA_START: usize = {};", start)?;
    writeln!(out, "const SIGNDATA_LENGTH: usize = {};", end - start)?;
    writeln!(
        out,
        "const SIGNDATA_END: usize = SIGNDATA_START + SIGNDATA_LENGTH;"
    )?;
    // don't clear signdata, it's the whole cert

    let (start, end) = cert.get_fwid_offsets()?;
    writeln!(out, "const FWID_START: usize = {};", start)?;
    writeln!(out, "const FWID_LENGTH: usize = {};", end - start)?;
    writeln!(out, "const FWID_END: usize = FWID_START + FWID_LENGTH;")?;
    cert.clear_range(start, end);

    writeln!(out, "const CERT_TMPL: [u8; {}] = {};", cert.len(), cert)?;

    dice_cert_tmpl::rustfmt(out.path())?;
    let data = fs::read_to_string(out.path())?;

    print!("{}", data);

    Ok(())
}

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
    dice_cert_tmpl::write_offsets(&mut out, "SERIAL_NUMBER", start, end)?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_issuer_sn_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "ISSUER_SN", start, end)?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_notbefore_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "NOTBEFORE", start, end)?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_subject_sn_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "SUBJECT_SN", start, end)?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_pub_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "PUB", start, end)?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_sig_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "SIG", start, end)?;
    cert.clear_range(start, end);

    let (start, end) = cert.get_signdata_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "SIGNDATA", start, end)?;
    // don't clear signdata, it's the whole cert

    let (start, end) = cert.get_fwid_offsets()?;
    dice_cert_tmpl::write_offsets(&mut out, "FWID", start, end)?;
    cert.clear_range(start, end);

    writeln!(out, "const CERT_TMPL: [u8; {}] = {};", cert.len(), cert)?;

    dice_cert_tmpl::rustfmt(out.path())?;
    let data = fs::read_to_string(out.path())?;

    print!("{}", data);

    Ok(())
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::anyhow;
use clap::{Parser, Subcommand};
use dice_cert_tmpl::{encoding, Cert, Csr, Encoding};
use dice_mfg_msgs::PLATFORM_ID_MAX_LEN;
use salty::{
    constants::{PUBLICKEY_SERIALIZED_LENGTH, SIGNATURE_SERIALIZED_LENGTH},
    signature::Signature,
    Keypair, PublicKey,
};
use std::{fs, io, io::Write, path::PathBuf, process};
use tempfile::NamedTempFile;

const LICENSE_TEXT: &str = " \
    // This Source Code Form is subject to the terms of the Mozilla Public\n\
    // License, v. 2.0. If a copy of the MPL was not distributed with this\n\
    // file, You can obtain one at https://mozilla.org/MPL/2.0/.\n";

const ORIGIN_TEXT: &str = " \
    // NOTE: This DER blob, offsets & lengths are generated code. This\n\
    // is currently accomplished by an external tool:\n\
    // https://github.com/oxidecomputer/dice-util\n\
    // TODO: Generate cert templates in-tree.\n";

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// cert encoding: pem|der
    #[clap(long, default_value = "pem")]
    encoding: Encoding,

    /// command
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Cert {
        #[command(subcommand)]
        sub_command: CertSubCommand,
    },
    Csr {
        #[command(subcommand)]
        sub_command: CsrSubCommand,
    },
}

#[derive(Subcommand, Debug)]
enum CertSubCommand {
    CheckSig {
        /// Path to Cert / CSR file.
        path: PathBuf,

        /// Path to key file.
        #[clap(long)]
        key: PathBuf,

        /// Key file encoding.
        #[clap(long, default_value = "pem")]
        key_form: Encoding,
    },
    DumpPub {
        /// Path to file.
        path: PathBuf,
    },
    DumpSig {
        /// Path to file.
        path: PathBuf,
    },
    TmplGen {
        /// Path to file.
        path: PathBuf,

        /// Cert has FWID field
        #[clap(long)]
        fwid: bool,

        /// Cert has issuer with CN
        #[clap(long)]
        issuer_cn: bool,

        /// Cert has subject with CN
        #[clap(long)]
        subject_cn: bool,
    },
}

// This enum differs from CertSubCommand only in the CheckSig variant.
// CSRs are signed by the private key associated with the public key in the
// CSR. This means we don't need the key to be provided separately: we just
// extract the public key from the CSR and use that to check the signature.
#[derive(Subcommand, Debug)]
enum CsrSubCommand {
    CheckSig {
        /// Path to Cert / CSR file.
        path: PathBuf,
    },
    DumpPub {
        /// Path to file.
        path: PathBuf,
    },
    DumpSig {
        /// Path to file.
        path: PathBuf,
    },
    TmplGen {
        /// Path to file.
        path: PathBuf,

        /// Cert has subject with CN
        #[clap(long)]
        subject_cn: bool,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Command::Cert { sub_command } => match sub_command {
            CertSubCommand::CheckSig {
                path,
                key,
                key_form,
            } => {
                let key = encoding::decode_key(&key, &key_form)?;
                let key: &[u8; 32] = &key[..].try_into()?;
                let keypair: Keypair = key.into();

                let mut cert = encoding::decode_cert(&path, &args.encoding)?;
                let cert = Cert::from_slice(&mut cert);

                let sig: &[u8; SIGNATURE_SERIALIZED_LENGTH] =
                    cert.get_sig()?.try_into()?;
                let sig: Signature = sig.into();

                let data = cert.get_signdata()?;

                print!("Checking signature ... ");
                if keypair.public.verify(data, &sig).is_ok() {
                    println!("Success!");
                    Ok(())
                } else {
                    println!("FAIL");
                    process::exit(1);
                }
            }
            CertSubCommand::DumpPub { path } => {
                let mut cert = encoding::decode_cert(&path, &args.encoding)?;
                let cert = Cert::from_slice(&mut cert);
                let pubkey = cert.get_pub()?;

                Ok(io::stdout().write_all(pubkey)?)
            }
            CertSubCommand::DumpSig { path } => {
                let mut cert = encoding::decode_cert(&path, &args.encoding)?;
                let cert = Cert::from_slice(&mut cert);
                let sig = cert.get_sig()?;

                Ok(io::stdout().write_all(sig)?)
            }
            CertSubCommand::TmplGen {
                fwid,
                path,
                issuer_cn,
                subject_cn,
            } => {
                let mut cert = encoding::decode_cert(&path, &args.encoding)?;
                let mut out = NamedTempFile::new()?;

                let mut cert = Cert::from_slice(&mut cert);

                writeln!(out, "{}\n", LICENSE_TEXT)?;
                writeln!(out, "use core::ops::Range;\n")?;
                writeln!(out, "{}\n", ORIGIN_TEXT)?;
                writeln!(out, "pub const SIZE: usize = {};", cert.len())?;

                let range = cert.get_serial_number_offsets()?;
                dice_cert_tmpl::write_range(
                    &mut out,
                    "SERIAL_NUMBER",
                    range.start,
                    range.end,
                )?;
                cert.clear_range(range.start, range.end);

                if issuer_cn {
                    let range = cert.get_issuer_cn_offsets()?.ok_or(
                        anyhow!("No Issuer or Issuer commonName found"),
                    )?;
                    dice_cert_tmpl::write_range(
                        &mut out,
                        "ISSUER_CN",
                        range.start,
                        range.end,
                    )?;
                    cert.clear_range(range.start, range.end);
                }

                if subject_cn {
                    let range = cert.get_subject_cn_offsets()?.ok_or(
                        anyhow!("No Subject or Subject commonName found"),
                    )?;
                    dice_cert_tmpl::write_range(
                        &mut out,
                        "SUBJECT_CN",
                        range.start,
                        range.end,
                    )?;
                    cert.clear_range(range.start, range.end);
                }

                let range = cert.get_pub_offsets()?;
                dice_cert_tmpl::write_range(
                    &mut out,
                    "PUB",
                    range.start,
                    range.end,
                )?;
                cert.clear_range(range.start, range.end);

                let range = cert.get_sig_offsets()?;
                dice_cert_tmpl::write_range(
                    &mut out,
                    "SIG",
                    range.start,
                    range.end,
                )?;
                cert.clear_range(range.start, range.end);

                let range = cert.get_signdata_offsets()?;
                dice_cert_tmpl::write_range(
                    &mut out,
                    "SIGNDATA",
                    range.start,
                    range.end,
                )?;
                // don't clear signdata, it's the whole cert

                if fwid {
                    let offsets = cert.get_fwids_offsets()?;
                    if offsets.is_empty() {
                        return Err(anyhow!(
                            "FWID offsets requested but none found"
                        )
                        .into());
                    }
                    if offsets.len() > 1 {
                        return Err(anyhow!(
                            "FWID offsets requested but none found"
                        )
                        .into());
                    }

                    dice_cert_tmpl::write_range(
                        &mut out,
                        "FWID",
                        offsets[0].start,
                        offsets[0].end,
                    )?;
                    cert.clear_range(offsets[0].start, offsets[0].end);
                }

                writeln!(
                    out,
                    "pub const CERT_TMPL: [u8; {}] = {};",
                    cert.len(),
                    cert
                )?;

                dice_cert_tmpl::rustfmt(out.path())?;
                let data = fs::read_to_string(out.path())?;

                print!("{}", data);

                Ok(())
            }
        },
        Command::Csr { sub_command } => match sub_command {
            CsrSubCommand::CheckSig { path } => {
                let mut csr = encoding::decode_csr(&path, &args.encoding)?;
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
                    Ok(())
                } else {
                    println!("FAIL");
                    process::exit(1);
                }
            }
            CsrSubCommand::DumpPub { path } => {
                let mut csr = encoding::decode_csr(&path, &args.encoding)?;
                let csr = Csr::from_slice(&mut csr);
                let pubkey = csr.get_pub()?;

                Ok(io::stdout().write_all(pubkey)?)
            }
            CsrSubCommand::DumpSig { path } => {
                let mut csr = encoding::decode_csr(&path, &args.encoding)?;
                let csr = Csr::from_slice(&mut csr);
                let sig = csr.get_sig()?;

                Ok(io::stdout().write_all(sig)?)
            }
            CsrSubCommand::TmplGen { path, subject_cn } => {
                let mut csr = encoding::decode_csr(&path, &args.encoding)?;
                let mut out = NamedTempFile::new()?;

                let mut csr = Csr::from_slice(&mut csr);

                writeln!(out, "{}", LICENSE_TEXT)?;
                writeln!(out, "use core::ops::Range;\n")?;
                writeln!(out, "pub const SIZE: usize = {};", csr.len())?;

                let range = csr.get_pub_offsets()?;
                dice_cert_tmpl::write_range(
                    &mut out,
                    "PUB",
                    range.start,
                    range.end,
                )?;
                csr.clear_range(range.start, range.end);

                if subject_cn {
                    let range = csr.get_subject_cn_offsets()?.ok_or(
                        anyhow!("No Subject or Subject commonName found"),
                    )?;
                    dice_cert_tmpl::write_range(
                        &mut out,
                        "SUBJECT_CN",
                        range.start,
                        range.end,
                    )?;
                    csr.clear_range(range.start, range.end);
                    if range.len() > PLATFORM_ID_MAX_LEN {
                        return Err(anyhow!("The Subject commonName exceeds PLATFORM_ID_MAX_LEN").into());
                    }
                }

                let range = csr.get_sig_offsets()?;
                if range.len() != SIGNATURE_SERIALIZED_LENGTH {
                    return Err(anyhow!(
                        "Unexpected length for Signature in CSR,
                            expecting:{}, got: {}",
                        SIGNATURE_SERIALIZED_LENGTH,
                        range.len()
                    )
                    .into());
                }
                dice_cert_tmpl::write_range(
                    &mut out,
                    "SIG",
                    range.start,
                    range.end,
                )?;
                csr.clear_range(range.start, range.end);

                let range = csr.get_signdata_offsets()?;
                dice_cert_tmpl::write_range(
                    &mut out,
                    "SIGNDATA",
                    range.start,
                    range.end,
                )?;
                // don't clear sign data

                writeln!(
                    out,
                    "pub const CSR_TMPL: [u8; {}] = {};",
                    csr.len(),
                    csr
                )?;

                dice_cert_tmpl::rustfmt(out.path())?;
                let data = fs::read_to_string(out.path())?;

                println!("{}", data);

                Ok(())
            }
        },
    }
}

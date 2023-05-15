// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
use clap::{Parser, Subcommand};
use dice_mfg_msgs::PlatformId;
use env_logger::Builder;
use log::{info, LevelFilter};
use serialport::{DataBits, FlowControl, Parity, SerialPort, StopBits};
use std::{
    env::{self, VarError},
    path::PathBuf,
    result, str,
    time::Duration,
};
use yubihsm::object::Id;
use zeroize::Zeroizing;

use dice_mfg::{CertSignerBuilder, MfgDriver, DEFAULT_AUTH_ID, ENV_PASSWD};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
/// Send commands to the RoT for DeviceId certification.
struct Args {
    /// serial port device path
    #[clap(long, default_value = "/dev/ttyACM0", env = "DICE_MFG_SERIAL_DEV")]
    serial_dev: String,

    /// baud rate
    #[clap(long, default_value = "9600", env)]
    baud: u32,

    /// command
    #[command(subcommand)]
    command: Command,

    /// verbosity
    #[clap(long, env)]
    verbose: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Send the 'Break' message to attempt to end the manufacturing process.
    /// If the system being manufactured has not yet received all required
    /// data this message will be rejected.
    Break,
    /// Send the 'GetCsr' message to request a CSR from the system being
    /// manufactured. If the system being manufactured has not yet received
    /// the platform id (required to generate a CSR) this message will be
    /// rejected.
    GetCsr {
        /// Destination path for CSR, stdout if omitted
        csr_path: Option<PathBuf>,
    },
    /// Send 'Ping' messages to the system being manufactured until we
    /// successfully receive an 'Ack' or 'max_retry' attempts fail.
    Liveness {
        /// Maximum number of retries for failed pings.
        #[clap(default_value = "10")]
        max_retry: u8,
    },
    /// Perform device identity provisioning by exchanging the required
    /// messages with the device being manufactured.
    Manufacture {
        /// Auth ID used w/r YubiHSM.
        #[clap(long, env = "DICE_MFG_AUTH_ID", default_value_t = DEFAULT_AUTH_ID)]
        auth_id: Id,

        /// Path to openssl.cnf file used for signing operation.
        #[clap(long, env)]
        openssl_cnf: Option<PathBuf>,

        /// CA section from openssl.cnf used for signing operation.
        #[clap(long, env)]
        ca_section: Option<String>,

        /// x509 v3 extension section from openssl.cnf used for signing operation.
        #[clap(long, env)]
        v3_section: Option<String>,

        /// Engine config section from openssl.cnf used for signing operation.
        #[clap(long, env)]
        engine_section: Option<String>,

        /// Maximum number of retries for failed pings.
        #[clap(long, default_value = "10", env)]
        max_retry: u8,

        /// Path to intermediate cert to send.
        #[clap(long, env)]
        intermediate_cert: Option<PathBuf>,

        /// Platform identity string
        #[clap(value_parser = validate_pid, env = "DICE_MFG_PLATFORM_ID")]
        platform_id: PlatformId,

        /// Root directory for CA state. If provided the tool will chdir to
        /// this directory before executing openssl commands. This is
        /// intended to support openssl.cnf files that use relative paths.
        #[clap(long, env = "DICE_MFG_CA_ROOT")]
        ca_root: PathBuf,
    },
    /// Send a 'Ping' message to the system being manufactured.
    Ping,
    /// Send the device being manufactured its identity certificate in a
    /// 'DeviceIdCert' message.
    SetPlatformIdCert {
        /// Path to DeviceId cert to send.
        cert_in: PathBuf,
    },
    /// Send the device being manufactured the certificate for the certifying
    /// CA.
    SetIntermediateCert {
        /// Path to intermediate cert to send.
        cert_in: PathBuf,
    },
    /// Send the device being manufactured its assigned platform identifier
    /// in a 'PlatformId' message.
    SetPlatformId {
        /// Platform identifier.
        #[clap(value_parser = validate_pid, env = "DICE_MFG_PLATFORM_ID")]
        platform_id: PlatformId,
    },
    /// Turn a CSR into a cert. This is a thin wrapper around the `openssl ca`
    /// command and behavior will depend on the openssl.cnf provided by the
    /// caller.
    SignCert {
        /// Auth ID used w/r YubiHSM.
        #[clap(long, env = "DICE_MFG_AUTH_ID", default_value = "2")]
        auth_id: Id,

        /// Destination path for Cert.
        #[clap(long, env)]
        cert_out: PathBuf,

        /// Path to openssl.cnf file used for signing operation.
        #[clap(long, env)]
        openssl_cnf: Option<PathBuf>,

        /// CA section from openssl.cnf.
        #[clap(long, env)]
        ca_section: Option<String>,

        /// x509 v3 extension section from openssl.cnf.
        #[clap(long, env)]
        v3_section: Option<String>,

        /// Engine section from openssl.cnf.
        #[clap(long, env)]
        engine_section: Option<String>,

        /// Path to input CSR file.
        #[clap(long, env)]
        csr_in: PathBuf,

        /// Root directory for CA state. If provided the tool will chdir to
        /// this directory before executing openssl commands. This is
        /// intended to support openssl.cnf files that use relative paths.
        #[clap(long, env = "DICE_MFG_CA_ROOT")]
        ca_root: PathBuf,
    },
    DumpLogEntries {
        /// Auth ID used w/r YubiHSM.
        #[clap(long, env = "DICE_MFG_AUTH_ID", default_value = "2")]
        auth_id: u16,
    },
}

fn open_serial(serial_dev: &str, baud: u32) -> Result<Box<dyn SerialPort>> {
    Ok(serialport::new(serial_dev, baud)
        .timeout(Duration::from_secs(1))
        .data_bits(DataBits::Eight)
        .flow_control(FlowControl::None)
        .parity(Parity::None)
        .stop_bits(StopBits::One)
        .open()?)
}

/// Get password from environment if set. Else fall back to challenging the
/// user. Once we get the passwd from the user we set it in the env.
fn passwd_to_env() -> Result<()> {
    match env::var(ENV_PASSWD) {
        Ok(_) => Ok(()), // passwd is already preset in the env
        Err(VarError::NotPresent) => {
            let passwd = Zeroizing::new(rpassword::prompt_password(
                "Enter YubiHSM Password: ",
            )?);
            std::env::set_var(ENV_PASSWD, passwd);
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let mut builder = Builder::from_default_env();

    let level = if args.verbose {
        LevelFilter::Info
    } else {
        LevelFilter::Warn
    };
    builder.filter(None, level).init();

    if args.verbose {
        info!("device: {}, baud: {}", args.serial_dev, args.baud);
    }
    let driver = match args.command {
        Command::SignCert { .. } | Command::DumpLogEntries { .. } => None,
        _ => Some(MfgDriver::new(open_serial(&args.serial_dev, args.baud)?)),
    };
    // all variants except for `Command::SignCert` can safely unwrap `driver`
    match args.command {
        Command::Break => driver.unwrap().send_break(),
        Command::GetCsr { csr_path } => {
            driver.unwrap().get_csr(csr_path.as_ref())
        }
        Command::Liveness { max_retry } => driver.unwrap().liveness(max_retry),
        Command::Manufacture {
            auth_id,
            openssl_cnf,
            ca_section,
            v3_section,
            engine_section,
            max_retry,
            platform_id,
            intermediate_cert,
            ca_root,
        } => {
            passwd_to_env()?;
            let mut driver = driver.unwrap();

            driver.liveness(max_retry)?;
            driver.set_platform_id(platform_id)?;

            let csr =
                ca_root.join(format!("csr/{}.csr.pem", platform_id.as_str()?));
            driver.get_csr(Some(&csr))?;

            let temp_dir = tempfile::tempdir()?;
            let cert = temp_dir.into_path().join("cert.pem");
            let intermediate_cert = intermediate_cert
                .unwrap_or_else(|| ca_root.join("ca.cert.pem"));
            let cert_signer = CertSignerBuilder::new(ca_root)
                .set_auth_id(auth_id)
                .set_ca_section(ca_section)
                .set_engine_section(engine_section)
                .set_openssl_cnf(openssl_cnf)
                .set_v3_section(v3_section)
                .build();
            cert_signer.sign(&csr, &cert)?;
            driver.set_platform_id_cert(&cert)?;
            driver.set_intermediate_cert(&intermediate_cert)?;
            driver.send_break()
        }
        Command::Ping => driver.unwrap().ping(),
        Command::SetPlatformIdCert { cert_in } => {
            driver.unwrap().set_platform_id_cert(&cert_in)
        }
        Command::SetIntermediateCert { cert_in } => {
            driver.unwrap().set_intermediate_cert(&cert_in)
        }
        Command::SetPlatformId { platform_id } => {
            driver.unwrap().set_platform_id(platform_id)
        }
        Command::SignCert {
            auth_id,
            cert_out,
            openssl_cnf,
            ca_section,
            v3_section,
            engine_section,
            csr_in,
            ca_root,
        } => {
            passwd_to_env()?;
            let cert_signer = CertSignerBuilder::new(ca_root)
                .set_auth_id(auth_id)
                .set_ca_section(ca_section)
                .set_engine_section(engine_section)
                .set_openssl_cnf(openssl_cnf)
                .set_v3_section(v3_section)
                .build();
            cert_signer.sign(&csr_in, &cert_out)
        }
        Command::DumpLogEntries { auth_id } => {
            passwd_to_env()?;
            let index = dice_mfg::get_log_entries(auth_id)?;
            dice_mfg::set_log_index(auth_id, index)
        }
    }
}

pub fn validate_pid(s: &str) -> result::Result<PlatformId, String> {
    PlatformId::try_from(s).map_err(|e| format!("Invalid PlatformId: {:?}", e))
}

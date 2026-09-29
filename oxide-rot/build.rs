// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::Result;
cfg_if::cfg_if! {
    if #[cfg(feature = "unittest")] {
        use anyhow::{anyhow, Context};
        use pki_playground::{config, OutputFileExistsBehavior};
        use std::{env, fs, path::PathBuf};

        const PKI_CFG: &str = "test-pki.kdl";
    }
}

#[cfg(feature = "unittest")]
fn mock_log() -> Result<()> {
    use attest_mock::{MockData, MockLog};

    let mut out =
        PathBuf::from(env::var("OUT_DIR").context("Failed to get OUT_DIR")?);
    out.push("log.bin");

    let config = "log.kdl";
    let mock = MockLog::load(config)
        .with_context(|| format!("load mock log from file: {config}"))?;
    let mock = mock.to_bytes().context("mock log to bytes")?;

    Ok(fs::write(&out, &mock).with_context(|| {
        format!("write mock measurement log to file: {}", out.display())
    })?)
}

#[cfg(feature = "unittest")]
fn pki_setup() -> Result<()> {
    // output directory where we put generated test inputs
    let out =
        PathBuf::from(env::var("OUT_DIR").context("Failed to get OUT_DIR")?);

    let config_path = "test-pki.kdl";
    let doc = config::load_and_validate(PKI_CFG).map_err(|e| {
        anyhow!("Loading config from \"{}\" failed: {e:?}", config_path)
    })?;

    doc.write_key_pairs(&out, OutputFileExistsBehavior::Skip)
        .map_err(|e| anyhow!("write key pairs to {}: {e:?}", out.display()))?;
    doc.write_certificates(&out, OutputFileExistsBehavior::Skip)
        .map_err(|e| {
            anyhow!("write certificates to {}: {e:?}", out.display())
        })?;
    doc.write_certificate_lists(&out, OutputFileExistsBehavior::Skip)
        .map_err(|e| {
            anyhow!("write certificate chains to {}: {e:?}", out.display())
        })?;
    Ok(())
}

fn main() -> Result<()> {
    #[cfg(feature = "unittest")]
    pki_setup()?;
    #[cfg(feature = "unittest")]
    mock_log()?;

    Ok(())
}

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use anyhow::{anyhow, Context, Result};
use camino::Utf8PathBuf;
use pki_playground::{config, OutputFileExistsBehavior};

use std::env;

fn main() -> Result<()> {
    // output directory where we put:
    // generated test inputs
    let out = Utf8PathBuf::from(
        env::var("OUT_DIR").context("Failed to get OUT_DIR")?,
    );

    let config_path = "test-pki.kdl";
    let doc = config::load_and_validate(config_path.as_ref()).map_err(|e| {
        anyhow!("Loading config from \"{}\" failed: {e:?}", config_path)
    })?;

    doc.write_key_pairs(out.clone(), OutputFileExistsBehavior::Skip)
        .map_err(|e| anyhow!("write key pairs to {out}: {e:?}"))?;
    doc.write_certificates(out.clone(), OutputFileExistsBehavior::Skip)
        .map_err(|e| anyhow!("write certificates to {out}: {e:?}"))?;
    doc.write_certificate_lists(out.clone(), OutputFileExistsBehavior::Skip)
        .map_err(|e| anyhow!("write certificate chains to {out}: {e:?}"))?;

    Ok(())
}

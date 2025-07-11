// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// This path is where Oxide specific libraries live on helios systems.
/// This is needed for linking with libipcc
#[cfg(all(feature = "ipcc", target_os = "illumos"))]
static OXIDE_PLATFORM: &str = "/usr/platform/oxide/lib/amd64/";

fn main() {
    #[cfg(all(feature = "ipcc", target_os = "illumos"))]
    {
        println!("cargo:rustc-link-arg=-Wl,-R{}", OXIDE_PLATFORM);
        println!("cargo:rustc-link-search={}", OXIDE_PLATFORM);
    }
}

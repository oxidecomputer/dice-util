// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use clap::ValueEnum;
use std::fmt;

#[derive(Clone, Debug, ValueEnum)]
pub enum Kind {
    LogEntries,
    LogEntry,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Kind::LogEntries => write!(f, "LogEntries"),
            Kind::LogEntry => write!(f, "LogEntry"),
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum Encoding {
    // The binary serializer from upstream is not exposed publicly.
    // We maintain a patch here:
    // https://github.com/oxidecomputer/yubihsm.rs/tree/v0.42.0-with-audit
    Bin,
    Json,
    Ron,
}

impl fmt::Display for Encoding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Encoding::Bin => write!(f, "bin"),
            Encoding::Json => write!(f, "json"),
            Encoding::Ron => write!(f, "ron"),
        }
    }
}

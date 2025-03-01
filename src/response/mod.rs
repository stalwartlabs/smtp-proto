/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::fmt::Display;

use crate::tokens::define_tokens_128;
use crate::{EhloResponse, Response};

pub mod generate;
pub mod parser;

define_tokens_128! {
    _8BITMIME = "8BITMIME",
    ATRN,
    AUTH,
    BINARYMIME,
    BURL,
    CHECKPOINT,
    CHUNKING,
    CONNEG,
    CONPERM,
    DELIVERBY,
    DSN,
    ENHANCEDSTATUSCO,
    ETRN,
    EXPN,
    VRFY,
    FUTURERELEASE,
    HELP,
    MT_PRIORITY = "MT-PRIORITY",
    MTRK,
    NO_SOLICITING = "NO-SOLICITING",
    ONEX,
    PIPELINING,
    REQUIRETLS,
    RRVS,
    SIZE,
    SMTPUTF8,
    STARTTLS,
    VERB,

    // Priorities
    MIXER,
    STANAG4406,
    NSEP,
}

impl<T: Display> EhloResponse<T> {
    /// Returns the hostname of the SMTP server.
    pub fn hostname(&self) -> &T {
        &self.hostname
    }

    /// Returns the capabilities of the SMTP server.
    pub fn capabilities(&self) -> u32 {
        self.capabilities
    }

    /// Returns `true` if the SMTP server supports a given extension.
    pub fn has_capability(&self, capability: u32) -> bool {
        (self.capabilities & capability) != 0
    }

    /// Returns all supported authentication mechanisms.
    pub fn auth(&self) -> u64 {
        self.auth_mechanisms
    }
}

impl<T: Display> Display for Response<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Code: {}, Enhanced code: {}.{}.{}, Message: {}",
            self.code, self.esc[0], self.esc[1], self.esc[2], self.message,
        )
    }
}

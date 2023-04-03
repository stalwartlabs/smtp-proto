/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP protocol parser.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

use std::fmt::Display;

use crate::{EhloResponse, Response};
use crate::tokens::define_tokens_128;

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

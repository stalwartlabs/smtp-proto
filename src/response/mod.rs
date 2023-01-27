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

pub mod generate;
pub mod parser;

pub(crate) const _8BITMIME: u128 = (b'8' as u128)
    | (b'B' as u128) << 8
    | (b'I' as u128) << 16
    | (b'T' as u128) << 24
    | (b'M' as u128) << 32
    | (b'I' as u128) << 40
    | (b'M' as u128) << 48
    | (b'E' as u128) << 56;
pub(crate) const ATRN: u128 =
    (b'A' as u128) | (b'T' as u128) << 8 | (b'R' as u128) << 16 | (b'N' as u128) << 24;
pub(crate) const AUTH: u128 =
    (b'A' as u128) | (b'U' as u128) << 8 | (b'T' as u128) << 16 | (b'H' as u128) << 24;
pub(crate) const BINARYMIME: u128 = (b'B' as u128)
    | (b'I' as u128) << 8
    | (b'N' as u128) << 16
    | (b'A' as u128) << 24
    | (b'R' as u128) << 32
    | (b'Y' as u128) << 40
    | (b'M' as u128) << 48
    | (b'I' as u128) << 56
    | (b'M' as u128) << 64
    | (b'E' as u128) << 72;
pub(crate) const BURL: u128 =
    (b'B' as u128) | (b'U' as u128) << 8 | (b'R' as u128) << 16 | (b'L' as u128) << 24;
pub(crate) const CHECKPOINT: u128 = (b'C' as u128)
    | (b'H' as u128) << 8
    | (b'E' as u128) << 16
    | (b'C' as u128) << 24
    | (b'K' as u128) << 32
    | (b'P' as u128) << 40
    | (b'O' as u128) << 48
    | (b'I' as u128) << 56
    | (b'N' as u128) << 64
    | (b'T' as u128) << 72;
pub(crate) const CHUNKING: u128 = (b'C' as u128)
    | (b'H' as u128) << 8
    | (b'U' as u128) << 16
    | (b'N' as u128) << 24
    | (b'K' as u128) << 32
    | (b'I' as u128) << 40
    | (b'N' as u128) << 48
    | (b'G' as u128) << 56;
pub(crate) const CONNEG: u128 = (b'C' as u128)
    | (b'O' as u128) << 8
    | (b'N' as u128) << 16
    | (b'N' as u128) << 24
    | (b'E' as u128) << 32
    | (b'G' as u128) << 40;
pub(crate) const CONPERM: u128 = (b'C' as u128)
    | (b'O' as u128) << 8
    | (b'N' as u128) << 16
    | (b'P' as u128) << 24
    | (b'E' as u128) << 32
    | (b'R' as u128) << 40
    | (b'M' as u128) << 48;
pub(crate) const DELIVERBY: u128 = (b'D' as u128)
    | (b'E' as u128) << 8
    | (b'L' as u128) << 16
    | (b'I' as u128) << 24
    | (b'V' as u128) << 32
    | (b'E' as u128) << 40
    | (b'R' as u128) << 48
    | (b'B' as u128) << 56
    | (b'Y' as u128) << 64;
pub(crate) const DSN: u128 = (b'D' as u128) | (b'S' as u128) << 8 | (b'N' as u128) << 16;
pub(crate) const ENHANCEDSTATUSCO: u128 = (b'E' as u128)
    | (b'N' as u128) << 8
    | (b'H' as u128) << 16
    | (b'A' as u128) << 24
    | (b'N' as u128) << 32
    | (b'C' as u128) << 40
    | (b'E' as u128) << 48
    | (b'D' as u128) << 56
    | (b'S' as u128) << 64
    | (b'T' as u128) << 72
    | (b'A' as u128) << 80
    | (b'T' as u128) << 88
    | (b'U' as u128) << 96
    | (b'S' as u128) << 104
    | (b'C' as u128) << 112
    | (b'O' as u128) << 120;
pub(crate) const ETRN: u128 =
    (b'E' as u128) | (b'T' as u128) << 8 | (b'R' as u128) << 16 | (b'N' as u128) << 24;
pub(crate) const EXPN: u128 =
    (b'E' as u128) | (b'X' as u128) << 8 | (b'P' as u128) << 16 | (b'N' as u128) << 24;
pub(crate) const VRFY: u128 =
    (b'V' as u128) | (b'R' as u128) << 8 | (b'F' as u128) << 16 | (b'Y' as u128) << 24;
pub(crate) const FUTURERELEASE: u128 = (b'F' as u128)
    | (b'U' as u128) << 8
    | (b'T' as u128) << 16
    | (b'U' as u128) << 24
    | (b'R' as u128) << 32
    | (b'E' as u128) << 40
    | (b'R' as u128) << 48
    | (b'E' as u128) << 56
    | (b'L' as u128) << 64
    | (b'E' as u128) << 72
    | (b'A' as u128) << 80
    | (b'S' as u128) << 88
    | (b'E' as u128) << 96;
pub(crate) const HELP: u128 =
    (b'H' as u128) | (b'E' as u128) << 8 | (b'L' as u128) << 16 | (b'P' as u128) << 24;
pub(crate) const MT_PRIORITY: u128 = (b'M' as u128)
    | (b'T' as u128) << 8
    | (b'-' as u128) << 16
    | (b'P' as u128) << 24
    | (b'R' as u128) << 32
    | (b'I' as u128) << 40
    | (b'O' as u128) << 48
    | (b'R' as u128) << 56
    | (b'I' as u128) << 64
    | (b'T' as u128) << 72
    | (b'Y' as u128) << 80;
pub(crate) const MTRK: u128 =
    (b'M' as u128) | (b'T' as u128) << 8 | (b'R' as u128) << 16 | (b'K' as u128) << 24;
pub(crate) const NO_SOLICITING: u128 = (b'N' as u128)
    | (b'O' as u128) << 8
    | (b'-' as u128) << 16
    | (b'S' as u128) << 24
    | (b'O' as u128) << 32
    | (b'L' as u128) << 40
    | (b'I' as u128) << 48
    | (b'C' as u128) << 56
    | (b'I' as u128) << 64
    | (b'T' as u128) << 72
    | (b'I' as u128) << 80
    | (b'N' as u128) << 88
    | (b'G' as u128) << 96;
pub(crate) const ONEX: u128 =
    (b'O' as u128) | (b'N' as u128) << 8 | (b'E' as u128) << 16 | (b'X' as u128) << 24;
pub(crate) const PIPELINING: u128 = (b'P' as u128)
    | (b'I' as u128) << 8
    | (b'P' as u128) << 16
    | (b'E' as u128) << 24
    | (b'L' as u128) << 32
    | (b'I' as u128) << 40
    | (b'N' as u128) << 48
    | (b'I' as u128) << 56
    | (b'N' as u128) << 64
    | (b'G' as u128) << 72;
pub(crate) const REQUIRETLS: u128 = (b'R' as u128)
    | (b'E' as u128) << 8
    | (b'Q' as u128) << 16
    | (b'U' as u128) << 24
    | (b'I' as u128) << 32
    | (b'R' as u128) << 40
    | (b'E' as u128) << 48
    | (b'T' as u128) << 56
    | (b'L' as u128) << 64
    | (b'S' as u128) << 72;
pub(crate) const RRVS: u128 =
    (b'R' as u128) | (b'R' as u128) << 8 | (b'V' as u128) << 16 | (b'S' as u128) << 24;
pub(crate) const SIZE: u128 =
    (b'S' as u128) | (b'I' as u128) << 8 | (b'Z' as u128) << 16 | (b'E' as u128) << 24;
pub(crate) const SMTPUTF8: u128 = (b'S' as u128)
    | (b'M' as u128) << 8
    | (b'T' as u128) << 16
    | (b'P' as u128) << 24
    | (b'U' as u128) << 32
    | (b'T' as u128) << 40
    | (b'F' as u128) << 48
    | (b'8' as u128) << 56;
pub(crate) const STARTTLS: u128 = (b'S' as u128)
    | (b'T' as u128) << 8
    | (b'A' as u128) << 16
    | (b'R' as u128) << 24
    | (b'T' as u128) << 32
    | (b'T' as u128) << 40
    | (b'L' as u128) << 48
    | (b'S' as u128) << 56;
pub(crate) const VERB: u128 =
    (b'V' as u128) | (b'E' as u128) << 8 | (b'R' as u128) << 16 | (b'B' as u128) << 24;

// Priorities
pub(crate) const MIXER: u128 = (b'M' as u128)
    | (b'I' as u128) << 8
    | (b'X' as u128) << 16
    | (b'E' as u128) << 24
    | (b'R' as u128) << 32;
pub(crate) const STANAG4406: u128 = (b'S' as u128)
    | (b'T' as u128) << 8
    | (b'A' as u128) << 16
    | (b'N' as u128) << 24
    | (b'A' as u128) << 32
    | (b'G' as u128) << 40
    | (b'4' as u128) << 48
    | (b'4' as u128) << 56
    | (b'0' as u128) << 64
    | (b'6' as u128) << 72;
pub(crate) const NSEP: u128 =
    (b'N' as u128) | (b'S' as u128) << 8 | (b'E' as u128) << 16 | (b'P' as u128) << 24;

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

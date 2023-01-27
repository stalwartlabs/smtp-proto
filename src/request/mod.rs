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

pub mod parser;
pub mod receiver;

// SMTP commands
pub(crate) const EHLO: u64 =
    (b'E' as u64) | (b'H' as u64) << 8 | (b'L' as u64) << 16 | (b'O' as u64) << 24;
pub(crate) const HELO: u64 =
    (b'H' as u64) | (b'E' as u64) << 8 | (b'L' as u64) << 16 | (b'O' as u64) << 24;
pub(crate) const LHLO: u64 =
    (b'L' as u64) | (b'H' as u64) << 8 | (b'L' as u64) << 16 | (b'O' as u64) << 24;
pub(crate) const MAIL: u64 =
    (b'M' as u64) | (b'A' as u64) << 8 | (b'I' as u64) << 16 | (b'L' as u64) << 24;
pub(crate) const RCPT: u64 =
    (b'R' as u64) | (b'C' as u64) << 8 | (b'P' as u64) << 16 | (b'T' as u64) << 24;
pub(crate) const DATA: u64 =
    (b'D' as u64) | (b'A' as u64) << 8 | (b'T' as u64) << 16 | (b'A' as u64) << 24;
pub(crate) const BDAT: u64 =
    (b'B' as u64) | (b'D' as u64) << 8 | (b'A' as u64) << 16 | (b'T' as u64) << 24;
pub(crate) const RSET: u64 =
    (b'R' as u64) | (b'S' as u64) << 8 | (b'E' as u64) << 16 | (b'T' as u64) << 24;
pub(crate) const VRFY: u64 =
    (b'V' as u64) | (b'R' as u64) << 8 | (b'F' as u64) << 16 | (b'Y' as u64) << 24;
pub(crate) const EXPN: u64 =
    (b'E' as u64) | (b'X' as u64) << 8 | (b'P' as u64) << 16 | (b'N' as u64) << 24;
pub(crate) const HELP: u64 =
    (b'H' as u64) | (b'E' as u64) << 8 | (b'L' as u64) << 16 | (b'P' as u64) << 24;
pub(crate) const NOOP: u64 =
    (b'N' as u64) | (b'O' as u64) << 8 | (b'O' as u64) << 16 | (b'P' as u64) << 24;
pub(crate) const QUIT: u64 =
    (b'Q' as u64) | (b'U' as u64) << 8 | (b'I' as u64) << 16 | (b'T' as u64) << 24;
pub(crate) const ETRN: u64 =
    (b'E' as u64) | (b'T' as u64) << 8 | (b'R' as u64) << 16 | (b'N' as u64) << 24;
pub(crate) const ATRN: u64 =
    (b'A' as u64) | (b'T' as u64) << 8 | (b'R' as u64) << 16 | (b'N' as u64) << 24;
pub const AUTH: u64 =
    (b'A' as u64) | (b'U' as u64) << 8 | (b'T' as u64) << 16 | (b'H' as u64) << 24;
pub(crate) const BURL: u64 =
    (b'B' as u64) | (b'U' as u64) << 8 | (b'R' as u64) << 16 | (b'L' as u64) << 24;
pub(crate) const STARTTLS: u64 = (b'S' as u64)
    | (b'T' as u64) << 8
    | (b'A' as u64) << 16
    | (b'R' as u64) << 24
    | (b'T' as u64) << 32
    | (b'T' as u64) << 40
    | (b'L' as u64) << 48
    | (b'S' as u64) << 56;

// Arguments
pub(crate) const FROM: u64 =
    (b'F' as u64) | (b'R' as u64) << 8 | (b'O' as u64) << 16 | (b'M' as u64) << 24;
pub(crate) const TO: u64 = (b'T' as u64) | (b'O' as u64) << 8;
pub(crate) const LAST: u64 =
    (b'L' as u64) | (b'A' as u64) << 8 | (b'S' as u64) << 16 | (b'T' as u64) << 24;

// Parameters
pub(crate) const BODY: u128 =
    (b'B' as u128) | (b'O' as u128) << 8 | (b'D' as u128) << 16 | (b'Y' as u128) << 24;
pub(crate) const SEVENBIT: u128 =
    (b'7' as u128) | (b'B' as u128) << 8 | (b'I' as u128) << 16 | (b'T' as u128) << 24;
pub(crate) const EIGHBITMIME: u128 = (b'8' as u128)
    | (b'B' as u128) << 8
    | (b'I' as u128) << 16
    | (b'T' as u128) << 24
    | (b'M' as u128) << 32
    | (b'I' as u128) << 40
    | (b'M' as u128) << 48
    | (b'E' as u128) << 56;
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
pub(crate) const SIZE: u128 =
    (b'S' as u128) | (b'I' as u128) << 8 | (b'Z' as u128) << 16 | (b'E' as u128) << 24;
pub(crate) const TRANSID: u128 = (b'T' as u128)
    | (b'R' as u128) << 8
    | (b'A' as u128) << 16
    | (b'N' as u128) << 24
    | (b'S' as u128) << 32
    | (b'I' as u128) << 40
    | (b'D' as u128) << 48;
pub(crate) const BY: u128 = (b'B' as u128) | (b'Y' as u128) << 8;

pub(crate) const N: u64 = b'N' as u64;
pub(crate) const NT: u64 = (b'N' as u64) | (b'T' as u64) << 8;
pub(crate) const C: u64 = b'C' as u64;
pub(crate) const R: u64 = b'R' as u64;
pub(crate) const RT: u64 = (b'R' as u64) | (b'T' as u64) << 8;

pub(crate) const NOTIFY: u128 = (b'N' as u128)
    | (b'O' as u128) << 8
    | (b'T' as u128) << 16
    | (b'I' as u128) << 24
    | (b'F' as u128) << 32
    | (b'Y' as u128) << 40;
pub(crate) const ORCPT: u128 = (b'O' as u128)
    | (b'R' as u128) << 8
    | (b'C' as u128) << 16
    | (b'P' as u128) << 24
    | (b'T' as u128) << 32;
pub(crate) const RFC822: u64 = (b'R' as u64)
    | (b'F' as u64) << 8
    | (b'C' as u64) << 16
    | (b'8' as u64) << 24
    | (b'2' as u64) << 32
    | (b'2' as u64) << 40;
pub(crate) const RET: u128 = (b'R' as u128) | (b'E' as u128) << 8 | (b'T' as u128) << 16;
pub(crate) const ENVID: u128 = (b'E' as u128)
    | (b'N' as u128) << 8
    | (b'V' as u128) << 16
    | (b'I' as u128) << 24
    | (b'D' as u128) << 32;
pub(crate) const NEVER: u128 = (b'N' as u128)
    | (b'E' as u128) << 8
    | (b'V' as u128) << 16
    | (b'E' as u128) << 24
    | (b'R' as u128) << 32;
pub(crate) const SUCCESS: u128 = (b'S' as u128)
    | (b'U' as u128) << 8
    | (b'C' as u128) << 16
    | (b'C' as u128) << 24
    | (b'E' as u128) << 32
    | (b'S' as u128) << 40
    | (b'S' as u128) << 48;
pub(crate) const FAILURE: u128 = (b'F' as u128)
    | (b'A' as u128) << 8
    | (b'I' as u128) << 16
    | (b'L' as u128) << 24
    | (b'U' as u128) << 32
    | (b'R' as u128) << 40
    | (b'E' as u128) << 48;
pub(crate) const DELAY: u128 = (b'D' as u128)
    | (b'E' as u128) << 8
    | (b'L' as u128) << 16
    | (b'A' as u128) << 24
    | (b'Y' as u128) << 32;
pub(crate) const FULL: u64 =
    (b'F' as u64) | (b'U' as u64) << 8 | (b'L' as u64) << 16 | (b'L' as u64) << 24;
pub(crate) const HDRS: u64 =
    (b'H' as u64) | (b'D' as u64) << 8 | (b'R' as u64) << 16 | (b'S' as u64) << 24;
pub(crate) const SOLICIT: u128 = (b'S' as u128)
    | (b'O' as u128) << 8
    | (b'L' as u128) << 16
    | (b'I' as u128) << 24
    | (b'C' as u128) << 32
    | (b'I' as u128) << 40
    | (b'T' as u128) << 48;
pub(crate) const MTRK: u128 =
    (b'M' as u128) | (b'T' as u128) << 8 | (b'R' as u128) << 16 | (b'K' as u128) << 24;
pub(crate) const AUTH_: u128 =
    (b'A' as u128) | (b'U' as u128) << 8 | (b'T' as u128) << 16 | (b'H' as u128) << 24;
pub(crate) const HOLDFOR: u128 = (b'H' as u128)
    | (b'O' as u128) << 8
    | (b'L' as u128) << 16
    | (b'D' as u128) << 24
    | (b'F' as u128) << 32
    | (b'O' as u128) << 40
    | (b'R' as u128) << 48;
pub(crate) const HOLDUNTIL: u128 = (b'H' as u128)
    | (b'O' as u128) << 8
    | (b'L' as u128) << 16
    | (b'D' as u128) << 24
    | (b'U' as u128) << 32
    | (b'N' as u128) << 40
    | (b'T' as u128) << 48
    | (b'I' as u128) << 56
    | (b'L' as u128) << 64;
pub(crate) const SMTPUTF8: u128 = (b'S' as u128)
    | (b'M' as u128) << 8
    | (b'T' as u128) << 16
    | (b'P' as u128) << 24
    | (b'U' as u128) << 32
    | (b'T' as u128) << 40
    | (b'F' as u128) << 48
    | (b'8' as u128) << 56;
pub(crate) const CONPERM: u128 = (b'C' as u128)
    | (b'O' as u128) << 8
    | (b'N' as u128) << 16
    | (b'P' as u128) << 24
    | (b'E' as u128) << 32
    | (b'R' as u128) << 40
    | (b'M' as u128) << 48;
pub(crate) const CONNEG: u128 = (b'C' as u128)
    | (b'O' as u128) << 8
    | (b'N' as u128) << 16
    | (b'N' as u128) << 24
    | (b'E' as u128) << 32
    | (b'G' as u128) << 40;
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
pub(crate) const RRVS: u128 =
    (b'R' as u128) | (b'R' as u128) << 8 | (b'V' as u128) << 16 | (b'S' as u128) << 24;
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

// SASL Mechanisms
pub(crate) const _9798_M_DSA_SHA1: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'M' as u128) << 40
    | (b'-' as u128) << 48
    | (b'D' as u128) << 56
    | (b'S' as u128) << 64
    | (b'A' as u128) << 72
    | (b'-' as u128) << 80
    | (b'S' as u128) << 88
    | (b'H' as u128) << 96
    | (b'A' as u128) << 104
    | (b'1' as u128) << 112;
pub(crate) const _9798_M_ECDSA_SHA: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'M' as u128) << 40
    | (b'-' as u128) << 48
    | (b'E' as u128) << 56
    | (b'C' as u128) << 64
    | (b'D' as u128) << 72
    | (b'S' as u128) << 80
    | (b'A' as u128) << 88
    | (b'-' as u128) << 96
    | (b'S' as u128) << 104
    | (b'H' as u128) << 112
    | (b'A' as u128) << 120;
pub(crate) const _9798_M_RSA_SHA1_: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'M' as u128) << 40
    | (b'-' as u128) << 48
    | (b'R' as u128) << 56
    | (b'S' as u128) << 64
    | (b'A' as u128) << 72
    | (b'-' as u128) << 80
    | (b'S' as u128) << 88
    | (b'H' as u128) << 96
    | (b'A' as u128) << 104
    | (b'1' as u128) << 112
    | (b'-' as u128) << 120;
pub(crate) const _9798_U_DSA_SHA1: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'U' as u128) << 40
    | (b'-' as u128) << 48
    | (b'D' as u128) << 56
    | (b'S' as u128) << 64
    | (b'A' as u128) << 72
    | (b'-' as u128) << 80
    | (b'S' as u128) << 88
    | (b'H' as u128) << 96
    | (b'A' as u128) << 104
    | (b'1' as u128) << 112;
pub(crate) const _9798_U_ECDSA_SHA: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'U' as u128) << 40
    | (b'-' as u128) << 48
    | (b'E' as u128) << 56
    | (b'C' as u128) << 64
    | (b'D' as u128) << 72
    | (b'S' as u128) << 80
    | (b'A' as u128) << 88
    | (b'-' as u128) << 96
    | (b'S' as u128) << 104
    | (b'H' as u128) << 112
    | (b'A' as u128) << 120;
pub(crate) const _9798_U_RSA_SHA1_: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'U' as u128) << 40
    | (b'-' as u128) << 48
    | (b'R' as u128) << 56
    | (b'S' as u128) << 64
    | (b'A' as u128) << 72
    | (b'-' as u128) << 80
    | (b'S' as u128) << 88
    | (b'H' as u128) << 96
    | (b'A' as u128) << 104
    | (b'1' as u128) << 112
    | (b'-' as u128) << 120;
pub(crate) const ANONYMOUS: u128 = (b'A' as u128)
    | (b'N' as u128) << 8
    | (b'O' as u128) << 16
    | (b'N' as u128) << 24
    | (b'Y' as u128) << 32
    | (b'M' as u128) << 40
    | (b'O' as u128) << 48
    | (b'U' as u128) << 56
    | (b'S' as u128) << 64;
pub(crate) const CRAM_MD5: u128 = (b'C' as u128)
    | (b'R' as u128) << 8
    | (b'A' as u128) << 16
    | (b'M' as u128) << 24
    | (b'-' as u128) << 32
    | (b'M' as u128) << 40
    | (b'D' as u128) << 48
    | (b'5' as u128) << 56;
pub(crate) const DIGEST_MD5: u128 = (b'D' as u128)
    | (b'I' as u128) << 8
    | (b'G' as u128) << 16
    | (b'E' as u128) << 24
    | (b'S' as u128) << 32
    | (b'T' as u128) << 40
    | (b'-' as u128) << 48
    | (b'M' as u128) << 56
    | (b'D' as u128) << 64
    | (b'5' as u128) << 72;
pub(crate) const EAP_AES128: u128 = (b'E' as u128)
    | (b'A' as u128) << 8
    | (b'P' as u128) << 16
    | (b'-' as u128) << 24
    | (b'A' as u128) << 32
    | (b'E' as u128) << 40
    | (b'S' as u128) << 48
    | (b'1' as u128) << 56
    | (b'2' as u128) << 64
    | (b'8' as u128) << 72;
pub(crate) const EAP_AES128_PLUS: u128 = (b'E' as u128)
    | (b'A' as u128) << 8
    | (b'P' as u128) << 16
    | (b'-' as u128) << 24
    | (b'A' as u128) << 32
    | (b'E' as u128) << 40
    | (b'S' as u128) << 48
    | (b'1' as u128) << 56
    | (b'2' as u128) << 64
    | (b'8' as u128) << 72
    | (b'-' as u128) << 80
    | (b'P' as u128) << 88
    | (b'L' as u128) << 96
    | (b'U' as u128) << 104
    | (b'S' as u128) << 112;
pub(crate) const ECDH_X25519_CHAL: u128 = (b'E' as u128)
    | (b'C' as u128) << 8
    | (b'D' as u128) << 16
    | (b'H' as u128) << 24
    | (b'-' as u128) << 32
    | (b'X' as u128) << 40
    | (b'2' as u128) << 48
    | (b'5' as u128) << 56
    | (b'5' as u128) << 64
    | (b'1' as u128) << 72
    | (b'9' as u128) << 80
    | (b'-' as u128) << 88
    | (b'C' as u128) << 96
    | (b'H' as u128) << 104
    | (b'A' as u128) << 112
    | (b'L' as u128) << 120;
pub(crate) const ECDSA_NIST256P_C: u128 = (b'E' as u128)
    | (b'C' as u128) << 8
    | (b'D' as u128) << 16
    | (b'S' as u128) << 24
    | (b'A' as u128) << 32
    | (b'-' as u128) << 40
    | (b'N' as u128) << 48
    | (b'I' as u128) << 56
    | (b'S' as u128) << 64
    | (b'T' as u128) << 72
    | (b'2' as u128) << 80
    | (b'5' as u128) << 88
    | (b'6' as u128) << 96
    | (b'P' as u128) << 104
    | (b'-' as u128) << 112
    | (b'C' as u128) << 120;
pub(crate) const EXTERNAL: u128 = (b'E' as u128)
    | (b'X' as u128) << 8
    | (b'T' as u128) << 16
    | (b'E' as u128) << 24
    | (b'R' as u128) << 32
    | (b'N' as u128) << 40
    | (b'A' as u128) << 48
    | (b'L' as u128) << 56;
pub(crate) const GS2_KRB5: u128 = (b'G' as u128)
    | (b'S' as u128) << 8
    | (b'2' as u128) << 16
    | (b'-' as u128) << 24
    | (b'K' as u128) << 32
    | (b'R' as u128) << 40
    | (b'B' as u128) << 48
    | (b'5' as u128) << 56;
pub(crate) const GS2_KRB5_PLUS: u128 = (b'G' as u128)
    | (b'S' as u128) << 8
    | (b'2' as u128) << 16
    | (b'-' as u128) << 24
    | (b'K' as u128) << 32
    | (b'R' as u128) << 40
    | (b'B' as u128) << 48
    | (b'5' as u128) << 56
    | (b'-' as u128) << 64
    | (b'P' as u128) << 72
    | (b'L' as u128) << 80
    | (b'U' as u128) << 88
    | (b'S' as u128) << 96;
pub(crate) const GSS_SPNEGO: u128 = (b'G' as u128)
    | (b'S' as u128) << 8
    | (b'S' as u128) << 16
    | (b'-' as u128) << 24
    | (b'S' as u128) << 32
    | (b'P' as u128) << 40
    | (b'N' as u128) << 48
    | (b'E' as u128) << 56
    | (b'G' as u128) << 64
    | (b'O' as u128) << 72;
pub(crate) const GSSAPI: u128 = (b'G' as u128)
    | (b'S' as u128) << 8
    | (b'S' as u128) << 16
    | (b'A' as u128) << 24
    | (b'P' as u128) << 32
    | (b'I' as u128) << 40;
pub(crate) const KERBEROS_V4: u128 = (b'K' as u128)
    | (b'E' as u128) << 8
    | (b'R' as u128) << 16
    | (b'B' as u128) << 24
    | (b'E' as u128) << 32
    | (b'R' as u128) << 40
    | (b'O' as u128) << 48
    | (b'S' as u128) << 56
    | (b'_' as u128) << 64
    | (b'V' as u128) << 72
    | (b'4' as u128) << 80;
pub(crate) const KERBEROS_V5: u128 = (b'K' as u128)
    | (b'E' as u128) << 8
    | (b'R' as u128) << 16
    | (b'B' as u128) << 24
    | (b'E' as u128) << 32
    | (b'R' as u128) << 40
    | (b'O' as u128) << 48
    | (b'S' as u128) << 56
    | (b'_' as u128) << 64
    | (b'V' as u128) << 72
    | (b'5' as u128) << 80;
pub(crate) const LOGIN: u128 = (b'L' as u128)
    | (b'O' as u128) << 8
    | (b'G' as u128) << 16
    | (b'I' as u128) << 24
    | (b'N' as u128) << 32;
pub(crate) const NMAS_SAMBA_AUTH: u128 = (b'N' as u128)
    | (b'M' as u128) << 8
    | (b'A' as u128) << 16
    | (b'S' as u128) << 24
    | (b'-' as u128) << 32
    | (b'S' as u128) << 40
    | (b'A' as u128) << 48
    | (b'M' as u128) << 56
    | (b'B' as u128) << 64
    | (b'A' as u128) << 72
    | (b'-' as u128) << 80
    | (b'A' as u128) << 88
    | (b'U' as u128) << 96
    | (b'T' as u128) << 104
    | (b'H' as u128) << 112;
pub(crate) const NMAS_AUTHEN: u128 = (b'N' as u128)
    | (b'M' as u128) << 8
    | (b'A' as u128) << 16
    | (b'S' as u128) << 24
    | (b'_' as u128) << 32
    | (b'A' as u128) << 40
    | (b'U' as u128) << 48
    | (b'T' as u128) << 56
    | (b'H' as u128) << 64
    | (b'E' as u128) << 72
    | (b'N' as u128) << 80;
pub(crate) const NMAS_LOGIN: u128 = (b'N' as u128)
    | (b'M' as u128) << 8
    | (b'A' as u128) << 16
    | (b'S' as u128) << 24
    | (b'_' as u128) << 32
    | (b'L' as u128) << 40
    | (b'O' as u128) << 48
    | (b'G' as u128) << 56
    | (b'I' as u128) << 64
    | (b'N' as u128) << 72;
pub(crate) const NTLM: u128 =
    (b'N' as u128) | (b'T' as u128) << 8 | (b'L' as u128) << 16 | (b'M' as u128) << 24;
pub(crate) const OAUTH10A: u128 = (b'O' as u128)
    | (b'A' as u128) << 8
    | (b'U' as u128) << 16
    | (b'T' as u128) << 24
    | (b'H' as u128) << 32
    | (b'1' as u128) << 40
    | (b'0' as u128) << 48
    | (b'A' as u128) << 56;
pub(crate) const OAUTHBEARER: u128 = (b'O' as u128)
    | (b'A' as u128) << 8
    | (b'U' as u128) << 16
    | (b'T' as u128) << 24
    | (b'H' as u128) << 32
    | (b'B' as u128) << 40
    | (b'E' as u128) << 48
    | (b'A' as u128) << 56
    | (b'R' as u128) << 64
    | (b'E' as u128) << 72
    | (b'R' as u128) << 80;
pub(crate) const OPENID20: u128 = (b'O' as u128)
    | (b'P' as u128) << 8
    | (b'E' as u128) << 16
    | (b'N' as u128) << 24
    | (b'I' as u128) << 32
    | (b'D' as u128) << 40
    | (b'2' as u128) << 48
    | (b'0' as u128) << 56;
pub(crate) const OTP: u128 = (b'O' as u128) | (b'T' as u128) << 8 | (b'P' as u128) << 16;
pub(crate) const PLAIN: u128 = (b'P' as u128)
    | (b'L' as u128) << 8
    | (b'A' as u128) << 16
    | (b'I' as u128) << 24
    | (b'N' as u128) << 32;
pub(crate) const SAML20: u128 = (b'S' as u128)
    | (b'A' as u128) << 8
    | (b'M' as u128) << 16
    | (b'L' as u128) << 24
    | (b'2' as u128) << 32
    | (b'0' as u128) << 40;
pub(crate) const SCRAM_SHA_1: u128 = (b'S' as u128)
    | (b'C' as u128) << 8
    | (b'R' as u128) << 16
    | (b'A' as u128) << 24
    | (b'M' as u128) << 32
    | (b'-' as u128) << 40
    | (b'S' as u128) << 48
    | (b'H' as u128) << 56
    | (b'A' as u128) << 64
    | (b'-' as u128) << 72
    | (b'1' as u128) << 80;
pub(crate) const SCRAM_SHA_1_PLUS: u128 = (b'S' as u128)
    | (b'C' as u128) << 8
    | (b'R' as u128) << 16
    | (b'A' as u128) << 24
    | (b'M' as u128) << 32
    | (b'-' as u128) << 40
    | (b'S' as u128) << 48
    | (b'H' as u128) << 56
    | (b'A' as u128) << 64
    | (b'-' as u128) << 72
    | (b'1' as u128) << 80
    | (b'-' as u128) << 88
    | (b'P' as u128) << 96
    | (b'L' as u128) << 104
    | (b'U' as u128) << 112
    | (b'S' as u128) << 120;
pub(crate) const SCRAM_SHA_256: u128 = (b'S' as u128)
    | (b'C' as u128) << 8
    | (b'R' as u128) << 16
    | (b'A' as u128) << 24
    | (b'M' as u128) << 32
    | (b'-' as u128) << 40
    | (b'S' as u128) << 48
    | (b'H' as u128) << 56
    | (b'A' as u128) << 64
    | (b'-' as u128) << 72
    | (b'2' as u128) << 80
    | (b'5' as u128) << 88
    | (b'6' as u128) << 96;
pub(crate) const SCRAM_SHA_256_PL: u128 = (b'S' as u128)
    | (b'C' as u128) << 8
    | (b'R' as u128) << 16
    | (b'A' as u128) << 24
    | (b'M' as u128) << 32
    | (b'-' as u128) << 40
    | (b'S' as u128) << 48
    | (b'H' as u128) << 56
    | (b'A' as u128) << 64
    | (b'-' as u128) << 72
    | (b'2' as u128) << 80
    | (b'5' as u128) << 88
    | (b'6' as u128) << 96
    | (b'-' as u128) << 104
    | (b'P' as u128) << 112
    | (b'L' as u128) << 120;
pub(crate) const SECURID: u128 = (b'S' as u128)
    | (b'E' as u128) << 8
    | (b'C' as u128) << 16
    | (b'U' as u128) << 24
    | (b'R' as u128) << 32
    | (b'I' as u128) << 40
    | (b'D' as u128) << 48;
pub(crate) const SKEY: u128 =
    (b'S' as u128) | (b'K' as u128) << 8 | (b'E' as u128) << 16 | (b'Y' as u128) << 24;
pub(crate) const SPNEGO: u128 = (b'S' as u128)
    | (b'P' as u128) << 8
    | (b'N' as u128) << 16
    | (b'E' as u128) << 24
    | (b'G' as u128) << 32
    | (b'O' as u128) << 40;
pub(crate) const SPNEGO_PLUS: u128 = (b'S' as u128)
    | (b'P' as u128) << 8
    | (b'N' as u128) << 16
    | (b'E' as u128) << 24
    | (b'G' as u128) << 32
    | (b'O' as u128) << 40
    | (b'-' as u128) << 48
    | (b'P' as u128) << 56
    | (b'L' as u128) << 64
    | (b'U' as u128) << 72
    | (b'S' as u128) << 80;
pub(crate) const SXOVER_PLUS: u128 = (b'S' as u128)
    | (b'X' as u128) << 8
    | (b'O' as u128) << 16
    | (b'V' as u128) << 24
    | (b'E' as u128) << 32
    | (b'R' as u128) << 40
    | (b'-' as u128) << 48
    | (b'P' as u128) << 56
    | (b'L' as u128) << 64
    | (b'U' as u128) << 72
    | (b'S' as u128) << 80;
pub(crate) const XOAUTH: u128 = (b'X' as u128)
    | (b'O' as u128) << 8
    | (b'A' as u128) << 16
    | (b'U' as u128) << 24
    | (b'T' as u128) << 32
    | (b'H' as u128) << 40;
pub(crate) const XOAUTH2: u128 = (b'X' as u128)
    | (b'O' as u128) << 8
    | (b'A' as u128) << 16
    | (b'U' as u128) << 24
    | (b'T' as u128) << 32
    | (b'H' as u128) << 40
    | (b'2' as u128) << 48;

/*
 * Adapted from Daniel Lemire's source:
 * https://github.com/lemire/Code-used-on-Daniel-Lemire-s-blog/blob/master/2019/04/17/hexparse.cpp
 *
 */

pub(crate) static HEX_MAP: &[i8] = &[
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10,
    11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

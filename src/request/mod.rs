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

use crate::tokens::{define_tokens_64, define_tokens_128};

pub mod parser;
pub mod receiver;

pub const AUTH: u64 = crate::tokens::token64("AUTH"); // special, because it is `pub` instead of `pub(crate)`

define_tokens_64! {
    // SMTP commands
    EHLO,
    HELO,
    LHLO,
    MAIL,
    RCPT,
    DATA,
    BDAT,
    RSET,
    VRFY,
    EXPN,
    HELP,
    NOOP,
    QUIT,
    ETRN,
    ATRN,
    BURL,
    STARTTLS,

    // Arguments
    FROM,
    TO,
    LAST,

    // Parameters
    N,
    NT,
    C,
    R,
    RT,
    FULL,
    HDRS,
    RFC822,
}

define_tokens_128! {
    // Parameters
    BODY,
    SEVENBIT = "7BIT",
    EIGHBITMIME = "8BITMIME",
    BINARYMIME,
    SIZE,
    TRANSID,
    BY,
    NOTIFY,
    ORCPT,
    RET,
    ENVID,
    NEVER,
    SUCCESS,
    FAILURE,
    DELAY,
    SOLICIT,
    MTRK,
    AUTH_ = "AUTH",
    HOLDFOR,
    HOLDUNTIL,
    SMTPUTF8,
    CONPERM,
    CONNEG,
    MT_PRIORITY = "MT-PRIORITY",
    RRVS,
    REQUIRETLS,
    _9798_M_DSA_SHA1 = "9798-M-DSA-SHA1",
    _9798_M_ECDSA_SHA = "9798-M-ECDSA-SHA",
    _9798_M_RSA_SHA1_ = "9798-M-RSA-SHA1-",
    _9798_U_DSA_SHA1 = "9798-U-DSA-SHA1",
    _9798_U_ECDSA_SHA = "9798-U-ECDSA-SHA",
    _9798_U_RSA_SHA1_ = "9798-U-RSA-SHA1-",
    ANONYMOUS,
    CRAM_MD5 = "CRAM-MD5",
    DIGEST_MD5 = "DIGEST-MD5",
    EAP_AES128 = "EAP-AES128",
    EAP_AES128_PLUS = "EAP-AES128-PLUS",
    ECDH_X25519_CHAL = "ECDH-X25519-CHAL",
    ECDSA_NIST256P_C = "ECDSA-NIST256P-C",
    EXTERNAL,
    GS2_KRB5 = "GS2-KRB5",
    GS2_KRB5_PLUS = "GS2-KRB5-PLUS",
    GSS_SPNEGO = "GSS-SPNEGO",
    GSSAPI,
    KERBEROS_V4 = "KERBEROS-V4",
    KERBEROS_V5 = "KERBEROS-V5",
    LOGIN,
    NMAS_SAMBA_AUTH = "NMAS-SAMBA-AUTH",
    NMAS_AUTHEN = "NMAS-AUTHEN",
    NMAS_LOGIN = "NMAS-LOGIN",
    NTLM,
    OAUTH10A,
    OAUTHBEARER,
    OPENID20,
    OTP,
    PLAIN,
    SAML20,
    SCRAM_SHA_1 = "SCRAM-SHA-1",
    SCRAM_SHA_1_PLUS = "SCRAM-SHA-1-PLUS",
    SCRAM_SHA_256 = "SCRAM-SHA-256",
    SCRAM_SHA_256_PL = "SCRAM-SHA-256-PL",
    SECURID,
    SKEY,
    SPNEGO,
    SPNEGO_PLUS = "SPNEGO-PLUS",
    SXOVER_PLUS = "SXOVER-PLUS",
    XOAUTH,
    XOAUTH2,
}

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

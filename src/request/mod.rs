/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::tokens::{define_tokens_128, define_tokens_64};

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

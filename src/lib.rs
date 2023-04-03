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

//! # smtp-proto
//!
//! [![crates.io](https://img.shields.io/crates/v/smtp-proto)](https://crates.io/crates/smtp-proto)
//! [![build](https://github.com/stalwartlabs/sieve/actions/workflows/rust.yml/badge.svg)](https://github.com/stalwartlabs/sieve/actions/workflows/rust.yml)
//! [![docs.rs](https://img.shields.io/docsrs/smtp-proto)](https://docs.rs/smtp-proto)
//! [![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
//!
//! _smtp-proto_ is a fast SMTP/LMTP parser for Rust that supports all [registered SMTP service extensions](https://www.iana.org/assignments/mail-parameters/mail-parameters.xhtml).
//! The library is part of Stalwart SMTP and LMTP servers. It is not yet documented so if you need help using the library please start a discussion.
//!
//!
//! ## Testing & Fuzzing
//!
//! To run the testsuite:
//!
//! ```bash
//!  $ cargo test
//! ```
//!
//! To fuzz the library with `cargo-fuzz`:
//!
//! ```bash
//!  $ cargo +nightly fuzz run smtp_proto
//! ```
//!
//! ## License
//!
//! Licensed under the terms of the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.en.html) as published by
//! the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
//! See [LICENSE](LICENSE) for more details.
//!
//! You can be released from the requirements of the AGPLv3 license by purchasing
//! a commercial license. Please contact licensing@stalw.art for more details.
//!   
//! ## Copyright
//!
//! Copyright (C) 2020-2023, Stalwart Labs Ltd.

use std::fmt::Display;

pub mod request;
pub mod response;
mod tokens;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request<T> {
    Ehlo { host: T },
    Lhlo { host: T },
    Helo { host: T },
    Mail { from: MailFrom<T> },
    Rcpt { to: RcptTo<T> },
    Bdat { chunk_size: usize, is_last: bool },
    Auth { mechanism: u64, initial_response: T },
    Noop { value: T },
    Vrfy { value: T },
    Expn { value: T },
    Help { value: T },
    Etrn { name: T },
    Atrn { domains: Vec<T> },
    Burl { uri: T, is_last: bool },
    StartTls,
    Data,
    Rset,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailFrom<T> {
    pub address: T,
    pub flags: u64,
    pub size: usize,
    pub trans_id: Option<T>,
    pub by: i64,
    pub env_id: Option<T>,
    pub solicit: Option<T>,
    pub mtrk: Option<Mtrk<T>>,
    pub auth: Option<T>,
    pub hold_for: u64,
    pub hold_until: u64,
    pub mt_priority: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RcptTo<T> {
    pub address: T,
    pub orcpt: Option<T>,
    pub rrvs: i64,
    pub flags: u64,
}

pub const MAIL_BODY_7BIT: u64 = 1 << 0;
pub const MAIL_BODY_8BITMIME: u64 = 1 << 1;
pub const MAIL_BODY_BINARYMIME: u64 = 1 << 2;
pub const MAIL_RET_FULL: u64 = 1 << 3;
pub const MAIL_RET_HDRS: u64 = 1 << 4;
pub const MAIL_SMTPUTF8: u64 = 1 << 5;
pub const MAIL_REQUIRETLS: u64 = 1 << 6;
pub const MAIL_CONPERM: u64 = 1 << 7;
pub const MAIL_BY_NOTIFY: u64 = 1 << 8;
pub const MAIL_BY_RETURN: u64 = 1 << 9;
pub const MAIL_BY_TRACE: u64 = 1 << 10;

pub const RCPT_NOTIFY_SUCCESS: u64 = 1 << 0;
pub const RCPT_NOTIFY_FAILURE: u64 = 1 << 1;
pub const RCPT_NOTIFY_DELAY: u64 = 1 << 2;
pub const RCPT_NOTIFY_NEVER: u64 = 1 << 3;
pub const RCPT_CONNEG: u64 = 1 << 4;
pub const RCPT_RRVS_REJECT: u64 = 1 << 5;
pub const RCPT_RRVS_CONTINUE: u64 = 1 << 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mtrk<T> {
    pub certifier: T,
    pub timeout: u64,
}

pub const AUTH_SCRAM_SHA_256_PLUS: u64 = 1u64 << 0;
pub const AUTH_SCRAM_SHA_256: u64 = 1u64 << 1;
pub const AUTH_SCRAM_SHA_1_PLUS: u64 = 1u64 << 2;
pub const AUTH_SCRAM_SHA_1: u64 = 1u64 << 3;
pub const AUTH_OAUTHBEARER: u64 = 1u64 << 4;
pub const AUTH_XOAUTH: u64 = 1u64 << 5;
pub const AUTH_XOAUTH2: u64 = 1u64 << 6;
pub const AUTH_9798_M_DSA_SHA1: u64 = 1u64 << 7;
pub const AUTH_9798_M_ECDSA_SHA1: u64 = 1u64 << 8;
pub const AUTH_9798_M_RSA_SHA1_ENC: u64 = 1u64 << 9;
pub const AUTH_9798_U_DSA_SHA1: u64 = 1u64 << 10;
pub const AUTH_9798_U_ECDSA_SHA1: u64 = 1u64 << 11;
pub const AUTH_9798_U_RSA_SHA1_ENC: u64 = 1u64 << 12;
pub const AUTH_EAP_AES128: u64 = 1u64 << 13;
pub const AUTH_EAP_AES128_PLUS: u64 = 1u64 << 14;
pub const AUTH_ECDH_X25519_CHALLENGE: u64 = 1u64 << 15;
pub const AUTH_ECDSA_NIST256P_CHALLENGE: u64 = 1u64 << 16;
pub const AUTH_EXTERNAL: u64 = 1u64 << 17;
pub const AUTH_GS2_KRB5: u64 = 1u64 << 18;
pub const AUTH_GS2_KRB5_PLUS: u64 = 1u64 << 19;
pub const AUTH_GSS_SPNEGO: u64 = 1u64 << 20;
pub const AUTH_GSSAPI: u64 = 1u64 << 21;
pub const AUTH_KERBEROS_V4: u64 = 1u64 << 22;
pub const AUTH_KERBEROS_V5: u64 = 1u64 << 23;
pub const AUTH_NMAS_SAMBA_AUTH: u64 = 1u64 << 24;
pub const AUTH_NMAS_AUTHEN: u64 = 1u64 << 25;
pub const AUTH_NMAS_LOGIN: u64 = 1u64 << 26;
pub const AUTH_NTLM: u64 = 1u64 << 27;
pub const AUTH_OAUTH10A: u64 = 1u64 << 28;
pub const AUTH_OPENID20: u64 = 1u64 << 29;
pub const AUTH_OTP: u64 = 1u64 << 30;
pub const AUTH_SAML20: u64 = 1u64 << 31;
pub const AUTH_SECURID: u64 = 1u64 << 32;
pub const AUTH_SKEY: u64 = 1u64 << 33;
pub const AUTH_SPNEGO: u64 = 1u64 << 34;
pub const AUTH_SPNEGO_PLUS: u64 = 1u64 << 35;
pub const AUTH_SXOVER_PLUS: u64 = 1u64 << 36;
pub const AUTH_CRAM_MD5: u64 = 1u64 << 37;
pub const AUTH_DIGEST_MD5: u64 = 1u64 << 38;
pub const AUTH_LOGIN: u64 = 1u64 << 39;
pub const AUTH_PLAIN: u64 = 1u64 << 40;
pub const AUTH_ANONYMOUS: u64 = 1u64 << 41;

pub const EXT_8BIT_MIME: u32 = 1 << 0;
pub const EXT_ATRN: u32 = 1 << 1;
pub const EXT_AUTH: u32 = 1 << 2;
pub const EXT_BINARY_MIME: u32 = 1 << 3;
pub const EXT_BURL: u32 = 1 << 4;
pub const EXT_CHECKPOINT: u32 = 1 << 5;
pub const EXT_CHUNKING: u32 = 1 << 6;
pub const EXT_CONNEG: u32 = 1 << 7;
pub const EXT_CONPERM: u32 = 1 << 8;
pub const EXT_DELIVER_BY: u32 = 1 << 9;
pub const EXT_DSN: u32 = 1 << 10;
pub const EXT_ENHANCED_STATUS_CODES: u32 = 1 << 11;
pub const EXT_ETRN: u32 = 1 << 12;
pub const EXT_FUTURE_RELEASE: u32 = 1 << 13;
pub const EXT_HELP: u32 = 1 << 14;
pub const EXT_MT_PRIORITY: u32 = 1 << 15;
pub const EXT_MTRK: u32 = 1 << 16;
pub const EXT_NO_SOLICITING: u32 = 1 << 17;
pub const EXT_ONEX: u32 = 1 << 18;
pub const EXT_PIPELINING: u32 = 1 << 19;
pub const EXT_REQUIRE_TLS: u32 = 1 << 20;
pub const EXT_RRVS: u32 = 1 << 21;
pub const EXT_SIZE: u32 = 1 << 22;
pub const EXT_SMTP_UTF8: u32 = 1 << 23;
pub const EXT_START_TLS: u32 = 1 << 24;
pub const EXT_VERB: u32 = 1 << 25;
pub const EXT_EXPN: u32 = 1 << 26;
pub const EXT_VRFY: u32 = 1 << 27;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MtPriority {
    #[default]
    Mixer,
    Stanag4406,
    Nsep,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EhloResponse<T: Display> {
    pub hostname: T,
    pub capabilities: u32,

    pub auth_mechanisms: u64,
    pub deliver_by: u64,
    pub future_release_interval: u64,
    pub future_release_datetime: u64,
    pub mt_priority: MtPriority,
    pub no_soliciting: Option<String>,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response<T: Display> {
    pub code: u16,
    pub esc: [u8; 3],
    pub message: T,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    PositiveCompletion = 2,
    PositiveIntermediate = 3,
    TransientNegativeCompletion = 4,
    PermanentNegativeCompletion = 5,
    Invalid = 0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Syntax = 0,
    Information = 1,
    Connections = 2,
    Unspecified3 = 3,
    Unspecified4 = 4,
    MailSystem = 5,
    Invalid = 6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NeedsMoreData { bytes_left: usize },
    UnknownCommand,
    InvalidSenderAddress,
    InvalidRecipientAddress,
    SyntaxError { syntax: &'static str },
    InvalidParameter { param: &'static str },
    UnsupportedParameter { param: String },
    ResponseTooLong,
    InvalidResponse { code: u16 },
}

pub(crate) const LF: u8 = b'\n';
pub(crate) const SP: u8 = b' ';

pub trait IntoString: Sized {
    fn into_string(self) -> String;
}

impl IntoString for Vec<u8> {
    fn into_string(self) -> String {
        String::from_utf8(self)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

impl<T: Default> Default for MailFrom<T> {
    fn default() -> Self {
        Self {
            address: Default::default(),
            flags: Default::default(),
            size: Default::default(),
            trans_id: Default::default(),
            by: Default::default(),
            env_id: Default::default(),
            solicit: Default::default(),
            mtrk: Default::default(),
            auth: Default::default(),
            hold_for: Default::default(),
            hold_until: Default::default(),
            mt_priority: Default::default(),
        }
    }
}

impl<T: Default> Default for RcptTo<T> {
    fn default() -> Self {
        Self {
            address: Default::default(),
            orcpt: Default::default(),
            rrvs: Default::default(),
            flags: Default::default(),
        }
    }
}

impl<T: Display> AsRef<EhloResponse<T>> for EhloResponse<T> {
    fn as_ref(&self) -> &EhloResponse<T> {
        self
    }
}

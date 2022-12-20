use std::fmt::Display;

pub mod request;
pub mod response;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request<T> {
    Ehlo {
        host: T,
    },
    Lhlo {
        host: T,
    },
    Helo {
        host: T,
    },
    Mail {
        from: T,
        parameters: Vec<Parameter<T>>,
    },
    Rcpt {
        to: T,
        parameters: Vec<Parameter<T>>,
    },
    Bdat {
        chunk_size: usize,
        is_last: bool,
    },
    Auth {
        mechanism: u64,
        initial_response: T,
    },
    Noop {
        value: T,
    },
    Vrfy {
        value: T,
    },
    Expn {
        value: T,
    },
    Help {
        value: T,
    },
    Etrn {
        name: T,
    },
    Atrn {
        domains: Vec<T>,
    },
    Burl {
        uri: T,
        is_last: bool,
    },
    StartTls,
    Data,
    Rset,
    Quit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parameter<T> {
    Body(Body),
    Size(usize),
    TransId(T),
    By(By),
    Notify(u8),
    Orcpt(Orcpt<T>),
    Ret(Ret),
    EnvId(T),
    Solicit(T),
    Mtrk(Mtrk<T>),
    Auth(T),
    HoldFor(u64),
    HoldUntil(u64),
    MtPriority(i64),
    Rrvs(Rrvs),
    SmtpUtf8,
    RequireTls,
    ConPerm,
    ConNeg,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    SevenBit,
    EightBitMime,
    BinaryMime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Orcpt<T> {
    pub addr_type: T,
    pub addr: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ret {
    Full,
    Hdrs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mtrk<T> {
    pub certifier: T,
    pub timeout: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum By {
    Notify { time: i64, trace: bool },
    Return { time: i64, trace: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rrvs {
    Reject(i64),
    Continue(i64),
}

pub const NOTIFY_SUCCESS: u8 = 0x01;
pub const NOTIFY_FAILURE: u8 = 0x02;
pub const NOTIFY_DELAY: u8 = 0x04;

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
    pub code: [u8; 3],
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
    LineTooLong,
    ResponseTooLong,
    InvalidResponse { code: [u8; 3] },
}

pub(crate) const LF: u8 = b'\n';
pub(crate) const SP: u8 = b' ';

pub(crate) trait IntoString: Sized {
    fn into_string(self) -> String;
}

impl IntoString for Vec<u8> {
    fn into_string(self) -> String {
        String::from_utf8(self)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

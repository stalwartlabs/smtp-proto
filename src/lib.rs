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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    EightBitMime,
    Atrn,
    Auth {
        mechanisms: u64,
    },
    BinaryMime,
    Burl,
    Checkpoint,
    Chunking,
    Conneg,
    Conperm,
    DeliverBy {
        min: u64,
    },
    Dsn,
    EnhancedStatusCodes,
    Etrn,
    Expn,
    FutureRelease {
        max_interval: u64,
        max_datetime: u64,
    },
    Help,
    MtPriority {
        priority: MtPriority,
    },
    Mtrk,
    NoSoliciting {
        keywords: Option<String>,
    },
    Onex,
    Pipelining,
    RequireTls,
    Rrvs,
    Size {
        size: usize,
    },
    SmtpUtf8,
    StartTls,
    Verb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MtPriority {
    Mixer,
    Stanag4406,
    Nsep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EhloResponse<T: Display> {
    pub hostname: T,
    pub capabilities: Vec<Capability>,
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
    InvalidResponse { response: Response<String> },
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

/*
#[cfg(test)]
mod tests {

    #[test]
    fn csv() {
        // Build the CSV reader and iterate over each record.
        let mut rdr = csv::Reader::from_path("smtp-enhanced-status-codes-1.csv").unwrap();
        for result in rdr.records() {
            // The iterator yields Result<StringRecord, Error>, so we check the
            // error here.
            let record = result.unwrap();
            let codes = record.get(0).unwrap().split('.').collect::<Vec<_>>();
            let title = record.get(1).unwrap().replace('\n', " ");
            let desc = record
                .get(2)
                .unwrap()
                .replace('\n', " ")
                .replace('"', "\\\"")
                .replace("This is useful only as a persistent transient error.", "")
                .replace(
                    "This is useful for both permanent and persistent transient errors.",
                    "",
                )
                .replace("This is useful only as a permanent error.", "")
                .trim()
                .replace("  ", " ")
                .chars()
                .collect::<Vec<_>>()
                .chunks(50)
                .map(|s| format!("\"{}\"", s.iter().collect::<String>()))
                .collect::<Vec<_>>()
                .join(", ");

            println!("{} => (\"{}\", concat!({})).into(),", codes[0], title, desc);
        }
    }
}
*/

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
        mechanism: Mechanism,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Mechanism {
    _9798MDsaSha1,
    _9798MEcdsaSha1,
    _9798MRsaSha1Enc,
    _9798UDsaSha1,
    _9798UEcdsaSha1,
    _9798URsaSha1Enc,
    Anonymous,
    CramMd5,
    DigestMd5,
    EapAes128,
    EapAes128Plus,
    EcdhX25519Challenge,
    EcdsaNist256pChallenge,
    External,
    Gs2Krb5,
    Gs2Krb5Plus,
    GssSpnego,
    Gssapi,
    KerberosV4,
    KerberosV5,
    Login,
    NmasSambaAuth,
    NmasAuthen,
    NmasLogin,
    Ntlm,
    Oauth10a,
    Oauthbearer,
    Openid20,
    Otp,
    Plain,
    Saml20,
    ScramSha1,
    ScramSha1Plus,
    ScramSha256,
    ScramSha256Plus,
    Securid,
    Skey,
    Spnego,
    SpnegoPlus,
    SxoverPlus,
    Xoauth,
    Xoauth2,
    // Unknown
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Capability {
    EightBitMime,
    Atrn,
    Auth {
        mechanisms: Vec<Mechanism>,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    InvalidAddress,
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

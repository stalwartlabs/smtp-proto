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

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NeedsMoreData,
    UnknownCommand,
    InvalidAddress,
    SyntaxError { syntax: &'static str },
    InvalidParameter { param: &'static str },
    UnsupportedParameter { param: String },
    UnexpectedChar { char: u8 },
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

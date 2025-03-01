/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::{
    fmt::Display,
    io::{self, Write},
};

use crate::*;

impl<T: Display> EhloResponse<T> {
    pub fn new(hostname: T) -> Self {
        Self {
            hostname,
            capabilities: 0,
            auth_mechanisms: 0,
            deliver_by: 0,
            future_release_interval: 0,
            future_release_datetime: 0,
            mt_priority: MtPriority::Mixer,
            no_soliciting: None,
            size: 0,
        }
    }

    pub fn write(&self, mut writer: impl Write) -> io::Result<()> {
        write!(writer, "250-{} you had me at EHLO\r\n", self.hostname)?;
        let mut capabilities = self.capabilities;

        while capabilities != 0 {
            let capability = 1 << (31 - capabilities.leading_zeros());
            capabilities ^= capability;

            writer.write_all(b"250")?;
            writer.write_all(if capabilities != 0 { b"-" } else { b" " })?;
            match capability {
                EXT_8BIT_MIME => write!(writer, "8BITMIME\r\n"),
                EXT_ATRN => write!(writer, "ATRN\r\n"),
                EXT_AUTH => {
                    writer.write_all(b"AUTH")?;
                    let mut mechanisms = self.auth_mechanisms;
                    while mechanisms != 0 {
                        let item = 1 << (63 - mechanisms.leading_zeros());
                        mechanisms ^= item;
                        write!(writer, " {}", item.to_mechanism())?;
                    }
                    writer.write_all(b"\r\n")
                }
                EXT_BINARY_MIME => write!(writer, "BINARYMIME\r\n"),
                EXT_BURL => write!(writer, "BURL\r\n"),
                EXT_CHECKPOINT => write!(writer, "CHECKPOINT\r\n"),
                EXT_CHUNKING => write!(writer, "CHUNKING\r\n"),
                EXT_CONNEG => write!(writer, "CONNEG\r\n"),
                EXT_CONPERM => write!(writer, "CONPERM\r\n"),
                EXT_DELIVER_BY => {
                    if self.deliver_by > 0 {
                        write!(writer, "DELIVERBY {}\r\n", self.deliver_by)
                    } else {
                        write!(writer, "DELIVERBY\r\n")
                    }
                }
                EXT_DSN => write!(writer, "DSN\r\n"),
                EXT_ENHANCED_STATUS_CODES => write!(writer, "ENHANCEDSTATUSCODES\r\n"),
                EXT_ETRN => write!(writer, "ETRN\r\n"),
                EXT_EXPN => write!(writer, "EXPN\r\n"),
                EXT_VRFY => write!(writer, "VRFY\r\n"),
                EXT_FUTURE_RELEASE => write!(
                    writer,
                    "FUTURERELEASE {} {}\r\n",
                    self.future_release_interval, self.future_release_datetime
                ),
                EXT_HELP => write!(writer, "HELP\r\n"),
                EXT_MT_PRIORITY => write!(
                    writer,
                    "MT-PRIORITY {}\r\n",
                    match self.mt_priority {
                        MtPriority::Mixer => "MIXER",
                        MtPriority::Stanag4406 => "STANAG4406",
                        MtPriority::Nsep => "NSEP",
                    }
                ),
                EXT_MTRK => write!(writer, "MTRK\r\n"),
                EXT_NO_SOLICITING => {
                    if let Some(keywords) = &self.no_soliciting {
                        write!(writer, "NO-SOLICITING {keywords}\r\n")
                    } else {
                        write!(writer, "NO-SOLICITING\r\n")
                    }
                }
                EXT_ONEX => write!(writer, "ONEX\r\n"),
                EXT_PIPELINING => write!(writer, "PIPELINING\r\n"),
                EXT_REQUIRE_TLS => write!(writer, "REQUIRETLS\r\n"),
                EXT_RRVS => write!(writer, "RRVS\r\n"),
                EXT_SIZE => {
                    if self.size > 0 {
                        write!(writer, "SIZE {}\r\n", self.size)
                    } else {
                        write!(writer, "SIZE\r\n")
                    }
                }
                EXT_SMTP_UTF8 => write!(writer, "SMTPUTF8\r\n"),
                EXT_START_TLS => write!(writer, "STARTTLS\r\n"),
                EXT_VERB => write!(writer, "VERB\r\n"),
                _ => write!(writer, ""),
            }?;
        }

        Ok(())
    }
}

impl<T: Display> Response<T> {
    pub fn write(&self, mut writer: impl Write) -> io::Result<()> {
        write!(
            writer,
            "{} {}.{}.{} {}\r\n",
            self.code, self.esc[0], self.esc[1], self.esc[2], self.message
        )
    }
}

pub trait BitToString {
    fn to_mechanism(&self) -> &'static str;
}

impl BitToString for u64 {
    fn to_mechanism(&self) -> &'static str {
        match *self {
            AUTH_SCRAM_SHA_256_PLUS => "SCRAM-SHA-256-PLUS",
            AUTH_SCRAM_SHA_256 => "SCRAM-SHA-256",
            AUTH_SCRAM_SHA_1_PLUS => "SCRAM-SHA-1-PLUS",
            AUTH_SCRAM_SHA_1 => "SCRAM-SHA-1",
            AUTH_OAUTHBEARER => "OAUTHBEARER",
            AUTH_XOAUTH => "XOAUTH",
            AUTH_XOAUTH2 => "XOAUTH2",
            AUTH_9798_M_DSA_SHA1 => "9798-M-DSA-SHA1",
            AUTH_9798_M_ECDSA_SHA1 => "9798-M-ECDSA-SHA1",
            AUTH_9798_M_RSA_SHA1_ENC => "9798-M-RSA-SHA1-ENC",
            AUTH_9798_U_DSA_SHA1 => "9798-U-DSA-SHA1",
            AUTH_9798_U_ECDSA_SHA1 => "9798-U-ECDSA-SHA1",
            AUTH_9798_U_RSA_SHA1_ENC => "9798-U-RSA-SHA1-ENC",
            AUTH_EAP_AES128 => "EAP-AES128",
            AUTH_EAP_AES128_PLUS => "EAP-AES128-PLUS",
            AUTH_ECDH_X25519_CHALLENGE => "ECDH-X25519-CHALLENGE",
            AUTH_ECDSA_NIST256P_CHALLENGE => "ECDSA-NIST256P-CHALLENGE",
            AUTH_EXTERNAL => "EXTERNAL",
            AUTH_GS2_KRB5 => "GS2-KRB5",
            AUTH_GS2_KRB5_PLUS => "GS2-KRB5-PLUS",
            AUTH_GSS_SPNEGO => "GSS-SPNEGO",
            AUTH_GSSAPI => "GSSAPI",
            AUTH_KERBEROS_V4 => "KERBEROS_V4",
            AUTH_KERBEROS_V5 => "KERBEROS_V5",
            AUTH_NMAS_SAMBA_AUTH => "NMAS-SAMBA-AUTH",
            AUTH_NMAS_AUTHEN => "NMAS_AUTHEN",
            AUTH_NMAS_LOGIN => "NMAS_LOGIN",
            AUTH_NTLM => "NTLM",
            AUTH_OAUTH10A => "OAUTH10A",
            AUTH_OPENID20 => "OPENID20",
            AUTH_OTP => "OTP",
            AUTH_SAML20 => "SAML20",
            AUTH_SECURID => "SECURID",
            AUTH_SKEY => "SKEY",
            AUTH_SPNEGO => "SPNEGO",
            AUTH_SPNEGO_PLUS => "SPNEGO-PLUS",
            AUTH_SXOVER_PLUS => "SXOVER-PLUS",
            AUTH_CRAM_MD5 => "CRAM-MD5",
            AUTH_DIGEST_MD5 => "DIGEST-MD5",
            AUTH_LOGIN => "LOGIN",
            AUTH_PLAIN => "PLAIN",
            AUTH_ANONYMOUS => "ANONYMOUS",
            _ => "",
        }
    }
}

impl<T: Display> Response<T> {
    pub fn new(code: u16, e0: u8, e1: u8, e2: u8, message: T) -> Self {
        Self {
            code,
            esc: [e0, e1, e2],
            message,
        }
    }

    /// Returns the reply's numeric status.
    pub fn code(&self) -> u16 {
        self.code
    }

    /// Returns the message included in the reply.
    pub fn message(&self) -> &T {
        &self.message
    }

    /// Returns the status severity (first digit of the status code).
    pub fn severity(&self) -> Severity {
        match self.code {
            200..=299 => Severity::PositiveCompletion,
            300..=399 => Severity::PositiveIntermediate,
            400..=499 => Severity::TransientNegativeCompletion,
            500..=599 => Severity::PermanentNegativeCompletion,
            _ => Severity::Invalid,
        }
    }

    /// Returns the status category (second digit of the status code).
    pub fn category(&self) -> Category {
        match (self.code / 10) % 10 {
            0 => Category::Syntax,
            1 => Category::Information,
            2 => Category::Connections,
            3 => Category::Unspecified3,
            4 => Category::Unspecified4,
            5 => Category::MailSystem,
            _ => Category::Invalid,
        }
    }

    /// Returns the status details (third digit of the status code).
    pub fn details(&self) -> u16 {
        self.code % 10
    }

    /// Returns `true` if the reply is a positive completion.
    pub fn is_positive_completion(&self) -> bool {
        self.severity() == Severity::PositiveCompletion
    }

    pub fn explain_class_code(&self) -> Option<(&'static str, &'static str)> {
        match self.esc[0] {
            2 => (
                "Success",
                concat!(
                    "Success specifies that the DSN is reporting a posi",
                    "tive delivery action. Detail sub-codes may provide",
                    " notification of transformations required for deli",
                    "very."
                ),
            )
                .into(),
            4 => (
                "Persistent Transient Failure",
                concat!(
                    "A persistent transient failure is one in which the",
                    " message as sent is valid, but persistence of some",
                    " temporary condition has caused abandonment or del",
                    "ay of attempts to send the message. If this code a",
                    "ccompanies a delivery failure report, sending in t",
                    "he future may be successful."
                ),
            )
                .into(),
            5 => (
                "Permanent Failure",
                concat!(
                    "A permanent failure is one which is not likely to ",
                    "be resolved by resending the message in the curren",
                    "t form. Some change to the message or the destinat",
                    "ion must be made for successful delivery."
                ),
            )
                .into(),
            _ => None,
        }
    }

    pub fn explain_subject_code(&self) -> Option<(&'static str, &'static str)> {
        match self.esc[1] {
            0 => (
                "Other or Undefined Status",
                concat!("There is no additional subject information availab", "le."),
            )
                .into(),
            1 => (
                "Addressing Status",
                concat!(
                    "The address status reports on the originator or de",
                    "stination address. It may include address syntax o",
                    "r validity. These errors can generally be correcte",
                    "d by the sender and retried."
                ),
            )
                .into(),
            2 => (
                "Mailbox Status",
                concat!(
                    "Mailbox status indicates that something having to ",
                    "do with the mailbox has caused this DSN. Mailbox i",
                    "ssues are assumed to be under the general control ",
                    "of the recipient."
                ),
            )
                .into(),
            3 => (
                "Mail System Status",
                concat!(
                    "Mail system status indicates that something having",
                    " to do with the destination system has caused this",
                    " DSN. System issues are assumed to be under the ge",
                    "neral control of the destination system administra",
                    "tor."
                ),
            )
                .into(),
            4 => (
                "Network and Routing Status",
                concat!(
                    "The networking or routing codes report status abou",
                    "t the delivery system itself. These system compone",
                    "nts include any necessary infrastructure such as d",
                    "irectory and routing services. Network issues are ",
                    "assumed to be under the control of the destination",
                    " or intermediate system administrator."
                ),
            )
                .into(),
            5 => (
                "Mail Delivery Protocol Status",
                concat!(
                    "The mail delivery protocol status codes report fai",
                    "lures involving the message delivery protocol. The",
                    "se failures include the full range of problems res",
                    "ulting from implementation errors or an unreliable",
                    " connection."
                ),
            )
                .into(),
            6 => (
                "Message Content or Media Status",
                concat!(
                    "The message content or media status codes report f",
                    "ailures involving the content of the message. Thes",
                    "e codes report failures due to translation, transc",
                    "oding, or otherwise unsupported message media. Mes",
                    "sage content or media issues are under the control",
                    " of both the sender and the receiver, both of whic",
                    "h must support a common set of supported content-t",
                    "ypes."
                ),
            )
                .into(),
            7 => (
                "Security or Policy Status",
                concat!(
                    "The security or policy status codes report failure",
                    "s involving policies such as per-recipient or per-",
                    "host filtering and cryptographic operations. Secur",
                    "ity and policy status issues are assumed to be und",
                    "er the control of either or both the sender and re",
                    "cipient. Both the sender and recipient must permit",
                    " the exchange of messages and arrange the exchange",
                    " of necessary keys and certificates for cryptograp",
                    "hic operations."
                ),
            )
                .into(),

            _ => None,
        }
    }

    pub fn explain_status_code(&self) -> Option<(&'static str, &'static str)> {
        match (self.esc[1], self.esc[2]) {
            (0, 0) => (
                "Other undefined Status",
                concat!(
                    "Other undefined status is the only undefined error",
                    " code."
                ),
            )
                .into(),
            (1, 0) => (
                "Other address status",
                concat!(
                    "Something about the address specified in the messa",
                    "ge caused this DSN."
                ),
            )
                .into(),
            (1, 1) => (
                "Bad destination mailbox address",
                concat!(
                    "The mailbox specified in the address does not exis",
                    "t. For Internet mail names, this means the address",
                    " portion to the left of the \"@\" sign is invalid.",
                    " This code is only useful for permanent failures."
                ),
            )
                .into(),
            (1, 2) => (
                "Bad destination system address",
                concat!(
                    "The destination system specified in the address do",
                    "es not exist or is incapable of accepting mail. Fo",
                    "r Internet mail names, this means the address port",
                    "ion to the right of the \"@\" is invalid for mail.",
                    " This code is only useful for permanent failures."
                ),
            )
                .into(),
            (1, 3) => (
                "Bad destination mailbox address syntax",
                concat!(
                    "The destination address was syntactically invalid.",
                    " This can apply to any field in the address. This ",
                    "code is only useful for permanent failures."
                ),
            )
                .into(),
            (1, 4) => (
                "Destination mailbox address ambiguous",
                concat!(
                    "The mailbox address as specified matches one or mo",
                    "re recipients on the destination system. This may ",
                    "result if a heuristic address mapping algorithm is",
                    " used to map the specified address to a local mail",
                    "box name."
                ),
            )
                .into(),
            (1, 5) => (
                "Destination address valid",
                concat!(
                    "This mailbox address as specified was valid. This ",
                    "status code should be used for positive delivery r",
                    "eports."
                ),
            )
                .into(),
            (1, 6) => (
                "Destination mailbox has moved, No forwarding address",
                concat!(
                    "The mailbox address provided was at one time valid",
                    ", but mail is no longer being accepted for that ad",
                    "dress. This code is only useful for permanent fail",
                    "ures."
                ),
            )
                .into(),
            (1, 7) => (
                "Bad sender's mailbox address syntax",
                concat!(
                    "The sender's address was syntactically invalid. Th",
                    "is can apply to any field in the address."
                ),
            )
                .into(),
            (1, 8) => (
                "Bad sender's system address",
                concat!(
                    "The sender's system specified in the address does ",
                    "not exist or is incapable of accepting return mail",
                    ". For domain names, this means the address portion",
                    " to the right of the \"@\" is invalid for mail."
                ),
            )
                .into(),
            (1, 9) => (
                "Message relayed to non-compliant mailer",
                concat!(
                    "The mailbox address specified was valid, but the m",
                    "essage has been relayed to a system that does not ",
                    "speak this protocol; no further information can be",
                    " provided."
                ),
            )
                .into(),
            (1, 10) => (
                "Recipient address has null MX",
                concat!(
                    "This status code is returned when the associated a",
                    "ddress is marked as invalid using a null MX."
                ),
            )
                .into(),
            (2, 0) => (
                "Other or undefined mailbox status",
                concat!(
                    "The mailbox exists, but something about the destin",
                    "ation mailbox has caused the sending of this DSN."
                ),
            )
                .into(),
            (2, 1) => (
                "Mailbox disabled, not accepting messages",
                concat!(
                    "The mailbox exists, but is not accepting messages.",
                    " This may be a permanent error if the mailbox will",
                    " never be re-enabled or a transient error if the m",
                    "ailbox is only temporarily disabled."
                ),
            )
                .into(),
            (2, 2) => (
                "Mailbox full",
                concat!(
                    "The mailbox is full because the user has exceeded ",
                    "a per-mailbox administrative quota or physical cap",
                    "acity. The general semantics implies that the reci",
                    "pient can delete messages to make more space avail",
                    "able. This code should be used as a persistent tra",
                    "nsient failure."
                ),
            )
                .into(),
            (2, 3) => (
                "Message length exceeds administrative limit",
                concat!(
                    "A per-mailbox administrative message length limit ",
                    "has been exceeded. This status code should be used",
                    " when the per-mailbox message length limit is less",
                    " than the general system limit. This code should b",
                    "e used as a permanent failure."
                ),
            )
                .into(),
            (2, 4) => (
                "Mailing list expansion problem",
                concat!(
                    "The mailbox is a mailing list address and the mail",
                    "ing list was unable to be expanded. This code may ",
                    "represent a permanent failure or a persistent tran",
                    "sient failure."
                ),
            )
                .into(),
            (3, 0) => (
                "Other or undefined mail system status",
                concat!(
                    "The destination system exists and normally accepts",
                    " mail, but something about the system has caused t",
                    "he generation of this DSN."
                ),
            )
                .into(),
            (3, 1) => (
                "Mail system full",
                concat!(
                    "Mail system storage has been exceeded. The general",
                    " semantics imply that the individual recipient may",
                    " not be able to delete material to make room for a",
                    "dditional messages."
                ),
            )
                .into(),
            (3, 2) => (
                "System not accepting network messages",
                concat!(
                    "The host on which the mailbox is resident is not a",
                    "ccepting messages. Examples of such conditions inc",
                    "lude an imminent shutdown, excessive load, or syst",
                    "em maintenance."
                ),
            )
                .into(),
            (3, 3) => (
                "System not capable of selected features",
                concat!(
                    "Selected features specified for the message are no",
                    "t supported by the destination system. This can oc",
                    "cur in gateways when features from one domain cann",
                    "ot be mapped onto the supported feature in another",
                    "."
                ),
            )
                .into(),
            (3, 4) => (
                "Message too big for system",
                concat!(
                    "The message is larger than per-message size limit.",
                    " This limit may either be for physical or administ",
                    "rative reasons."
                ),
            )
                .into(),
            (3, 5) => (
                "System incorrectly configured",
                concat!(
                    "The system is not configured in a manner that will",
                    " permit it to accept this message."
                ),
            )
                .into(),
            (3, 6) => (
                "Requested priority was changed",
                concat!(
                    "The message was accepted for relay/delivery, but t",
                    "he requested priority (possibly the implied defaul",
                    "t) was not honoured. The human readable text after",
                    " the status code contains the new priority, follow",
                    "ed by SP (space) and explanatory human readable te",
                    "xt."
                ),
            )
                .into(),
            (4, 0) => (
                "Other or undefined network or routing status",
                concat!(
                    "Something went wrong with the networking, but it i",
                    "s not clear what the problem is, or the problem ca",
                    "nnot be well expressed with any of the other provi",
                    "ded detail codes."
                ),
            )
                .into(),
            (4, 1) => (
                "No answer from host",
                concat!(
                    "The outbound connection attempt was not answered, ",
                    "because either the remote system was busy, or was ",
                    "unable to take a call."
                ),
            )
                .into(),
            (4, 2) => (
                "Bad connection",
                concat!(
                    "The outbound connection was established, but was u",
                    "nable to complete the message transaction, either ",
                    "because of time-out, or inadequate connection qual",
                    "ity."
                ),
            )
                .into(),
            (4, 3) => (
                "Directory server failure",
                concat!(
                    "The network system was unable to forward the messa",
                    "ge, because a directory server was unavailable. Th",
                    "e inability to connect to an Internet DNS server i",
                    "s one example of the directory server failure erro",
                    "r."
                ),
            )
                .into(),
            (4, 4) => (
                "Unable to route",
                concat!(
                    "The mail system was unable to determine the next h",
                    "op for the message because the necessary routing i",
                    "nformation was unavailable from the directory serv",
                    "er. A DNS lookup returning only an SOA (Start of A",
                    "dministration) record for a domain name is one exa",
                    "mple of the unable to route error."
                ),
            )
                .into(),
            (4, 5) => (
                "Mail system congestion",
                concat!(
                    "The mail system was unable to deliver the message ",
                    "because the mail system was congested."
                ),
            )
                .into(),
            (4, 6) => (
                "Routing loop detected",
                concat!(
                    "A routing loop caused the message to be forwarded ",
                    "too many times, either because of incorrect routin",
                    "g tables or a user- forwarding loop."
                ),
            )
                .into(),
            (4, 7) => (
                "Delivery time expired",
                concat!(
                    "The message was considered too old by the rejectin",
                    "g system, either because it remained on that host ",
                    "too long or because the time-to-live value specifi",
                    "ed by the sender of the message was exceeded. If p",
                    "ossible, the code for the actual problem found whe",
                    "n delivery was attempted should be returned rather",
                    " than this code."
                ),
            )
                .into(),
            (5, 0) => (
                "Other or undefined protocol status",
                concat!(
                    "Something was wrong with the protocol necessary to",
                    " deliver the message to the next hop and the probl",
                    "em cannot be well expressed with any of the other ",
                    "provided detail codes."
                ),
            )
                .into(),
            (5, 1) => (
                "Invalid command",
                concat!(
                    "A mail transaction protocol command was issued whi",
                    "ch was either out of sequence or unsupported."
                ),
            )
                .into(),
            (5, 2) => (
                "Syntax error",
                concat!(
                    "A mail transaction protocol command was issued whi",
                    "ch could not be interpreted, either because the sy",
                    "ntax was wrong or the command is unrecognized."
                ),
            )
                .into(),
            (5, 3) => (
                "Too many recipients",
                concat!(
                    "More recipients were specified for the message tha",
                    "n could have been delivered by the protocol. This ",
                    "error should normally result in the segmentation o",
                    "f the message into two, the remainder of the recip",
                    "ients to be delivered on a subsequent delivery att",
                    "empt. It is included in this list in the event tha",
                    "t such segmentation is not possible."
                ),
            )
                .into(),
            (5, 4) => (
                "Invalid command arguments",
                concat!(
                    "A valid mail transaction protocol command was issu",
                    "ed with invalid arguments, either because the argu",
                    "ments were out of range or represented unrecognize",
                    "d features."
                ),
            )
                .into(),
            (5, 5) => (
                "Wrong protocol version",
                concat!(
                    "A protocol version mis-match existed which could n",
                    "ot be automatically resolved by the communicating ",
                    "parties."
                ),
            )
                .into(),
            (5, 6) => (
                "Authentication Exchange line is too long",
                concat!(
                    "This enhanced status code SHOULD be returned when ",
                    "the server fails the AUTH command due to the clien",
                    "t sending a [BASE64] response which is longer than",
                    " the maximum buffer size available for the current",
                    "ly selected SASL mechanism."
                ),
            )
                .into(),
            (6, 0) => (
                "Other or undefined media error",
                concat!(
                    "Something about the content of a message caused it",
                    " to be considered undeliverable and the problem ca",
                    "nnot be well expressed with any of the other provi",
                    "ded detail codes."
                ),
            )
                .into(),
            (6, 1) => (
                "Media not supported",
                concat!(
                    "The media of the message is not supported by eithe",
                    "r the delivery protocol or the next system in the ",
                    "forwarding path."
                ),
            )
                .into(),
            (6, 2) => (
                "Conversion required and prohibited",
                concat!(
                    "The content of the message must be converted befor",
                    "e it can be delivered and such conversion is not p",
                    "ermitted. Such prohibitions may be the expression ",
                    "of the sender in the message itself or the policy ",
                    "of the sending host."
                ),
            )
                .into(),
            (6, 3) => (
                "Conversion required but not supported",
                concat!(
                    "The message content must be converted in order to ",
                    "be forwarded but such conversion is not possible o",
                    "r is not practical by a host in the forwarding pat",
                    "h. This condition may result when an ESMTP gateway",
                    " supports 8bit transport but is not able to downgr",
                    "ade the message to 7 bit as required for the next ",
                    "hop."
                ),
            )
                .into(),
            (6, 4) => (
                "Conversion with loss performed",
                concat!(
                    "This is a warning sent to the sender when message ",
                    "delivery was successfully but when the delivery re",
                    "quired a conversion in which some data was lost. T",
                    "his may also be a permanent error if the sender ha",
                    "s indicated that conversion with loss is prohibite",
                    "d for the message."
                ),
            )
                .into(),
            (6, 5) => (
                "Conversion Failed",
                concat!(
                    "A conversion was required but was unsuccessful. Th",
                    "is may be useful as a permanent or persistent temp",
                    "orary notification."
                ),
            )
                .into(),
            (6, 6) => (
                "Message content not available",
                concat!(
                    "The message content could not be fetched from a re",
                    "mote system. This may be useful as a permanent or ",
                    "persistent temporary notification."
                ),
            )
                .into(),
            (6, 7) => (
                "Non-ASCII addresses not permitted for that sender/recipient",
                concat!(
                    "This indicates the reception of a MAIL or RCPT com",
                    "mand that non-ASCII addresses are not permitted"
                ),
            )
                .into(),
            (6, 8 | 10) => (
                "UTF-8 string reply is required, but not permitted by the SMTP client",
                concat!(
                    "This indicates that a reply containing a UTF-8 str",
                    "ing is required to show the mailbox name, but that",
                    " form of response is not permitted by the SMTP cli",
                    "ent."
                ),
            )
                .into(),
            (6, 9) => (
                concat!(
                    "UTF-8 header message cannot be transferred to ",
                    "one or more recipients, so the message must be rejected"
                ),
                concat!(
                    "This indicates that transaction failed after the f",
                    "inal \".\" of the DATA command."
                ),
            )
                .into(),
            (7, 0) => (
                "Other or undefined security status",
                concat!(
                    "Something related to security caused the message t",
                    "o be returned, and the problem cannot be well expr",
                    "essed with any of the other provided detail codes.",
                    " This status code may also be used when the condit",
                    "ion cannot be further described because of securit",
                    "y policies in force."
                ),
            )
                .into(),
            (7, 1) => (
                "Delivery not authorized, message refused",
                concat!(
                    "The sender is not authorized to send to the destin",
                    "ation. This can be the result of per-host or per-r",
                    "ecipient filtering. This memo does not discuss the",
                    " merits of any such filtering, but provides a mech",
                    "anism to report such."
                ),
            )
                .into(),
            (7, 2) => (
                "Mailing list expansion prohibited",
                concat!(
                    "The sender is not authorized to send a message to ",
                    "the intended mailing list."
                ),
            )
                .into(),
            (7, 3) => (
                "Security conversion required but not possible",
                concat!(
                    "A conversion from one secure messaging protocol to",
                    " another was required for delivery and such conver",
                    "sion was not possible."
                ),
            )
                .into(),
            (7, 4) => (
                "Security features not supported",
                concat!(
                    "A message contained security features such as secu",
                    "re authentication that could not be supported on t",
                    "he delivery protocol."
                ),
            )
                .into(),
            (7, 5) => (
                "Cryptographic failure",
                concat!(
                    "A transport system otherwise authorized to validat",
                    "e or decrypt a message in transport was unable to ",
                    "do so because necessary information such as key wa",
                    "s not available or such information was invalid."
                ),
            )
                .into(),
            (7, 6) => (
                "Cryptographic algorithm not supported",
                concat!(
                    "A transport system otherwise authorized to validat",
                    "e or decrypt a message was unable to do so because",
                    " the necessary algorithm was not supported."
                ),
            )
                .into(),
            (7, 7) => (
                "Message integrity failure",
                concat!(
                    "A transport system otherwise authorized to validat",
                    "e a message was unable to do so because the messag",
                    "e was corrupted or altered. This may be useful as ",
                    "a permanent, transient persistent, or successful d",
                    "elivery code."
                ),
            )
                .into(),
            (7, 8) => (
                "Authentication credentials invalid",
                concat!(
                    "This response to the AUTH command indicates that t",
                    "he authentication failed due to invalid or insuffi",
                    "cient authentication credentials. In this case, th",
                    "e client SHOULD ask the user to supply new credent",
                    "ials (such as by presenting a password dialog box)",
                    "."
                ),
            )
                .into(),
            (7, 9) => (
                "Authentication mechanism is too weak",
                concat!(
                    "This response to the AUTH command indicates that t",
                    "he selected authentication mechanism is weaker tha",
                    "n server policy permits for that user. The client ",
                    "SHOULD retry with a new authentication mechanism."
                ),
            )
                .into(),
            (7, 10) => (
                "Encryption Needed",
                concat!(
                    "This indicates that external strong privacy layer ",
                    "is needed in order to use the requested authentica",
                    "tion mechanism. This is primarily intended for use",
                    " with clear text authentication mechanisms. A clie",
                    "nt which receives this may activate a security lay",
                    "er such as TLS prior to authenticating, or attempt",
                    " to use a stronger mechanism."
                ),
            )
                .into(),
            (7, 11) => (
                "Encryption required for requested authentication mechanism",
                concat!(
                    "This response to the AUTH command indicates that t",
                    "he selected authentication mechanism may only be u",
                    "sed when the underlying SMTP connection is encrypt",
                    "ed. Note that this response code is documented her",
                    "e for historical purposes only. Modern implementat",
                    "ions SHOULD NOT advertise mechanisms that are not ",
                    "permitted due to lack of encryption, unless an enc",
                    "ryption layer of sufficient strength is currently ",
                    "being employed."
                ),
            )
                .into(),
            (7, 12) => (
                "A password transition is needed",
                concat!(
                    "This response to the AUTH command indicates that t",
                    "he user needs to transition to the selected authen",
                    "tication mechanism. This is typically done by auth",
                    "enticating once using the [PLAIN] authentication m",
                    "echanism. The selected mechanism SHOULD then work ",
                    "for authentications in subsequent sessions."
                ),
            )
                .into(),
            (7, 13) => (
                "User Account Disabled",
                concat!(
                    "Sometimes a system administrator will have to disa",
                    "ble a user's account (e.g., due to lack of payment",
                    ", abuse, evidence of a break-in attempt, etc). Thi",
                    "s error code occurs after a successful authenticat",
                    "ion to a disabled account. This informs the client",
                    " that the failure is permanent until the user cont",
                    "acts their system administrator to get the account",
                    " re-enabled. It differs from a generic authenticat",
                    "ion failure where the client's best option is to p",
                    "resent the passphrase entry dialog in case the use",
                    "r simply mistyped their passphrase."
                ),
            )
                .into(),
            (7, 14) => (
                "Trust relationship required",
                concat!(
                    "The submission server requires a configured trust ",
                    "relationship with a third-party server in order to",
                    " access the message content. This value replaces t",
                    "he prior use of X.7.8 for this error condition. th",
                    "ereby updating [RFC4468]."
                ),
            )
                .into(),
            (7, 15) => (
                "Priority Level is too low",
                concat!(
                    "The specified priority level is below the lowest p",
                    "riority acceptable for the receiving SMTP server. ",
                    "This condition might be temporary, for example the",
                    " server is operating in a mode where only higher p",
                    "riority messages are accepted for transfer and del",
                    "ivery, while lower priority messages are rejected."
                ),
            )
                .into(),
            (7, 16) => (
                "Message is too big for the specified priority",
                concat!(
                    "The message is too big for the specified priority.",
                    " This condition might be temporary, for example th",
                    "e server is operating in a mode where only higher ",
                    "priority messages below certain size are accepted ",
                    "for transfer and delivery."
                ),
            )
                .into(),
            (7, 17) => (
                "Mailbox owner has changed",
                concat!(
                    "This status code is returned when a message is rec",
                    "eived with a Require-Recipient-Valid-Since field o",
                    "r RRVS extension and the receiving system is able ",
                    "to determine that the intended recipient mailbox h",
                    "as not been under continuous ownership since the s",
                    "pecified date-time."
                ),
            )
                .into(),
            (7, 18) => (
                "Domain owner has changed",
                concat!(
                    "This status code is returned when a message is rec",
                    "eived with a Require-Recipient-Valid-Since field o",
                    "r RRVS extension and the receiving system wishes t",
                    "o disclose that the owner of the domain name of th",
                    "e recipient has changed since the specified date-t",
                    "ime."
                ),
            )
                .into(),
            (7, 19) => (
                "RRVS test cannot be completed",
                concat!(
                    "This status code is returned when a message is rec",
                    "eived with a Require-Recipient-Valid-Since field o",
                    "r RRVS extension and the receiving system cannot c",
                    "omplete the requested evaluation because the requi",
                    "red timestamp was not recorded. The message origin",
                    "ator needs to decide whether to reissue the messag",
                    "e without RRVS protection."
                ),
            )
                .into(),
            (7, 20) => (
                "No passing DKIM signature found",
                concat!(
                    "This status code is returned when a message did no",
                    "t contain any passing DKIM signatures. (This viola",
                    "tes the advice of Section 6.1 of [RFC6376].)"
                ),
            )
                .into(),
            (7, 21) => (
                "No acceptable DKIM signature found",
                concat!(
                    "This status code is returned when a message contai",
                    "ns one or more passing DKIM signatures, but none a",
                    "re acceptable. (This violates the advice of Sectio",
                    "n 6.1 of [RFC6376].)"
                ),
            )
                .into(),
            (7, 22) => (
                "No valid author-matched DKIM signature found",
                concat!(
                    "This status code is returned when a message contai",
                    "ns one or more passing DKIM signatures, but none a",
                    "re acceptable because none have an identifier(s) t",
                    "hat matches the author address(es) found in the Fr",
                    "om header field. This is a special case of X.7.21.",
                    " (This violates the advice of Section 6.1 of [RFC6",
                    "376].)"
                ),
            )
                .into(),
            (7, 23) => (
                "SPF validation failed",
                concat!(
                    "This status code is returned when a message comple",
                    "ted an SPF check that produced a \"fail\" result, ",
                    "contrary to local policy requirements. Used in pla",
                    "ce of 5.7.1 as described in Section 8.4 of [RFC720",
                    "8]."
                ),
            )
                .into(),
            (7, 24) => (
                "SPF validation error",
                concat!(
                    "This status code is returned when evaluation of SP",
                    "F relative to an arriving message resulted in an e",
                    "rror. Used in place of 4.4.3 or 5.5.2 as described",
                    " in Sections 8.6 and 8.7 of [RFC7208]."
                ),
            )
                .into(),
            (7, 25) => (
                "Reverse DNS validation failed",
                concat!(
                    "This status code is returned when an SMTP client's",
                    " IP address failed a reverse DNS validation check,",
                    " contrary to local policy requirements."
                ),
            )
                .into(),
            (7, 26) => (
                "Multiple authentication checks failed",
                concat!(
                    "This status code is returned when a message failed",
                    " more than one message authentication check, contr",
                    "ary to local policy requirements. The particular m",
                    "echanisms that failed are not specified."
                ),
            )
                .into(),
            (7, 27) => (
                "Sender address has null MX",
                concat!(
                    "This status code is returned when the associated s",
                    "ender address has a null MX, and the SMTP receiver",
                    " is configured to reject mail from such sender (e.",
                    "g., because it could not return a DSN)."
                ),
            )
                .into(),
            (7, 28) => (
                "Mail flood detected",
                concat!(
                    "The message appears to be part of a mail flood of ",
                    "similar abusive messages."
                ),
            )
                .into(),
            (7, 29) => (
                "ARC validation failure",
                concat!(
                    "This status code may be returned when a message fa",
                    "ils ARC validation."
                ),
            )
                .into(),
            (7, 30) => (
                "REQUIRETLS support required",
                concat!(
                    "This indicates that the message was not able to be",
                    " forwarded because it was received with a REQUIRET",
                    "LS requirement and none of the SMTP servers to whi",
                    "ch the message should be forwarded provide this su",
                    "pport."
                ),
            )
                .into(),
            _ => None,
        }
    }
}

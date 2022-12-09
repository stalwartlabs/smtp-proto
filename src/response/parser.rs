use std::slice::Iter;

use crate::{
    request::{parser::Rfc5321Parser, receiver::ReceiverParser},
    Capability, EhloResponse, Error, IntoString, MtPriority, Response, LF,
};

use super::*;

impl ReceiverParser for EhloResponse<String> {
    fn parse(bytes: &mut Iter<'_, u8>) -> Result<EhloResponse<String>, Error> {
        let mut parser = Rfc5321Parser::new(bytes);
        let mut response = EhloResponse {
            hostname: String::new(),
            capabilities: Vec::new(),
        };
        let mut eol = false;
        let mut buf = Vec::with_capacity(32);
        let mut code = [0u8; 3];
        let mut is_first_line = true;
        let mut did_success = false;

        while !eol {
            for code in code.iter_mut() {
                match parser.read_char()? {
                    ch @ b'0'..=b'9' => {
                        *code = ch - b'0';
                    }
                    _ => {
                        return Err(Error::SyntaxError {
                            syntax: "unexpected token",
                        });
                    }
                }
            }
            match parser.read_char()? {
                b' ' => {
                    eol = true;
                }
                b'-' => (),
                b'\n' if code[0] < 6 => {
                    break;
                }
                _ => {
                    return Err(Error::SyntaxError {
                        syntax: "unexpected token",
                    });
                }
            }

            did_success = code[0] == 2 && code[1] == 5 && code[2] == 0;

            if !is_first_line && did_success {
                response
                    .capabilities
                    .push(match parser.hashed_value_long()? {
                        _8BITMIME => Capability::EightBitMime,
                        ATRN => Capability::Atrn,
                        AUTH => {
                            let mut mechanisms = 0;
                            while parser.stop_char != LF {
                                if let Some(mechanism) = parser.mechanism()? {
                                    mechanisms |= mechanism;
                                }
                            }

                            Capability::Auth { mechanisms }
                        }
                        BINARYMIME => Capability::BinaryMime,
                        BURL => Capability::Burl,
                        CHECKPOINT => Capability::Checkpoint,
                        CHUNKING => Capability::Chunking,
                        CONNEG => Capability::Conneg,
                        CONPERM => Capability::Conperm,
                        DELIVERBY => Capability::DeliverBy {
                            min: if parser.stop_char != LF {
                                let db = parser.size()?;
                                if db != usize::MAX {
                                    db as u64
                                } else {
                                    0
                                }
                            } else {
                                0
                            },
                        },
                        DSN => Capability::Dsn,
                        ENHANCEDSTATUSCO
                            if parser.stop_char.to_ascii_uppercase() == b'D'
                                && parser.read_char()?.to_ascii_uppercase() == b'E'
                                && parser.read_char()?.to_ascii_uppercase() == b'S' =>
                        {
                            Capability::EnhancedStatusCodes
                        }
                        ETRN => Capability::Etrn,
                        EXPN => Capability::Expn,
                        FUTURERELEASE => {
                            let max_interval = if parser.stop_char != LF {
                                parser.size()?
                            } else {
                                0
                            };
                            let max_datetime = if parser.stop_char != LF {
                                parser.size()?
                            } else {
                                0
                            };

                            Capability::FutureRelease {
                                max_interval: if max_interval != usize::MAX {
                                    max_interval as u64
                                } else {
                                    0
                                },
                                max_datetime: if max_datetime != usize::MAX {
                                    max_datetime as u64
                                } else {
                                    0
                                },
                            }
                        }
                        HELP => Capability::Help,
                        MT_PRIORITY => Capability::MtPriority {
                            priority: if parser.stop_char != LF {
                                match parser.hashed_value_long()? {
                                    MIXER => MtPriority::Mixer,
                                    STANAG4406 => MtPriority::Stanag4406,
                                    NSEP => MtPriority::Nsep,
                                    _ => MtPriority::Mixer,
                                }
                            } else {
                                MtPriority::Mixer
                            },
                        },
                        MTRK => Capability::Mtrk,
                        NO_SOLICITING => Capability::NoSoliciting {
                            keywords: if parser.stop_char != LF {
                                let text = parser.text()?;
                                if !text.is_empty() {
                                    text.into()
                                } else {
                                    None
                                }
                            } else {
                                None
                            },
                        },
                        ONEX => Capability::Onex,
                        PIPELINING => Capability::Pipelining,
                        REQUIRETLS => Capability::RequireTls,
                        RRVS => Capability::Rrvs,
                        SIZE => Capability::Size {
                            size: if parser.stop_char != LF {
                                let size = parser.size()?;
                                if size != usize::MAX {
                                    size
                                } else {
                                    0
                                }
                            } else {
                                0
                            },
                        },
                        SMTPUTF8 => Capability::SmtpUtf8,
                        STARTTLS => Capability::StartTls,
                        VERB => Capability::Verb,
                        _ => {
                            parser.seek_lf()?;
                            continue;
                        }
                    });
                parser.seek_lf()?;
            } else {
                if is_first_line {
                    is_first_line = false;
                } else if !buf.is_empty() {
                    buf.extend_from_slice(b"\r\n");
                }

                loop {
                    match parser.read_char()? {
                        b'\n' => break,
                        b'\r' => (),
                        b' ' if did_success => {
                            parser.seek_lf()?;
                            break;
                        }
                        ch => {
                            buf.push(ch);
                        }
                    }
                }

                if did_success {
                    response.hostname = buf.into_string();
                    buf = Vec::new();
                }
            }
        }

        if did_success {
            Ok(response)
        } else {
            Err(Error::InvalidResponse {
                response: Response {
                    code,
                    esc: [0, 0, 0],
                    message: buf.into_string(),
                },
            })
        }
    }
}

impl Response<String> {
    pub fn parse(bytes: &mut Iter<'_, u8>, has_esc: bool) -> Result<Response<String>, Error> {
        let mut parser = Rfc5321Parser::new(bytes);
        let mut code = [0u8; 3];
        let mut message = Vec::with_capacity(32);
        let mut esc = [0u8; 3];
        let mut eol = false;

        'outer: while !eol {
            for code in code.iter_mut() {
                match parser.read_char()? {
                    ch @ b'0'..=b'9' => {
                        *code = ch - b'0';
                    }
                    _ => {
                        return Err(Error::SyntaxError {
                            syntax: "unexpected token",
                        })
                    }
                }
            }
            match parser.read_char()? {
                b' ' => {
                    eol = true;
                }
                b'-' => (),
                b'\n' if code[0] < 6 => {
                    break;
                }
                _ => {
                    return Err(Error::SyntaxError {
                        syntax: "unexpected token",
                    });
                }
            }

            let mut esc_parse_error = 0;
            if has_esc {
                if esc[0] == 0 {
                    for (pos, esc) in esc.iter_mut().enumerate() {
                        let val = parser.size()?;
                        *esc = if val < 100 { val as u8 } else { 0 };
                        if pos < 2 && parser.stop_char != b'.' {
                            esc_parse_error = parser.stop_char;
                            break;
                        }
                    }
                    if parser.stop_char == LF {
                        continue;
                    }
                } else {
                    loop {
                        match parser.read_char()? {
                            b'0'..=b'9' | b'.' => (),
                            b'\n' => continue 'outer,
                            _ => break,
                        }
                    }
                }
            }

            if !message.is_empty() && !matches!(message.last(), Some(b' ')) {
                message.push(b' ');
            }
            if esc_parse_error != 0 {
                message.push(esc_parse_error);
            }

            loop {
                match parser.read_char()? {
                    b'\n' => break,
                    b'\r' => (),
                    ch => {
                        message.push(ch);
                    }
                }
            }
        }

        Ok(Response {
            code,
            esc,
            message: message.into_string(),
        })
    }
}

impl Capability {
    pub fn parse(value: &[u8]) -> Option<Capability> {
        if value.eq_ignore_ascii_case(b"8BITMIME") {
            Capability::EightBitMime.into()
        } else if value.eq_ignore_ascii_case(b"ATRN") {
            Capability::Atrn.into()
        } else if value.eq_ignore_ascii_case(b"AUTH") {
            Capability::Auth { mechanisms: 0 }.into()
        } else if value.eq_ignore_ascii_case(b"BINARYMIME") {
            Capability::BinaryMime.into()
        } else if value.eq_ignore_ascii_case(b"BURL") {
            Capability::Burl.into()
        } else if value.eq_ignore_ascii_case(b"CHECKPOINT") {
            Capability::Checkpoint.into()
        } else if value.eq_ignore_ascii_case(b"CHUNKING") {
            Capability::Chunking.into()
        } else if value.eq_ignore_ascii_case(b"CONNEG") {
            Capability::Conneg.into()
        } else if value.eq_ignore_ascii_case(b"CONPERM") {
            Capability::Conperm.into()
        } else if value.eq_ignore_ascii_case(b"DELIVERBY") {
            Capability::DeliverBy { min: 0 }.into()
        } else if value.eq_ignore_ascii_case(b"DSN") {
            Capability::Dsn.into()
        } else if value.eq_ignore_ascii_case(b"ENHANCEDSTATUSCODES") {
            Capability::EnhancedStatusCodes.into()
        } else if value.eq_ignore_ascii_case(b"ETRN") {
            Capability::Etrn.into()
        } else if value.eq_ignore_ascii_case(b"EXPN") {
            Capability::Expn.into()
        } else if value.eq_ignore_ascii_case(b"FUTURERELEASE") {
            Capability::FutureRelease {
                max_interval: 0,
                max_datetime: 0,
            }
            .into()
        } else if value.eq_ignore_ascii_case(b"HELP") {
            Capability::Help.into()
        } else if value.eq_ignore_ascii_case(b"MT-PRIORITY") {
            Capability::MtPriority {
                priority: MtPriority::Mixer,
            }
            .into()
        } else if value.eq_ignore_ascii_case(b"MTRK") {
            Capability::Mtrk.into()
        } else if value.eq_ignore_ascii_case(b"NO-SOLICITING") {
            Capability::NoSoliciting { keywords: None }.into()
        } else if value.eq_ignore_ascii_case(b"ONEX") {
            Capability::Onex.into()
        } else if value.eq_ignore_ascii_case(b"PIPELINING") {
            Capability::Pipelining.into()
        } else if value.eq_ignore_ascii_case(b"REQUIRETLS") {
            Capability::RequireTls.into()
        } else if value.eq_ignore_ascii_case(b"RRVS") {
            Capability::Rrvs.into()
        } else if value.eq_ignore_ascii_case(b"SIZE") {
            Capability::Size { size: 0 }.into()
        } else if value.eq_ignore_ascii_case(b"SMTPUTF8") {
            Capability::SmtpUtf8.into()
        } else if value.eq_ignore_ascii_case(b"STARTTLS") {
            Capability::StartTls.into()
        } else if value.eq_ignore_ascii_case(b"VERB") {
            Capability::Verb.into()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        request::receiver::ReceiverParser, Capability, EhloResponse, Error, MtPriority, Response,
        AUTH_DIGEST_MD5, AUTH_GSSAPI, AUTH_PLAIN,
    };

    #[test]
    fn parse_ehlo() {
        for item in [
            (
                concat!(
                    "250-dbc.mtview.ca.us says hello\n",
                    "250-8BITMIME\n",
                    "250-ATRN\n",
                    "250-AUTH GSSAPI DIGEST-MD5 PLAIN\n",
                    "250-BINARYMIME\n",
                    "250-BURL imap\n",
                    "250-CHECKPOINT\n",
                    "250-CHUNKING\n",
                    "250-CONNEG\n",
                    "250-CONPERM\n",
                    "250-DELIVERBY\n",
                    "250-DELIVERBY 240\n",
                    "250-DSN\n",
                    "250-ENHANCEDSTATUSCODES\n",
                    "250-ETRN\n",
                    "250-EXPN\n",
                    "250-FUTURERELEASE 1234 5678\n",
                    "250-FUTURERELEASE 123\n",
                    "250-FUTURERELEASE\n",
                    "250-HELP\n",
                    "250-MT-PRIORITY\n",
                    "250-MT-PRIORITY MIXER\n",
                    "250-MT-PRIORITY STANAG4406\n",
                    "250-MTRK\n",
                    "250-NO-SOLICITING net.example:ADV\n",
                    "250-NO-SOLICITING\n",
                    "250-PIPELINING\n",
                    "250-REQUIRETLS\n",
                    "250-RRVS\n",
                    "250-SIZE 1000000\n",
                    "250-SIZE\n",
                    "250-SMTPUTF8 ignore\n",
                    "250-SMTPUTF8\n",
                    "250 STARTTLS\n",
                ),
                Ok(EhloResponse {
                    hostname: "dbc.mtview.ca.us".to_string(),
                    capabilities: vec![
                        Capability::EightBitMime,
                        Capability::Atrn,
                        Capability::Auth {
                            mechanisms: AUTH_GSSAPI | AUTH_DIGEST_MD5 | AUTH_PLAIN,
                        },
                        Capability::BinaryMime,
                        Capability::Burl,
                        Capability::Checkpoint,
                        Capability::Chunking,
                        Capability::Conneg,
                        Capability::Conperm,
                        Capability::DeliverBy { min: 0 },
                        Capability::DeliverBy { min: 240 },
                        Capability::Dsn,
                        Capability::EnhancedStatusCodes,
                        Capability::Etrn,
                        Capability::Expn,
                        Capability::FutureRelease {
                            max_interval: 1234,
                            max_datetime: 5678,
                        },
                        Capability::FutureRelease {
                            max_interval: 123,
                            max_datetime: 0,
                        },
                        Capability::FutureRelease {
                            max_interval: 0,
                            max_datetime: 0,
                        },
                        Capability::Help,
                        Capability::MtPriority {
                            priority: MtPriority::Mixer,
                        },
                        Capability::MtPriority {
                            priority: MtPriority::Mixer,
                        },
                        Capability::MtPriority {
                            priority: MtPriority::Stanag4406,
                        },
                        Capability::Mtrk,
                        Capability::NoSoliciting {
                            keywords: Some("net.example:ADV".to_string()),
                        },
                        Capability::NoSoliciting { keywords: None },
                        Capability::Pipelining,
                        Capability::RequireTls,
                        Capability::Rrvs,
                        Capability::Size { size: 1000000 },
                        Capability::Size { size: 0 },
                        Capability::SmtpUtf8,
                        Capability::SmtpUtf8,
                        Capability::StartTls,
                    ],
                }),
            ),
            (
                concat!("523-Massive\n", "523-Error\n", "523 Message\n"),
                Err(Error::InvalidResponse {
                    response: Response {
                        code: [5, 2, 3],
                        esc: [0, 0, 0],
                        message: "Massive\r\nError\r\nMessage".to_string(),
                    },
                }),
            ),
        ] {
            let (response, parsed_response): (&str, Result<EhloResponse<String>, Error>) = item;

            for replacement in ["", "\r\n", " \n", " \r\n"] {
                let response = if !replacement.is_empty() && parsed_response.is_ok() {
                    response.replace('\n', replacement)
                } else {
                    response.to_string()
                };
                assert_eq!(
                    parsed_response,
                    EhloResponse::parse(&mut response.as_bytes().iter()),
                    "failed for {:?}",
                    response
                );
            }
        }
    }

    #[test]
    fn parse_response() {
        for (response, parsed_response, has_esc) in [
            (
                "250 2.1.1 Originator <ned@ymir.claremont.edu> ok\n",
                Response {
                    code: [2, 5, 0],
                    esc: [2, 1, 1],
                    message: "Originator <ned@ymir.claremont.edu> ok".to_string(),
                },
                true,
            ),
            (
                concat!(
                    "551-5.7.1 Forwarding to remote hosts disabled\n",
                    "551 5.7.1 Select another host to act as your forwarder\n"
                ),
                Response {
                    code: [5, 5, 1],
                    esc: [5, 7, 1],
                    message: concat!(
                        "Forwarding to remote hosts disabled ",
                        "Select another host to act as your forwarder"
                    )
                    .to_string(),
                },
                true,
            ),
            (
                concat!(
                    "550-mailbox unavailable\n",
                    "550 user has moved with no forwarding address\n"
                ),
                Response {
                    code: [5, 5, 0],
                    esc: [0, 0, 0],
                    message: "mailbox unavailable user has moved with no forwarding address"
                        .to_string(),
                },
                false,
            ),
            (
                concat!(
                    "550-mailbox unavailable\n",
                    "550 user has moved with no forwarding address\n"
                ),
                Response {
                    code: [5, 5, 0],
                    esc: [0, 0, 0],
                    message: "mailbox unavailable user has moved with no forwarding address"
                        .to_string(),
                },
                true,
            ),
            (
                concat!(
                    "432-6.8.9\n",
                    "432-6.8.9 Hello\n",
                    "432-6.8.9 \n",
                    "432-6.8.9 ,\n",
                    "432-\n",
                    "432-6\n",
                    "432-6.\n",
                    "432-6.8\n",
                    "432-6.8.9\n",
                    "432 6.8.9 World!\n"
                ),
                Response {
                    code: [4, 3, 2],
                    esc: [6, 8, 9],
                    message: "Hello , World!".to_string(),
                },
                true,
            ),
            (
                concat!("250-Missing space\n", "250\n", "250 Ignore this"),
                Response {
                    code: [2, 5, 0],
                    esc: [0, 0, 0],
                    message: "Missing space".to_string(),
                },
                true,
            ),
        ] {
            assert_eq!(
                parsed_response,
                Response::parse(&mut response.as_bytes().iter(), has_esc).unwrap(),
                "failed for {:?}",
                response
            );
        }
    }
}

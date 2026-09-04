/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::*;
use crate::{request::parser::Rfc5321Parser, *};
use memchr::memchr2;
use std::slice::Iter;

pub const MAX_RESPONSE_LENGTH: usize = 4096;
const MULTILINE_RESERVE: usize = 128;
const CONTINUATION_RESERVE: usize = 64;

#[derive(Default)]
pub struct ResponseReceiver {
    buf: Vec<u8>,
    code: u16,
    esc: [u8; 3],
    esc_cur: [u8; 3],
    esc_restore: [u8; 10],
    esc_pos: usize,
    is_last: bool,
    pos: usize,
}

impl ResponseReceiver {
    pub fn from_code(code: u16) -> Self {
        Self {
            code,
            esc: [0u8; 3],
            esc_cur: [0u8; 3],
            esc_restore: [0u8; 10],
            esc_pos: 0,
            pos: 3,
            is_last: false,
            buf: Vec::new(),
        }
    }

    pub fn parse(&mut self, bytes: &mut Iter<'_, u8>) -> Result<Response<String>, Error> {
        let mut rest = bytes.as_slice();
        let result = loop {
            if self.pos > 6 {
                let end = line_end(rest);
                if end != 0 {
                    let available = MAX_RESPONSE_LENGTH.saturating_sub(self.buf.len());
                    if end <= available {
                        let (run, tail) = rest.split_at(end);
                        self.buf.extend_from_slice(run);
                        rest = tail;
                    } else {
                        let (run, tail) = rest.split_at(available);
                        self.buf.extend_from_slice(run);
                        rest = tail.get(1..).unwrap_or_default();
                        break Err(Error::ResponseTooLong);
                    }
                }
            } else if self.pos == 0
                && let [d0, d1, d2, sep, tail @ ..] = rest
                && d0.is_ascii_digit()
                && d1.is_ascii_digit()
                && d2.is_ascii_digit()
                && matches!(*sep, b' ' | b'-')
            {
                if self.buf.is_empty() {
                    self.code = self
                        .code
                        .saturating_mul(10)
                        .saturating_add((d0 - b'0') as u16)
                        .saturating_mul(10)
                        .saturating_add((d1 - b'0') as u16)
                        .saturating_mul(10)
                        .saturating_add((d2 - b'0') as u16);
                    if *sep == b'-' {
                        self.buf.reserve(MULTILINE_RESERVE);
                    }
                }
                self.is_last |= *sep == b' ';
                self.pos = 4;
                rest = tail;
                continue;
            } else if self.pos == 4 && self.esc_pos == 0 {
                if let Some(ch) = rest.first()
                    && !matches!(ch, b'0'..=b'9' | b'.' | b'\r' | b'\n')
                    && self.buf.len() < MAX_RESPONSE_LENGTH
                {
                    self.pos = 7;
                    continue;
                }
                if let [class, b'.', subject, b'.', detail, separator, tail @ ..] = rest
                    && class.is_ascii_digit()
                    && subject.is_ascii_digit()
                    && detail.is_ascii_digit()
                    && matches!(*separator, b' ' | b'\r')
                {
                    self.esc = [class - b'0', subject - b'0', detail - b'0'];
                    self.pos = 7;
                    rest = tail;
                    continue;
                }
            }

            let [ch, tail @ ..] = rest else {
                break Err(Error::NeedsMoreData { bytes_left: 0 });
            };
            let ch = *ch;
            rest = tail;

            match self.pos {
                0..=2 => {
                    if ch.is_ascii_digit() {
                        if self.buf.is_empty() {
                            self.code = self
                                .code
                                .saturating_mul(10)
                                .saturating_add((ch - b'0') as u16);
                        }
                        self.pos += 1;
                    } else {
                        break Err(Error::SyntaxError {
                            syntax: "Invalid response code",
                        });
                    }
                }
                3 => match ch {
                    b' ' => {
                        self.is_last = true;
                        self.pos += 1;
                    }
                    b'-' => {
                        if self.buf.is_empty() {
                            self.buf.reserve(MULTILINE_RESERVE);
                        }
                        self.pos += 1;
                    }
                    b'\r' => (),
                    b'\n' => {
                        self.is_last = true;
                    }
                    _ => {
                        break Err(Error::SyntaxError {
                            syntax: "Invalid response separator",
                        });
                    }
                },
                4..=6 => {
                    let mut do_restore = false;

                    match ch {
                        b'0'..=b'9' => {
                            let code = &mut self.esc_cur[self.pos - 4];
                            if *code < 100 {
                                if let Some(restore) = self.esc_restore.get_mut(self.esc_pos) {
                                    *restore = ch;
                                    *code = code.saturating_mul(10).saturating_add(ch - b'0');
                                    self.esc_pos += 1;
                                } else {
                                    do_restore = true;
                                }
                            } else {
                                do_restore = true;
                            }
                        }
                        b'.' if self.pos < 6 => {
                            if let Some(restore) = self.esc_restore.get_mut(self.esc_pos) {
                                *restore = ch;
                                self.pos += 1;
                                self.esc_pos += 1;
                            } else {
                                do_restore = true;
                            }
                        }
                        b' ' | b'\r' | b'\n' if self.pos == 6 => {
                            self.esc = self.esc_cur;
                            self.esc_cur.fill(0);
                            self.pos = 7;
                            self.esc_pos = 0;
                        }
                        _ => {
                            do_restore = true;
                        }
                    }
                    if do_restore {
                        if self.esc_pos > 0 {
                            self.buf
                                .extend_from_slice(&self.esc_restore[..self.esc_pos]);
                        }
                        self.buf.push(ch);
                        self.pos = 7;
                        self.esc_pos = 0;
                        self.esc_cur.fill(0);
                    }
                }
                _ => (),
            }

            if ch == b'\n' {
                if self.is_last {
                    break Ok(Response {
                        code: self.code,
                        esc: self.esc,
                        message: std::mem::take(&mut self.buf).into_string(),
                    });
                } else {
                    self.buf.reserve(CONTINUATION_RESERVE);
                    self.buf.push(b'\n');
                    self.pos = 0;
                }
            }
        };
        *bytes = rest.iter();
        result
    }

    pub fn reset(&mut self) {
        self.is_last = false;
        self.code = 0;
        self.esc.fill(0);
        self.esc_cur.fill(0);
        self.pos = 0;
        self.esc_pos = 0;
        self.buf.clear();
    }
}

impl EhloResponse<String> {
    fn parse_first_line(
        rest: &mut &[u8],
        bytes_left: usize,
        hostname: &mut String,
    ) -> Result<bool, Error> {
        let mut code: u16 = 0;
        for _ in 0..3 {
            let [ch, tail @ ..] = *rest else {
                return Err(Error::NeedsMoreData { bytes_left });
            };
            *rest = tail;
            if !ch.is_ascii_digit() {
                return Err(Error::SyntaxError {
                    syntax: "unexpected token",
                });
            }
            code = code.saturating_mul(10).saturating_add((ch - b'0') as u16);
        }

        if code != 250 {
            return Err(Error::InvalidResponse { code });
        }

        let [separator, tail @ ..] = *rest else {
            return Err(Error::NeedsMoreData { bytes_left });
        };
        *rest = tail;
        let eol = match *separator {
            b' ' => true,
            b'-' => false,
            b'\n' => return Ok(true),
            _ => {
                return Err(Error::SyntaxError {
                    syntax: "unexpected token",
                });
            }
        };

        let mut buf = Vec::new();
        loop {
            let end = rest
                .iter()
                .position(|&ch| matches!(ch, b' ' | b'\r' | b'\n'))
                .unwrap_or(rest.len());
            if end > MAX_RESPONSE_LENGTH.saturating_sub(buf.len()) {
                *rest = rest
                    .get(MAX_RESPONSE_LENGTH.saturating_sub(buf.len()) + 1..)
                    .unwrap_or_default();
                return Err(Error::ResponseTooLong);
            }
            let (run, tail) = rest.split_at(end);
            buf.extend_from_slice(run);
            let [ch, tail @ ..] = tail else {
                *rest = tail;
                return Err(Error::NeedsMoreData { bytes_left });
            };
            *rest = tail;
            match *ch {
                b'\r' => (),
                b'\n' => break,
                _ => {
                    let Some(lf) = rest.iter().position(|&ch| ch == b'\n') else {
                        *rest = &[];
                        return Err(Error::NeedsMoreData { bytes_left });
                    };
                    *rest = rest.get(lf + 1..).unwrap_or_default();
                    break;
                }
            }
        }

        *hostname = buf.into_string();
        Ok(eol)
    }

    pub fn parse(bytes: &mut Iter<'_, u8>) -> Result<Self, Error> {
        let bytes_left = bytes.len();
        let mut response = EhloResponse::default();
        let mut rest = bytes.as_slice();
        let first_line = Self::parse_first_line(&mut rest, bytes_left, &mut response.hostname);
        *bytes = rest.iter();
        let mut eol = first_line?;

        let mut parser = Rfc5321Parser::new(bytes);
        parser.bytes_left = bytes_left;

        while !eol {
            let mut code: u16 = 0;
            for _ in 0..3 {
                match parser.read_char()? {
                    ch @ b'0'..=b'9' => {
                        code = code.saturating_mul(10).saturating_add((ch - b'0') as u16);
                    }
                    _ => {
                        return Err(Error::SyntaxError {
                            syntax: "unexpected token",
                        });
                    }
                }
            }

            if code != 250 {
                return Err(Error::InvalidResponse { code });
            }

            match parser.read_char()? {
                b' ' => {
                    eol = true;
                }
                b'-' => (),
                b'\n' if code < 600 => {
                    break;
                }
                _ => {
                    return Err(Error::SyntaxError {
                        syntax: "unexpected token",
                    });
                }
            }

            response.capabilities |= match parser.hashed_value_long()? {
                _8BITMIME => EXT_8BIT_MIME,
                ATRN => EXT_ATRN,
                AUTH => {
                    while parser.stop_char != LF {
                        if let Some(mechanism) = parser.mechanism()? {
                            response.auth_mechanisms |= mechanism;
                        }
                    }

                    EXT_AUTH
                }
                BINARYMIME => EXT_BINARY_MIME,
                BURL => EXT_BURL,
                CHECKPOINT => EXT_CHECKPOINT,
                CHUNKING => EXT_CHUNKING,
                CONNEG => EXT_CONNEG,
                CONPERM => EXT_CONPERM,
                DELIVERBY => {
                    response.deliver_by = if parser.stop_char != LF {
                        let db = parser.size()?;
                        if db != usize::MAX { db as u64 } else { 0 }
                    } else {
                        0
                    };
                    EXT_DELIVER_BY
                }
                DSN => EXT_DSN,
                ENHANCEDSTATUSCO
                    if parser.stop_char.eq_ignore_ascii_case(&b'D')
                        && parser.read_char()?.eq_ignore_ascii_case(&b'E')
                        && parser.read_char()?.eq_ignore_ascii_case(&b'S') =>
                {
                    EXT_ENHANCED_STATUS_CODES
                }
                ETRN => EXT_ETRN,
                EXPN => EXT_EXPN,
                VRFY => EXT_VRFY,
                FUTURERELEASE => {
                    let max_interval = if parser.stop_char != LF {
                        parser.size()?
                    } else {
                        0
                    };
                    let max_datetime = if parser.stop_char != LF {
                        parser.timestamp()?
                    } else {
                        0
                    };

                    response.future_release_interval = if max_interval != usize::MAX {
                        max_interval as u64
                    } else {
                        0
                    };
                    response.future_release_datetime = if max_datetime != i64::MAX {
                        max_datetime.max(0) as u64
                    } else {
                        0
                    };
                    EXT_FUTURE_RELEASE
                }
                HELP => EXT_HELP,
                MT_PRIORITY => {
                    response.mt_priority = if parser.stop_char != LF {
                        match parser.hashed_value_long()? {
                            MIXER => MtPriority::Mixer,
                            STANAG4406 => MtPriority::Stanag4406,
                            NSEP => MtPriority::Nsep,
                            _ => MtPriority::Mixer,
                        }
                    } else {
                        MtPriority::Mixer
                    };
                    EXT_MT_PRIORITY
                }
                MTRK => EXT_MTRK,
                NO_SOLICITING => {
                    response.no_soliciting = if parser.stop_char != LF {
                        let text = parser.text()?;
                        if !text.is_empty() {
                            text.into_owned().into()
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    EXT_NO_SOLICITING
                }
                ONEX => EXT_ONEX,
                PIPELINING => EXT_PIPELINING,
                REQUIRETLS => EXT_REQUIRE_TLS,
                RRVS => EXT_RRVS,
                SIZE => {
                    response.size = if parser.stop_char != LF {
                        let size = parser.size()?;
                        if size != usize::MAX { size } else { 0 }
                    } else {
                        0
                    };
                    EXT_SIZE
                }
                SMTPUTF8 => EXT_SMTP_UTF8,
                STARTTLS => EXT_START_TLS,
                VERB => EXT_VERB,
                _ => 0,
            };
            parser.seek_lf()?;
        }

        Ok(response)
    }
}

#[inline(always)]
fn line_end(bytes: &[u8]) -> usize {
    memchr2(b'\r', b'\n', bytes).unwrap_or(bytes.len())
}

#[cfg(test)]
mod tests {
    use crate::*;

    use super::ResponseReceiver;

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
                    "250-DSN\n",
                    "250-ENHANCEDSTATUSCODES\n",
                    "250-ETRN\n",
                    "250-EXPN\n",
                    "250-VRFY\n",
                    "250-FUTURERELEASE 1234 2026-08-10T03:00:00Z\n",
                    "250-HELP\n",
                    "250-MT-PRIORITY\n",
                    "250-MTRK\n",
                    "250-NO-SOLICITING net.example:ADV\n",
                    "250-PIPELINING\n",
                    "250-REQUIRETLS\n",
                    "250-RRVS\n",
                    "250-SIZE 1000000\n",
                    "250-SMTPUTF8 ignore\n",
                    "250 STARTTLS\n",
                ),
                Ok(EhloResponse {
                    hostname: "dbc.mtview.ca.us".to_string(),
                    capabilities: EXT_8BIT_MIME
                        | EXT_ATRN
                        | EXT_AUTH
                        | EXT_BINARY_MIME
                        | EXT_BURL
                        | EXT_CHECKPOINT
                        | EXT_CHUNKING
                        | EXT_CONNEG
                        | EXT_CONPERM
                        | EXT_DELIVER_BY
                        | EXT_DSN
                        | EXT_ENHANCED_STATUS_CODES
                        | EXT_ETRN
                        | EXT_EXPN
                        | EXT_VRFY
                        | EXT_FUTURE_RELEASE
                        | EXT_HELP
                        | EXT_MT_PRIORITY
                        | EXT_MTRK
                        | EXT_NO_SOLICITING
                        | EXT_PIPELINING
                        | EXT_REQUIRE_TLS
                        | EXT_RRVS
                        | EXT_SIZE
                        | EXT_SMTP_UTF8
                        | EXT_START_TLS,
                    auth_mechanisms: AUTH_GSSAPI | AUTH_DIGEST_MD5 | AUTH_PLAIN,
                    deliver_by: 0,
                    future_release_interval: 1234,
                    future_release_datetime: 1786330800,
                    mt_priority: MtPriority::Mixer,
                    no_soliciting: Some("net.example:ADV".to_string()),
                    size: 1000000,
                }),
            ),
            (
                concat!(
                    "250-\n",
                    "250-DELIVERBY 240\n",
                    "250-FUTURERELEASE 123\n",
                    "250-MT-PRIORITY MIXER\n",
                    "250-NO-SOLICITING\n",
                    "250-SIZE\n",
                    "250 SMTPUTF8\n",
                ),
                Ok(EhloResponse {
                    hostname: "".to_string(),
                    capabilities: EXT_DELIVER_BY
                        | EXT_FUTURE_RELEASE
                        | EXT_MT_PRIORITY
                        | EXT_NO_SOLICITING
                        | EXT_SIZE
                        | EXT_SMTP_UTF8,
                    auth_mechanisms: 0,
                    deliver_by: 240,
                    future_release_interval: 123,
                    future_release_datetime: 0,
                    mt_priority: MtPriority::Mixer,
                    no_soliciting: None,
                    size: 0,
                }),
            ),
            (
                concat!(
                    "250-dbc.mtview.ca.us says hello\n",
                    "250-FUTURERELEASE\n",
                    "250 MT-PRIORITY STANAG4406\n",
                ),
                Ok(EhloResponse {
                    hostname: "dbc.mtview.ca.us".to_string(),
                    capabilities: EXT_FUTURE_RELEASE | EXT_MT_PRIORITY,
                    auth_mechanisms: 0,
                    deliver_by: 0,
                    future_release_interval: 0,
                    future_release_datetime: 0,
                    mt_priority: MtPriority::Stanag4406,
                    no_soliciting: None,
                    size: 0,
                }),
            ),
            (
                concat!("523-Massive\n", "523-Error\n", "523 Message\n"),
                Err(Error::InvalidResponse { code: 523 }),
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
                    "failed for {response:?}",
                );
            }
        }
    }

    #[test]
    fn parse_response() {
        let mut all_responses = Vec::new();
        let mut all_parsed_responses = Vec::new();

        for (response, parsed_response, _) in [
            (
                "250 2.1.1 Originator <ned@ymir.claremont.edu> ok\n",
                Response {
                    code: 250,
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
                    code: 551,
                    esc: [5, 7, 1],
                    message: concat!(
                        "Forwarding to remote hosts disabled\n",
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
                    code: 550,
                    esc: [0, 0, 0],
                    message: "mailbox unavailable\nuser has moved with no forwarding address"
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
                    code: 550,
                    esc: [0, 0, 0],
                    message: "mailbox unavailable\nuser has moved with no forwarding address"
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
                    code: 432,
                    esc: [6, 8, 9],
                    message: "\nHello\n\n,\n\n\n6\n\n6.\n\n6.8\n\n\nWorld!".to_string(),
                },
                true,
            ),
            (
                "250 2address.org\n",
                Response {
                    code: 250,
                    esc: [0, 0, 0],
                    message: "2address.org".to_string(),
                },
                true,
            ),
            (
                "250 100.address.org\n",
                Response {
                    code: 250,
                    esc: [0, 0, 0],
                    message: "100.address.org".to_string(),
                },
                true,
            ),
            (
                "250 111111111111\n",
                Response {
                    code: 250,
                    esc: [0, 0, 0],
                    message: "111111111111".to_string(),
                },
                true,
            ),
            (
                "250 99999999999999\n",
                Response {
                    code: 250,
                    esc: [0, 0, 0],
                    message: "99999999999999".to_string(),
                },
                true,
            ),
            (
                "250 2.0.0 Message queued for delivery.\r\n",
                Response {
                    code: 250,
                    esc: [2, 0, 0],
                    message: "Message queued for delivery.".to_string(),
                },
                true,
            ),
            (
                concat!("250-Missing space\n", "250\n", "250 Ignore this"),
                Response {
                    code: 250,
                    esc: [0, 0, 0],
                    message: "Missing space\n".to_string(),
                },
                true,
            ),
        ] {
            assert_eq!(
                parsed_response,
                ResponseReceiver::default()
                    .parse(&mut response.as_bytes().iter())
                    .unwrap(),
                "failed for {response:?}",
            );
            all_responses.extend_from_slice(response.as_bytes());
            all_parsed_responses.push(parsed_response);
        }

        // Test receiver
        for chunk_size in [5, 10, 20, 30, 40, 50, 60] {
            let mut receiver = ResponseReceiver::default();
            let mut parsed_response = all_parsed_responses.clone().into_iter();
            for chunk in all_responses.chunks(chunk_size) {
                let mut bytes = chunk.iter();
                loop {
                    match receiver.parse(&mut bytes) {
                        Ok(response) => {
                            assert_eq!(
                                parsed_response.next(),
                                Some(response),
                                "chunk size {chunk_size}",
                            );
                            receiver.reset();
                        }
                        Err(Error::NeedsMoreData { .. }) => {
                            break;
                        }
                        err => panic!("Unexpected error {err:?} for chunk size {chunk_size}"),
                    }
                }
            }
        }
    }
}

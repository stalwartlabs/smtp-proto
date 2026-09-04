/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::{Error, Request};
use memchr::{memchr, memchr2, memmem};
use std::{borrow::Cow, slice::Iter};

pub const MAX_LINE_LENGTH: usize = 4096;

#[derive(Default)]
pub struct RequestReceiver {
    buf: Vec<u8>,
    buf_used: bool,
}

pub struct DataReceiver {
    state: DataState,
}

pub struct BdatReceiver {
    pub is_last: bool,
    bytes_left: usize,
}

pub struct DummyDataReceiver {
    is_bdat: bool,
    bdat_bytes_left: usize,
    state: DataState,
}

#[derive(Clone, Copy)]
struct DataState {
    crlf_dot: bool,
    last_ch: u8,
    prev_last_ch: u8,
}

struct Discard;

trait DataSink {
    fn push_byte(&mut self, ch: u8);

    fn push_slice(&mut self, bytes: &[u8]);

    fn pop_byte(&mut self);

    fn take_chunk(&mut self, bytes: &mut Iter<'_, u8>, bytes_left: &mut usize) -> bool {
        let rest = bytes.as_slice();
        let (chunk, tail) = rest.split_at(rest.len().min(*bytes_left));
        self.push_slice(chunk);
        *bytes_left -= chunk.len();
        *bytes = tail.iter();
        *bytes_left == 0
    }
}

impl DataSink for Vec<u8> {
    fn push_byte(&mut self, ch: u8) {
        self.push(ch);
    }

    fn push_slice(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }

    fn pop_byte(&mut self) {
        self.pop();
    }
}

impl DataSink for Discard {
    fn push_byte(&mut self, _: u8) {}

    fn push_slice(&mut self, _: &[u8]) {}

    fn pop_byte(&mut self) {}
}

impl DataState {
    fn new() -> Self {
        Self {
            crlf_dot: false,
            last_ch: 0,
            prev_last_ch: 0,
        }
    }

    fn advance(&mut self, chunk: &[u8]) {
        if let Some((&last, head)) = chunk.split_last() {
            self.prev_last_ch = head.last().copied().unwrap_or(self.last_ch);
            self.last_ch = last;
        }
    }

    fn ingest<S: DataSink>(&mut self, bytes: &mut Iter<'_, u8>, sink: &mut S) -> bool {
        let mut rest = bytes.as_slice();

        loop {
            if self.last_ch == b'\n'
                && self.prev_last_ch == b'\r'
                && let [b'.', tail @ ..] = rest
            {
                self.crlf_dot = true;
                self.prev_last_ch = b'\n';
                self.last_ch = b'.';
                rest = tail;
            }

            while self.crlf_dot {
                let Some((&ch, tail)) = rest.split_first() else {
                    *bytes = rest.iter();
                    return false;
                };
                rest = tail;

                if ch == b'\n' && self.last_ch == b'\r' {
                    sink.pop_byte();
                    *bytes = rest.iter();
                    return true;
                }

                sink.push_byte(ch);
                self.crlf_dot = ch == b'\r';
                self.prev_last_ch = self.last_ch;
                self.last_ch = ch;
            }

            let Some(pos) = find_stuffed_newline(rest) else {
                sink.push_slice(rest);
                self.advance(rest);
                *bytes = [].iter();
                return false;
            };

            let (line, tail) = rest.split_at(pos + 1);
            sink.push_slice(line);
            self.advance(line);
            rest = tail;
        }
    }
}

#[inline(always)]
fn find_stuffed_newline(haystack: &[u8]) -> Option<usize> {
    memmem::find(haystack, b"\n.")
}

#[derive(Default)]
pub struct DummyLineReceiver {}

#[derive(Default)]
pub struct LineReceiver<T> {
    pub buf: Vec<u8>,
    pub state: T,
}

impl RequestReceiver {
    pub fn buf(&mut self) -> &mut Vec<u8> {
        if self.buf_used {
            self.buf.clear();
            self.buf_used = false;
        }

        &mut self.buf
    }

    pub fn ingest<'this, 'bytes, 'out>(
        &'this mut self,
        bytes: &mut Iter<'bytes, u8>,
    ) -> Result<Request<Cow<'out, str>>, Error>
    where
        'this: 'out,
        'bytes: 'out,
    {
        self.buf();

        if self.buf.is_empty() {
            let buf = bytes.as_slice();
            match Request::parse(bytes) {
                Err(Error::NeedsMoreData { bytes_left }) => {
                    if bytes_left > 0 {
                        if bytes_left < MAX_LINE_LENGTH {
                            self.buf = buf[buf.len().saturating_sub(bytes_left)..].to_vec();
                        } else {
                            return Err(Error::ResponseTooLong);
                        }
                    }
                }
                result => return result,
            }
        } else {
            let rest = bytes.as_slice();
            let free = MAX_LINE_LENGTH.saturating_sub(self.buf.len());
            let newline = memchr(b'\n', rest);

            if let Some(pos) = newline.filter(|&pos| pos < free || free == 0) {
                let (line, tail) = rest.split_at(pos + 1);
                self.buf.extend_from_slice(line);
                *bytes = tail.iter();
                self.buf_used = true;
                return Request::parse(&mut self.buf.iter());
            } else if free > 0 && rest.len() >= free {
                *bytes = rest.split_at(free).1.iter();
                self.buf.clear();
                return Err(Error::ResponseTooLong);
            }

            self.buf.extend_from_slice(rest);
            *bytes = [].iter();
        }

        Err(Error::NeedsMoreData { bytes_left: 0 })
    }
}

impl DataReceiver {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            state: DataState::new(),
        }
    }

    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>, buf: &mut Vec<u8>) -> bool {
        self.state.ingest(bytes, buf)
    }
}

impl BdatReceiver {
    pub fn new(chunk_size: usize, is_last: bool) -> Self {
        Self {
            bytes_left: chunk_size,
            is_last,
        }
    }

    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>, buf: &mut Vec<u8>) -> bool {
        buf.take_chunk(bytes, &mut self.bytes_left)
    }
}

impl DummyDataReceiver {
    pub fn new_bdat(chunk_size: usize) -> Self {
        Self {
            bdat_bytes_left: chunk_size,
            is_bdat: true,
            state: DataState::new(),
        }
    }

    pub fn new_data(data: &DataReceiver) -> Self {
        Self {
            is_bdat: false,
            bdat_bytes_left: 0,
            state: data.state,
        }
    }

    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>) -> bool {
        if !self.is_bdat {
            self.state.ingest(bytes, &mut Discard)
        } else {
            Discard.take_chunk(bytes, &mut self.bdat_bytes_left)
        }
    }
}

impl<T> LineReceiver<T> {
    pub fn new(state: T) -> Self {
        Self {
            buf: Vec::with_capacity(32),
            state,
        }
    }

    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>) -> bool {
        let mut rest = bytes.as_slice();

        loop {
            let Some(pos) = memchr2(b'\n', b'\r', rest) else {
                self.push_capped(rest);
                *bytes = [].iter();
                return false;
            };

            let (head, tail) = rest.split_at(pos);
            self.push_capped(head);

            let Some((&ch, tail)) = tail.split_first() else {
                *bytes = [].iter();
                return false;
            };
            rest = tail;

            if ch == b'\n' {
                *bytes = rest.iter();
                return true;
            }
        }
    }

    fn push_capped(&mut self, chunk: &[u8]) {
        let free = MAX_LINE_LENGTH.saturating_sub(self.buf.len());
        self.buf.extend_from_slice(&chunk[..chunk.len().min(free)]);
    }
}

impl DummyLineReceiver {
    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>) -> bool {
        let rest = bytes.as_slice();

        match memchr(b'\n', rest) {
            Some(pos) => {
                *bytes = rest.split_at(pos + 1).1.iter();
                true
            }
            None => {
                *bytes = [].iter();
                false
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DataReceiver;
    use crate::{Error, MailFrom, RcptTo, Request, request::receiver::RequestReceiver};

    #[test]
    fn data_receiver() {
        'outer: for (data, message) in [
            (
                vec!["hi\r\n", "..\r\n", ".a\r\n", "\r\n.\r\n"],
                "hi\r\n.\r\na\r\n\r\n",
            ),
            (
                vec!["\r\na\rb\nc\r\n.d\r\n..\r\n", "\r\n.\r\n"],
                "\r\na\rb\nc\r\nd\r\n.\r\n\r\n",
            ),
            // Test SMTP smuggling attempts
            (
                vec![
                    "\n.\r\n",
                    "MAIL FROM:<hello@world.com>\r\n",
                    "RCPT TO:<test@domain.com\r\n",
                    "DATA\r\n",
                    "\r\n.\r\n",
                ],
                concat!(
                    "\n.\r\n",
                    "MAIL FROM:<hello@world.com>\r\n",
                    "RCPT TO:<test@domain.com\r\n",
                    "DATA\r\n",
                    "\r\n",
                ),
            ),
            (
                vec![
                    "\n.\n",
                    "MAIL FROM:<hello@world.com>\r\n",
                    "RCPT TO:<test@domain.com\r\n",
                    "DATA\r\n",
                    "\r\n.\r\n",
                ],
                concat!(
                    "\n.\n",
                    "MAIL FROM:<hello@world.com>\r\n",
                    "RCPT TO:<test@domain.com\r\n",
                    "DATA\r\n",
                    "\r\n",
                ),
            ),
            (
                vec![
                    "\r.\r\n",
                    "MAIL FROM:<hello@world.com>\r\n",
                    "RCPT TO:<test@domain.com\r\n",
                    "DATA\r\n",
                    "\r\n.\r\n",
                ],
                concat!(
                    "\r.\r\n",
                    "MAIL FROM:<hello@world.com>\r\n",
                    "RCPT TO:<test@domain.com\r\n",
                    "DATA\r\n",
                    "\r\n",
                ),
            ),
            (
                vec![
                    "\r.\r",
                    "MAIL FROM:<hello@world.com>\r\n",
                    "RCPT TO:<test@domain.com\r\n",
                    "DATA\r\n",
                    "\r\n.\r\n",
                ],
                concat!(
                    "\r.\r",
                    "MAIL FROM:<hello@world.com>\r\n",
                    "RCPT TO:<test@domain.com\r\n",
                    "DATA\r\n",
                    "\r\n",
                ),
            ),
        ] {
            let mut r = DataReceiver::new();
            let mut buf = Vec::new();
            for data in &data {
                if r.ingest(&mut data.as_bytes().iter(), &mut buf) {
                    assert_eq!(message, String::from_utf8(buf).unwrap());
                    continue 'outer;
                }
            }
            panic!("Failed for {data:?}");
        }
    }

    #[test]
    fn request_receiver() {
        for (data, expected_requests) in [
            (
                vec![
                    "data\n",
                    "start",
                    "tls\n",
                    "quit\nnoop",
                    " hello\nehlo test\nvrfy name\n",
                    "mail from:<hello",
                    "@world.com>\nrcpt to:<",
                    "test@domain.com>\n",
                ],
                vec![
                    Request::Data,
                    Request::StartTls,
                    Request::Quit,
                    Request::Noop {
                        value: "hello".to_string(),
                    },
                    Request::Ehlo {
                        host: "test".to_string(),
                    },
                    Request::Vrfy {
                        value: "name".to_string(),
                    },
                    Request::Mail {
                        from: MailFrom {
                            address: "hello@world.com".to_string(),
                            flags: 0,
                            size: 0,
                            trans_id: None,
                            by: 0,
                            env_id: None,
                            solicit: None,
                            mtrk: None,
                            auth: None,
                            hold_for: 0,
                            hold_until: 0,
                            mt_priority: 0,
                        },
                    },
                    Request::Rcpt {
                        to: RcptTo {
                            address: "test@domain.com".to_string(),
                            orcpt: None,
                            rrvs: 0,
                            flags: 0,
                        },
                    },
                ],
            ),
            (
                vec!["d", "a", "t", "a", "\n", "quit", "\n"],
                vec![Request::Data, Request::Quit],
            ),
        ] {
            let mut requests = Vec::new();
            let mut r = RequestReceiver::default();
            for data in &data {
                let mut bytes = data.as_bytes().iter();
                loop {
                    match r.ingest(&mut bytes) {
                        Ok(request) => {
                            requests.push(request.into_owned());
                            continue;
                        }
                        Err(Error::NeedsMoreData { .. }) => {
                            break;
                        }
                        err => panic!("Unexpected error for {data:?}: {err:?}"),
                    }
                }
            }
            assert_eq!(expected_requests, requests);
        }
    }
}

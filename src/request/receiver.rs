/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::slice::Iter;

use crate::{Error, Request};

pub const MAX_LINE_LENGTH: usize = 2048;

#[derive(Default)]
pub struct RequestReceiver {
    pub buf: Vec<u8>,
}

pub struct DataReceiver {
    crlf_dot: bool,
    last_ch: u8,
    prev_last_ch: u8,
}

pub struct BdatReceiver {
    pub is_last: bool,
    bytes_left: usize,
}

pub struct DummyDataReceiver {
    is_bdat: bool,
    bdat_bytes_left: usize,
    crlf_dot: bool,
    last_ch: u8,
    prev_last_ch: u8,
}

#[derive(Default)]
pub struct DummyLineReceiver {}

#[derive(Default)]
pub struct LineReceiver<T> {
    pub buf: Vec<u8>,
    pub state: T,
}

impl RequestReceiver {
    pub fn ingest(
        &mut self,
        bytes: &mut Iter<'_, u8>,
        buf: &[u8],
    ) -> Result<Request<String>, Error> {
        if self.buf.is_empty() {
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
            for &ch in bytes {
                self.buf.push(ch);
                if ch == b'\n' {
                    let result = Request::parse(&mut self.buf.iter());
                    self.buf.clear();
                    return result;
                } else if self.buf.len() == MAX_LINE_LENGTH {
                    self.buf.clear();
                    return Err(Error::ResponseTooLong);
                }
            }
        }

        Err(Error::NeedsMoreData { bytes_left: 0 })
    }
}

impl DataReceiver {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            crlf_dot: false,
            last_ch: 0,
            prev_last_ch: 0,
        }
    }

    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>, buf: &mut Vec<u8>) -> bool {
        for &ch in bytes {
            match ch {
                b'.' if self.last_ch == b'\n' && self.prev_last_ch == b'\r' => {
                    self.crlf_dot = true;
                }
                b'\n' if self.crlf_dot && self.last_ch == b'\r' => {
                    buf.truncate(buf.len() - 3);
                    return true;
                }
                b'\r' => {
                    buf.push(ch);
                }
                _ => {
                    buf.push(ch);
                    self.crlf_dot = false;
                }
            }
            self.prev_last_ch = self.last_ch;
            self.last_ch = ch;
        }

        false
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
        while self.bytes_left > 0 {
            if let Some(&ch) = bytes.next() {
                buf.push(ch);
                self.bytes_left -= 1;
            } else {
                return false;
            }
        }
        true
    }
}

impl DummyDataReceiver {
    pub fn new_bdat(chunk_size: usize) -> Self {
        Self {
            bdat_bytes_left: chunk_size,
            is_bdat: true,
            crlf_dot: false,
            last_ch: 0,
            prev_last_ch: 0,
        }
    }

    pub fn new_data(data: &DataReceiver) -> Self {
        Self {
            is_bdat: false,
            bdat_bytes_left: 0,
            crlf_dot: data.crlf_dot,
            last_ch: data.last_ch,
            prev_last_ch: data.prev_last_ch,
        }
    }

    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>) -> bool {
        if !self.is_bdat {
            for &ch in bytes {
                match ch {
                    b'.' if self.last_ch == b'\n' && self.prev_last_ch == b'\r' => {
                        self.crlf_dot = true;
                    }
                    b'\n' if self.crlf_dot && self.last_ch == b'\r' => {
                        return true;
                    }
                    b'\r' => {}
                    _ => {
                        self.crlf_dot = false;
                    }
                }
                self.prev_last_ch = self.last_ch;
                self.last_ch = ch;
            }

            false
        } else {
            while self.bdat_bytes_left > 0 {
                if bytes.next().is_some() {
                    self.bdat_bytes_left -= 1;
                } else {
                    return false;
                }
            }

            true
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
        for &ch in bytes {
            match ch {
                b'\n' => return true,
                b'\r' => (),
                _ => {
                    if self.buf.len() < MAX_LINE_LENGTH {
                        self.buf.push(ch);
                    }
                }
            }
        }
        false
    }
}

impl DummyLineReceiver {
    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>) -> bool {
        for &ch in bytes {
            if ch == b'\n' {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::{request::receiver::RequestReceiver, Error, Request};

    use super::DataReceiver;

    #[test]
    fn data_receiver() {
        'outer: for (data, message) in [
            (
                vec!["hi\r\n", "..\r\n", ".a\r\n", "\r\n.\r\n"],
                "hi\r\n.\r\na\r\n",
            ),
            (
                vec!["\r\na\rb\nc\r\n.d\r\n..\r\n", "\r\n.\r\n"],
                "\r\na\rb\nc\r\nd\r\n.\r\n",
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
                    match r.ingest(&mut bytes, data.as_bytes()) {
                        Ok(request) => {
                            requests.push(request);
                            continue;
                        }
                        Err(Error::NeedsMoreData { .. }) => {
                            break;
                        }
                        err => panic!("Unexpected error {err:?}"),
                    }
                }
            }
            assert_eq!(expected_requests, requests);
        }
    }
}

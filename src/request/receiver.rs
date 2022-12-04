use std::slice::Iter;

use crate::{Error, Request};

pub struct RequestReceiver {
    pub buf: Vec<u8>,
}

pub struct DataReceiver {
    pub buf: Vec<u8>,
    crlf_dot: bool,
    last_ch: u8,
    prev_last_ch: u8,
}

pub struct BdatReceiver {
    pub buf: Vec<u8>,
    bytes_left: usize,
}

impl RequestReceiver {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(0),
        }
    }

    pub fn ingest(
        &mut self,
        bytes: &mut Iter<'_, u8>,
        buf: &[u8],
    ) -> Result<Request<String>, Error> {
        if self.buf.is_empty() {
            match Request::parse(bytes) {
                Err(Error::NeedsMoreData { bytes_left }) if bytes_left > 0 => {
                    self.buf = buf[buf.len() - bytes_left..].to_vec();
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
            buf: Vec::with_capacity(1024),
            crlf_dot: false,
            last_ch: 0,
            prev_last_ch: 0,
        }
    }

    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>) -> bool {
        for &ch in bytes {
            match ch {
                b'.' if self.last_ch == b'\n' && self.prev_last_ch == b'\r' => {
                    self.crlf_dot = true;
                }
                b'\n' if self.crlf_dot && self.last_ch == b'\r' => {
                    self.buf.truncate(self.buf.len() - 3);
                    return true;
                }
                b'\r' => {
                    self.buf.push(ch);
                }
                _ => {
                    self.buf.push(ch);
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
    pub fn new(bytes_left: usize) -> Self {
        Self {
            buf: Vec::with_capacity(bytes_left),
            bytes_left,
        }
    }

    pub fn ingest(&mut self, bytes: &mut Iter<'_, u8>) -> bool {
        for &ch in bytes {
            self.buf.push(ch);
            if self.buf.len() == self.bytes_left {
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
        ] {
            let mut r = DataReceiver::new();
            for data in &data {
                if r.ingest(&mut data.as_bytes().iter()) {
                    assert_eq!(message, String::from_utf8(r.buf).unwrap());
                    continue 'outer;
                }
            }
            panic!("Failed for {:?}", data);
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
            let mut r = RequestReceiver::new();
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
                        err => panic!("Unexpected error {:?}", err),
                    }
                }
            }
            assert_eq!(expected_requests, requests);
        }
    }
}

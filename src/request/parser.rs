use std::slice::Iter;

use crate::*;

use super::*;

#[derive(Default)]
pub struct RequestParser {}

impl Request<String> {
    pub fn parse(bytes: &mut Iter<'_, u8>) -> Result<Request<String>, Error> {
        let mut parser = Rfc5321Parser::new(bytes);
        let command = parser.hashed_value()?;
        if !parser.stop_char.is_ascii_whitespace() {
            return Err(Error::UnknownCommand);
        }

        match command {
            RCPT => {
                if !(parser.stop_char == LF
                    || parser.hashed_value()? != TO
                    || parser.stop_char != b':' && parser.next_char()? != b':')
                    && parser.next_char()? == b'<'
                {
                    if let Some(to) = parser.address()? {
                        if parser.stop_char == b'>' {
                            return Ok(Request::Rcpt {
                                to,
                                parameters: parser.parameters()?,
                            });
                        }
                    } else {
                        parser.seek_lf()?;
                        return Err(Error::InvalidRecipientAddress);
                    }
                }
                parser.seek_lf()?;
                Err(Error::SyntaxError {
                    syntax: "RCPT TO:<forward-path> [parameters]",
                })
            }
            MAIL => {
                if !(parser.stop_char == LF
                    || parser.hashed_value()? != FROM
                    || parser.stop_char != b':' && parser.next_char()? != b':')
                    && parser.next_char()? == b'<'
                {
                    if let Some(from) = parser.address()? {
                        if parser.stop_char == b'>' {
                            return Ok(Request::Mail {
                                from,
                                parameters: parser.parameters()?,
                            });
                        }
                    } else {
                        parser.seek_lf()?;
                        return Err(Error::InvalidSenderAddress);
                    }
                }

                parser.seek_lf()?;
                Err(Error::SyntaxError {
                    syntax: "MAIL FROM:<reverse-path> [parameters]",
                })
            }
            DATA => {
                parser.seek_lf()?;
                Ok(Request::Data)
            }
            EHLO => {
                if parser.stop_char != LF {
                    let host = parser.text()?;
                    parser.seek_lf()?;
                    if !host.is_empty() {
                        return Ok(Request::Ehlo { host });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "EHLO domain",
                })
            }
            BDAT => {
                if parser.stop_char != LF {
                    let chunk_size = parser.size()?;
                    if chunk_size != usize::MAX && parser.stop_char.is_ascii_whitespace() {
                        if parser.stop_char != LF {
                            match parser.hashed_value()? {
                                LAST => {
                                    parser.seek_lf()?;
                                    return Ok(Request::Bdat {
                                        chunk_size,
                                        is_last: true,
                                    });
                                }
                                0 => {
                                    parser.seek_lf()?;
                                    return Ok(Request::Bdat {
                                        chunk_size,
                                        is_last: false,
                                    });
                                }
                                _ => (),
                            }
                        } else {
                            return Ok(Request::Bdat {
                                chunk_size,
                                is_last: false,
                            });
                        }
                    }
                }
                parser.seek_lf()?;
                Err(Error::SyntaxError {
                    syntax: "BDAT chunk-size [LAST]",
                })
            }
            AUTH => {
                if parser.stop_char != LF {
                    if let Some(mechanism) = parser.mechanism()? {
                        let initial_response = if parser.stop_char != LF {
                            parser.text()?
                        } else {
                            String::new()
                        };
                        parser.seek_lf()?;
                        return Ok(Request::Auth {
                            mechanism,
                            initial_response,
                        });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "AUTH mechanism [initial-response]",
                })
            }
            EXPN => {
                if parser.stop_char != LF {
                    let value = parser.string()?;
                    parser.seek_lf()?;
                    if !value.is_empty() {
                        return Ok(Request::Expn { value });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "EXPN string",
                })
            }
            NOOP => {
                if parser.stop_char != LF {
                    let value = parser.string()?;
                    parser.seek_lf()?;
                    Ok(Request::Noop { value })
                } else {
                    Ok(Request::Noop {
                        value: String::new(),
                    })
                }
            }
            QUIT => {
                parser.seek_lf()?;
                Ok(Request::Quit)
            }
            LHLO => {
                if parser.stop_char != LF {
                    let host = parser.text()?;
                    parser.seek_lf()?;
                    if !host.is_empty() {
                        return Ok(Request::Lhlo { host });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "LHLO domain",
                })
            }
            RSET => {
                parser.seek_lf()?;
                Ok(Request::Rset)
            }
            VRFY => {
                if parser.stop_char != LF {
                    let value = parser.string()?;
                    parser.seek_lf()?;
                    if !value.is_empty() {
                        return Ok(Request::Vrfy { value });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "VRFY string",
                })
            }
            HELP => {
                if parser.stop_char != LF {
                    let value = parser.string()?;
                    parser.seek_lf()?;
                    Ok(Request::Help { value })
                } else {
                    Ok(Request::Help {
                        value: String::new(),
                    })
                }
            }
            STARTTLS => {
                parser.seek_lf()?;
                Ok(Request::StartTls)
            }
            ETRN => {
                if parser.stop_char != LF {
                    let name = parser.string()?;
                    parser.seek_lf()?;
                    if !name.is_empty() {
                        return Ok(Request::Etrn { name });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "ETRN name",
                })
            }
            ATRN => {
                if parser.stop_char != LF {
                    let mut domains = Vec::new();
                    loop {
                        let domain = parser.seek_char(b',')?;
                        if !domain.is_empty() {
                            domains.push(domain);
                        }
                        if parser.stop_char != b',' {
                            parser.seek_lf()?;
                            if !domains.is_empty() {
                                return Ok(Request::Atrn { domains });
                            } else {
                                break;
                            }
                        }
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "ATRN domain[,domain]",
                })
            }
            BURL => {
                if parser.stop_char != LF {
                    let uri = parser.text()?;
                    if !uri.is_empty() && parser.stop_char.is_ascii_whitespace() {
                        if parser.stop_char != LF {
                            match parser.hashed_value()? {
                                LAST => {
                                    parser.seek_lf()?;
                                    return Ok(Request::Burl { uri, is_last: true });
                                }
                                0 => {
                                    parser.seek_lf()?;
                                    return Ok(Request::Burl {
                                        uri,
                                        is_last: false,
                                    });
                                }
                                _ => (),
                            }
                        } else {
                            return Ok(Request::Burl {
                                uri,
                                is_last: false,
                            });
                        }
                    }
                }
                parser.seek_lf()?;
                Err(Error::SyntaxError {
                    syntax: "BURL absolute-uri [LAST]",
                })
            }
            HELO => {
                if parser.stop_char != LF {
                    let host = parser.text()?;
                    parser.seek_lf()?;
                    if !host.is_empty() {
                        return Ok(Request::Helo { host });
                    }
                }
                Err(Error::SyntaxError {
                    syntax: "HELO domain",
                })
            }
            _ => {
                parser.seek_lf()?;
                Err(Error::UnknownCommand)
            }
        }
    }
}

pub struct Rfc5321Parser<'x, 'y> {
    bytes: &'x mut Iter<'y, u8>,
    pub stop_char: u8,
    pub bytes_left: usize,
}

impl<'x, 'y> Rfc5321Parser<'x, 'y> {
    pub fn new(bytes: &'x mut Iter<'y, u8>) -> Self {
        let (bytes_left, _) = bytes.size_hint();
        Rfc5321Parser {
            bytes,
            bytes_left,
            stop_char: 0,
        }
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn hashed_value(&mut self) -> Result<u64, Error> {
        let mut value: u64 = 0;
        let mut shift = 0;

        while let Some(&ch) = self.bytes.next() {
            match ch {
                b'A'..=b'Z' | b'0'..=b'9' | b'-' if shift < 64 => {
                    value |= (ch as u64) << shift;
                    shift += 8;
                }
                b'a'..=b'z' if shift < 64 => {
                    value |= ((ch - b'a' + b'A') as u64) << shift;
                    shift += 8;
                }
                b'\r' => (),
                b' ' => {
                    if value != 0 {
                        self.stop_char = ch;
                        return Ok(value);
                    }
                }
                _ => {
                    self.stop_char = ch;
                    return Ok(value);
                }
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn hashed_value_long(&mut self) -> Result<u128, Error> {
        let mut value: u128 = 0;
        let mut shift = 0;

        while let Some(&ch) = self.bytes.next() {
            match ch {
                b'A'..=b'Z' | b'0'..=b'9' | b'-' if shift < 128 => {
                    value |= (ch as u128) << shift;
                    shift += 8;
                }
                b'a'..=b'z' if shift < 128 => {
                    value |= ((ch - b'a' + b'A') as u128) << shift;
                    shift += 8;
                }
                b' ' => {
                    if value != 0 {
                        self.stop_char = b' ';
                        return Ok(value);
                    }
                }
                b'\r' => (),
                _ => {
                    self.stop_char = ch;
                    return Ok(value);
                }
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn address(&mut self) -> Result<Option<String>, Error> {
        let mut value = Vec::with_capacity(32);
        let mut last_ch = 0;
        let mut in_quote = false;
        let mut at_count = 0;
        let mut lp_len = 0;

        for &ch in &mut self.bytes {
            match ch {
                b'0'..=b'9'
                | b'a'..=b'z'
                | b'A'..=b'Z'
                | b'!'
                | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'/'
                | b'='
                | b'?'
                | b'^'
                | b'_'
                | b'`'
                | b'{'
                | b'|'
                | b'}'
                | b'~'
                | 0x7f..=u8::MAX => {
                    value.push(ch);
                }
                b'.' if !in_quote => {
                    if last_ch != b'.' && last_ch != b'@' && !value.is_empty() {
                        value.push(ch);
                    } else {
                        self.stop_char = ch;
                        return Ok(None);
                    }
                }
                b'@' if !in_quote => {
                    at_count += 1;
                    lp_len = value.len();
                    value.push(ch);
                }
                b'>' if !in_quote => {
                    self.stop_char = ch;
                    let value = value.into_string();
                    let len = value.chars().count();
                    return Ok(if len == 0 || len < 255 && at_count == 1 && lp_len > 0 {
                        value.into()
                    } else {
                        None
                    });
                }
                b'\r' => (),
                b':' if !in_quote && matches!(value.first(), Some(b'@')) => {
                    // Remove source route
                    value.clear();
                    at_count = 0;
                    lp_len = 0;
                }
                b',' if !in_quote && matches!(value.first(), Some(b'@')) => (),
                b' ' if !in_quote => {
                    if !value.is_empty() {
                        self.stop_char = b' ';
                        let value = value.into_string();
                        let len = value.chars().count();
                        return Ok(if len == 0 || len < 255 && at_count == 1 && lp_len > 0 {
                            value.into()
                        } else {
                            None
                        });
                    }
                }
                b'\n' => {
                    self.stop_char = b'\n';
                    let value = value.into_string();
                    let len = value.chars().count();
                    return Ok(if len == 0 || len < 255 && at_count == 1 && lp_len > 0 {
                        value.into()
                    } else {
                        None
                    });
                }
                b'\"' if !in_quote || last_ch != b'\\' => {
                    in_quote = !in_quote;
                }
                b'\\' if in_quote && last_ch != b'\\' => (),
                _ => {
                    if in_quote {
                        value.push(ch);
                    } else {
                        self.stop_char = ch;
                        return Ok(None);
                    }
                }
            }

            last_ch = ch;
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn string(&mut self) -> Result<String, Error> {
        let mut in_quote = false;
        let mut value = Vec::with_capacity(32);
        let mut last_ch = 0;

        for &ch in &mut self.bytes {
            match ch {
                b' ' if !in_quote => {
                    if !value.is_empty() {
                        self.stop_char = b' ';
                        return Ok(value.into_string());
                    }
                }
                b'\n' => {
                    self.stop_char = b'\n';
                    return Ok(value.into_string());
                }
                b'\"' if !in_quote || last_ch != b'\\' => {
                    in_quote = !in_quote;
                }
                b'\\' if in_quote && last_ch != b'\\' => (),
                b'\r' => (),
                _ => {
                    value.push(ch);
                }
            }

            last_ch = ch;
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn text(&mut self) -> Result<String, Error> {
        let mut value = Vec::with_capacity(32);
        while let Some(&ch) = self.bytes.next() {
            match ch {
                b'\n' => {
                    self.stop_char = b'\n';
                    return Ok(value.into_string());
                }
                b' ' => {
                    self.stop_char = b' ';
                    return Ok(value.into_string());
                }
                b'\r' => (),
                _ => {
                    value.push(ch);
                }
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn xtext(&mut self) -> Result<String, Error> {
        let mut value = Vec::with_capacity(32);
        while let Some(&ch) = self.bytes.next() {
            match ch {
                b'\n' => {
                    self.stop_char = b'\n';
                    return Ok(value.into_string());
                }
                b'+' => {
                    let mut hex1 = 0;

                    while let Some(&ch) = self.bytes.next() {
                        if ch.is_ascii_hexdigit() {
                            if hex1 != 0 {
                                let hex1 = HEX_MAP[hex1 as usize];
                                let hex2 = HEX_MAP[ch as usize];
                                if hex1 != -1 && hex2 != -1 {
                                    value.push(((hex1 as u8) << 4) | hex2 as u8);
                                }
                                break;
                            } else {
                                hex1 = ch;
                            }
                        } else if ch == LF {
                            self.stop_char = b'\n';
                            return Ok(value.into_string());
                        } else {
                            break;
                        }
                    }
                }
                b' ' => {
                    self.stop_char = b' ';
                    return Ok(value.into_string());
                }
                b'\r' => (),
                _ => {
                    value.push(ch);
                }
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn seek_char(&mut self, stop_char: u8) -> Result<String, Error> {
        let mut value = Vec::with_capacity(32);
        while let Some(&ch) = self.bytes.next() {
            match ch {
                b'\n' => {
                    self.stop_char = b'\n';
                    return Ok(value.into_string());
                }
                b' ' => {
                    if !value.is_empty() {
                        self.stop_char = b' ';
                        return Ok(value.into_string());
                    }
                }
                b'\r' => (),
                _ => {
                    if ch != stop_char {
                        value.push(ch);
                    } else {
                        self.stop_char = ch;
                        return Ok(value.into_string());
                    }
                }
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[inline(always)]
    pub fn seek_lf(&mut self) -> Result<(), Error> {
        if self.stop_char != LF {
            for &ch in &mut self.bytes {
                if ch == LF {
                    return Ok(());
                }
            }
            Err(Error::NeedsMoreData {
                bytes_left: self.bytes_left,
            })
        } else {
            Ok(())
        }
    }

    #[inline(always)]
    pub fn next_char(&mut self) -> Result<u8, Error> {
        for &ch in &mut self.bytes {
            match ch {
                b' ' | b'\r' => (),
                _ => {
                    self.stop_char = ch;
                    return Ok(ch);
                }
            }
        }
        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[inline(always)]
    pub fn read_char(&mut self) -> Result<u8, Error> {
        self.bytes.next().copied().ok_or(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn size(&mut self) -> Result<usize, Error> {
        let mut value = usize::MAX;
        for &ch in &mut self.bytes {
            match ch {
                b'0'..=b'9' => {
                    value = if value != usize::MAX {
                        value
                            .saturating_mul(10)
                            .saturating_add((ch - b'0') as usize)
                    } else {
                        (ch - b'0') as usize
                    };
                }
                b'\r' => (),
                b' ' => {
                    if value != usize::MAX {
                        self.stop_char = b' ';
                        return Ok(value);
                    }
                }
                _ => {
                    self.stop_char = ch;
                    return Ok(value);
                }
            }
        }
        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn integer(&mut self) -> Result<i64, Error> {
        let mut value = i64::MAX;
        let mut multiplier = 1;

        for &ch in &mut self.bytes {
            match ch {
                b'0'..=b'9' => {
                    value = if value != i64::MAX {
                        value.saturating_mul(10).saturating_add((ch - b'0') as i64)
                    } else {
                        (ch - b'0') as i64
                    };
                }
                b' ' => {
                    if value != i64::MAX {
                        self.stop_char = b' ';
                        return Ok(value * multiplier);
                    }
                }
                b'-' if value == i64::MAX => {
                    multiplier = -1;
                }
                b'+' if value == i64::MAX => (),
                b'\r' => (),
                _ => {
                    self.stop_char = ch;
                    return Ok(if value != i64::MAX {
                        value * multiplier
                    } else {
                        i64::MAX
                    });
                }
            }
        }
        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn timestamp(&mut self) -> Result<i64, Error> {
        let mut dt = [0u32; 8];
        let mut zone_multiplier = 1;
        let mut pos = 0;

        for &ch in &mut self.bytes {
            match ch {
                b'0'..=b'9' if pos < 8 => {
                    dt[pos] = dt[pos]
                        .saturating_mul(10)
                        .saturating_add((ch - b'0') as u32);
                }
                b'-' if pos <= 1 || pos == 5 => {
                    pos += 1;
                }
                b'+' if pos == 5 => {
                    zone_multiplier = -1;
                    pos += 1;
                }
                b'T' if pos == 2 => {
                    pos += 1;
                }
                b':' if pos == 3 || pos == 4 || pos == 6 => {
                    pos += 1;
                }
                b'Z' if pos == 5 => {
                    pos = 8;
                }
                _ => {
                    self.stop_char = ch;
                    return Ok(if pos >= 7 {
                        // Ported from https://github.com/protocolbuffers/upb/blob/22182e6e/upb/json_decode.c#L982-L992
                        let month = dt[1];
                        let year_base = 4800; /* Before min year, multiple of 400. */
                        let m_adj = month.wrapping_sub(3); /* March-based month. */
                        let carry = i64::from(m_adj > month);
                        let adjust = if carry > 0 { 12 } else { 0 };
                        let y_adj = dt[0] as i64 + year_base - carry;
                        let month_days = ((m_adj.wrapping_add(adjust)) * 62719 + 769) / 2048;
                        let leap_days = y_adj / 4 - y_adj / 100 + y_adj / 400;
                        (y_adj * 365 + leap_days + month_days as i64 + (dt[2] as i64 - 1) - 2472632)
                            * 86400
                            + dt[3] as i64 * 3600
                            + dt[4] as i64 * 60
                            + dt[5] as i64
                            + ((dt[6] as i64 * 3600 + dt[7] as i64 * 60) * zone_multiplier)
                    } else {
                        i64::MAX
                    });
                }
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn parameters(&mut self) -> Result<Vec<Parameter<String>>, Error> {
        let mut params = Vec::new();
        while self.stop_char != LF {
            let key = self.hashed_value_long()?;
            match key {
                SMTPUTF8 if self.stop_char.is_ascii_whitespace() => {
                    params.push(Parameter::SmtpUtf8);
                }
                BODY if self.stop_char == b'=' => match Body::try_from(self.hashed_value_long()?) {
                    Ok(body) if self.stop_char.is_ascii_whitespace() => {
                        params.push(Parameter::Body(body));
                    }
                    _ => {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "BODY" });
                    }
                },
                SIZE if self.stop_char == b'=' => {
                    let size = self.size()?;
                    if size != usize::MAX && self.stop_char.is_ascii_whitespace() {
                        params.push(Parameter::Size(size));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "SIZE" });
                    }
                }
                BY if self.stop_char == b'=' => {
                    let time = self.integer()?;
                    if time != i64::MAX && self.stop_char == b';' {
                        let (is_notify, trace) = match self.hashed_value()? {
                            N if self.stop_char.is_ascii_whitespace() => (true, false),
                            NT if self.stop_char.is_ascii_whitespace() => (true, true),
                            R if self.stop_char.is_ascii_whitespace() => (false, false),
                            RT if self.stop_char.is_ascii_whitespace() => (false, true),
                            _ => {
                                self.seek_lf()?;
                                return Err(Error::InvalidParameter { param: "BY" });
                            }
                        };
                        params.push(Parameter::By(if is_notify {
                            By::Notify { time, trace }
                        } else {
                            By::Return { time, trace }
                        }));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "BY" });
                    }
                }
                HOLDUNTIL if self.stop_char == b'=' => {
                    let hold = self.size()?;
                    if hold != usize::MAX && self.stop_char.is_ascii_whitespace() {
                        params.push(Parameter::HoldUntil(hold as u64));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "HOLDUNTIL" });
                    }
                }
                HOLDFOR if self.stop_char == b'=' => {
                    let hold = self.size()?;
                    if hold != usize::MAX && self.stop_char.is_ascii_whitespace() {
                        params.push(Parameter::HoldFor(hold as u64));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "HOLDFOR" });
                    }
                }
                NOTIFY if self.stop_char == b'=' => {
                    let mut notify = 0;
                    loop {
                        match self.hashed_value_long()? {
                            NEVER if notify == 0 => (),
                            SUCCESS => {
                                notify |= NOTIFY_SUCCESS;
                            }
                            FAILURE => {
                                notify |= NOTIFY_FAILURE;
                            }
                            DELAY => {
                                notify |= NOTIFY_DELAY;
                            }
                            _ => {
                                self.seek_lf()?;
                                return Err(Error::InvalidParameter { param: "NOTIFY" });
                            }
                        }
                        if self.stop_char.is_ascii_whitespace() {
                            break;
                        } else if self.stop_char != b',' {
                            self.seek_lf()?;
                            return Err(Error::InvalidParameter { param: "NOTIFY" });
                        }
                    }
                    params.push(Parameter::Notify(notify));
                }
                ORCPT if self.stop_char == b'=' => {
                    let addr_type = self.seek_char(b';')?;
                    if self.stop_char != b';' {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "ORCPT" });
                    }
                    let addr = self.xtext()?;
                    if self.stop_char.is_ascii_whitespace()
                        && !addr_type.is_empty()
                        && !addr.is_empty()
                    {
                        params.push(Parameter::Orcpt(Orcpt { addr_type, addr }));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "ORCPT" });
                    }
                }
                RET if self.stop_char == b'=' => {
                    params.push(Parameter::Ret(match self.hashed_value()? {
                        FULL if self.stop_char.is_ascii_whitespace() => Ret::Full,
                        HDRS if self.stop_char.is_ascii_whitespace() => Ret::Hdrs,
                        _ => {
                            self.seek_lf()?;
                            return Err(Error::InvalidParameter { param: "RET" });
                        }
                    }));
                }
                ENVID if self.stop_char == b'=' => {
                    let envid = self.xtext()?;
                    if self.stop_char.is_ascii_whitespace() && !envid.is_empty() {
                        params.push(Parameter::EnvId(envid));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "ENVID" });
                    }
                }
                REQUIRETLS if self.stop_char.is_ascii_whitespace() => {
                    params.push(Parameter::RequireTls);
                }
                SOLICIT if self.stop_char == b'=' => {
                    let solicit = self.text()?;
                    if !solicit.is_empty() && self.stop_char.is_ascii_whitespace() {
                        params.push(Parameter::Solicit(solicit));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "SOLICIT" });
                    }
                }
                TRANSID if self.stop_char == b'=' => {
                    if self.next_char()? == b'<' {
                        let transid = self.seek_char(b'>')?;
                        if self.stop_char == b'>' && !transid.is_empty() {
                            params.push(Parameter::TransId(transid));
                            self.stop_char = SP;
                            continue;
                        }
                    }
                    self.seek_lf()?;
                    return Err(Error::InvalidParameter { param: "TRANSID" });
                }
                MTRK if self.stop_char == b'=' => {
                    let certifier = self.seek_char(b':')?;
                    let timeout = if self.stop_char == b':' {
                        self.size()?
                    } else {
                        0
                    };

                    if !certifier.is_empty()
                        && self.stop_char.is_ascii_whitespace()
                        && timeout != usize::MAX
                    {
                        params.push(Parameter::Mtrk(Mtrk {
                            certifier,
                            timeout: timeout as u64,
                        }));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "MTRK" });
                    }
                }
                AUTH_ if self.stop_char == b'=' => {
                    let mailbox = self.xtext()?;
                    if !mailbox.is_empty() && self.stop_char.is_ascii_whitespace() {
                        params.push(Parameter::Auth(mailbox));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "AUTH" });
                    }
                }
                MT_PRIORITY if self.stop_char == b'=' => {
                    let priority = self.integer()?;
                    if priority != i64::MAX && self.stop_char.is_ascii_whitespace() {
                        params.push(Parameter::MtPriority(priority));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter {
                            param: "MT-PRIORITY",
                        });
                    }
                }
                RRVS if self.stop_char == b'=' => {
                    let time = self.timestamp()?;
                    if time != i64::MAX && self.stop_char.is_ascii_whitespace()
                        || self.stop_char == b';'
                    {
                        let is_reject = self.stop_char != b';'
                            || match self.hashed_value()? {
                                C if self.stop_char.is_ascii_whitespace() => false,
                                R if self.stop_char.is_ascii_whitespace() => true,
                                _ => {
                                    self.seek_lf()?;
                                    return Err(Error::InvalidParameter { param: "RRVS" });
                                }
                            };
                        params.push(Parameter::Rrvs(if is_reject {
                            Rrvs::Reject(time)
                        } else {
                            Rrvs::Continue(time)
                        }));
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "RRVS" });
                    }
                }
                CONPERM if self.stop_char.is_ascii_whitespace() => {
                    params.push(Parameter::ConPerm);
                }
                CONNEG if self.stop_char.is_ascii_whitespace() => {
                    params.push(Parameter::ConNeg);
                }
                0 => (),
                unknown => {
                    let mut param = Vec::with_capacity(16);
                    for ch in unknown.to_le_bytes() {
                        if ch != 0 {
                            param.push(ch.to_ascii_uppercase());
                        }
                    }
                    if !self.stop_char.is_ascii_whitespace() {
                        param.push(self.stop_char.to_ascii_uppercase());
                        for &ch in &mut self.bytes {
                            if !ch.is_ascii_whitespace() {
                                param.push(ch.to_ascii_uppercase());
                            } else {
                                self.stop_char = ch;
                                break;
                            }
                        }
                    }

                    self.seek_lf()?;
                    return Err(Error::UnsupportedParameter {
                        param: param.into_string(),
                    });
                }
            }
        }

        Ok(params)
    }

    pub fn mechanism(&mut self) -> Result<Option<u64>, Error> {
        let mut trailing_chars = [0u8; 8];
        let mut pos = 0;
        let mechanism = self.hashed_value_long()?;
        if !self.stop_char.is_ascii_whitespace() {
            trailing_chars[0] = self.stop_char;
            pos += 1;
            for &ch in &mut self.bytes {
                if !ch.is_ascii_whitespace() {
                    if let Some(tch) = trailing_chars.get_mut(pos) {
                        *tch = ch.to_ascii_uppercase();
                    }
                    pos += 1;
                } else {
                    self.stop_char = ch;
                    break;
                }
            }
            if !self.stop_char.is_ascii_whitespace() {
                return Err(Error::NeedsMoreData {
                    bytes_left: self.bytes_left,
                });
            } else if pos > 8 {
                return Ok(0.into());
            }
        }
        Ok(match (mechanism, &trailing_chars[..pos]) {
            (_9798_M_DSA_SHA1, b"") => AUTH_9798_M_DSA_SHA1.into(),
            (_9798_M_ECDSA_SHA, b"1") => AUTH_9798_M_ECDSA_SHA1.into(),
            (_9798_M_RSA_SHA1_, b"ENC") => AUTH_9798_M_RSA_SHA1_ENC.into(),
            (_9798_U_DSA_SHA1, b"") => AUTH_9798_U_DSA_SHA1.into(),
            (_9798_U_ECDSA_SHA, b"1") => AUTH_9798_U_ECDSA_SHA1.into(),
            (_9798_U_RSA_SHA1_, b"ENC") => AUTH_9798_U_RSA_SHA1_ENC.into(),
            (ANONYMOUS, b"") => AUTH_ANONYMOUS.into(),
            (CRAM_MD5, b"") => AUTH_CRAM_MD5.into(),
            (DIGEST_MD5, b"") => AUTH_DIGEST_MD5.into(),
            (EAP_AES128, b"") => AUTH_EAP_AES128.into(),
            (EAP_AES128_PLUS, b"") => AUTH_EAP_AES128_PLUS.into(),
            (ECDH_X25519_CHAL, b"LENGE") => AUTH_ECDH_X25519_CHALLENGE.into(),
            (ECDSA_NIST256P_C, b"HALLENGE") => AUTH_ECDSA_NIST256P_CHALLENGE.into(),
            (EXTERNAL, b"") => AUTH_EXTERNAL.into(),
            (GS2_KRB5, b"") => AUTH_GS2_KRB5.into(),
            (GS2_KRB5_PLUS, b"") => AUTH_GS2_KRB5_PLUS.into(),
            (GSS_SPNEGO, b"") => AUTH_GSS_SPNEGO.into(),
            (GSSAPI, b"") => AUTH_GSSAPI.into(),
            (KERBEROS_V4, b"") => AUTH_KERBEROS_V4.into(),
            (KERBEROS_V5, b"") => AUTH_KERBEROS_V5.into(),
            (LOGIN, b"") => AUTH_LOGIN.into(),
            (NMAS_SAMBA_AUTH, b"") => AUTH_NMAS_SAMBA_AUTH.into(),
            (NMAS_AUTHEN, b"") => AUTH_NMAS_AUTHEN.into(),
            (NMAS_LOGIN, b"") => AUTH_NMAS_LOGIN.into(),
            (NTLM, b"") => AUTH_NTLM.into(),
            (OAUTH10A, b"") => AUTH_OAUTH10A.into(),
            (OAUTHBEARER, b"") => AUTH_OAUTHBEARER.into(),
            (OPENID20, b"") => AUTH_OPENID20.into(),
            (OTP, b"") => AUTH_OTP.into(),
            (PLAIN, b"") => AUTH_PLAIN.into(),
            (SAML20, b"") => AUTH_SAML20.into(),
            (SCRAM_SHA_1, b"") => AUTH_SCRAM_SHA_1.into(),
            (SCRAM_SHA_1_PLUS, b"") => AUTH_SCRAM_SHA_1_PLUS.into(),
            (SCRAM_SHA_256, b"") => AUTH_SCRAM_SHA_256.into(),
            (SCRAM_SHA_256_PL, b"US") => AUTH_SCRAM_SHA_256_PLUS.into(),
            (SECURID, b"") => AUTH_SECURID.into(),
            (SKEY, b"") => AUTH_SKEY.into(),
            (SPNEGO, b"") => AUTH_SPNEGO.into(),
            (SPNEGO_PLUS, b"") => AUTH_SPNEGO_PLUS.into(),
            (SXOVER_PLUS, b"") => AUTH_SXOVER_PLUS.into(),
            (XOAUTH, b"") => AUTH_XOAUTH.into(),
            (XOAUTH2, b"") => AUTH_XOAUTH2.into(),
            (0, b"") => None,
            _ => 0.into(),
        })
    }
}

impl TryFrom<u128> for Body {
    type Error = ();

    fn try_from(value: u128) -> Result<Self, Self::Error> {
        match value {
            EIGHBITMIME => Ok(Body::EightBitMime),
            BINARYMIME => Ok(Body::BinaryMime),
            SEVENBIT => Ok(Body::SevenBit),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        Body, By, Error, Mtrk, Orcpt, Parameter, Request, Ret, Rrvs, AUTH_ECDSA_NIST256P_CHALLENGE,
        AUTH_GSSAPI, AUTH_SCRAM_SHA_256_PLUS, NOTIFY_DELAY, NOTIFY_FAILURE, NOTIFY_SUCCESS,
    };

    #[test]
    fn parse_request() {
        for item in [
            // HELO et al.
            (
                "EHLO bar.com",
                Ok(Request::Ehlo {
                    host: "bar.com".to_string(),
                }),
            ),
            (
                "EHLO",
                Err(Error::SyntaxError {
                    syntax: "EHLO domain",
                }),
            ),
            (
                "HELO bar.com",
                Ok(Request::Helo {
                    host: "bar.com".to_string(),
                }),
            ),
            (
                "HELO",
                Err(Error::SyntaxError {
                    syntax: "HELO domain",
                }),
            ),
            (
                "LHLO bar.com",
                Ok(Request::Lhlo {
                    host: "bar.com".to_string(),
                }),
            ),
            (
                "LHLO",
                Err(Error::SyntaxError {
                    syntax: "LHLO domain",
                }),
            ),
            // VRFY
            (
                "VRFY Hello",
                Ok(Request::Vrfy {
                    value: "Hello".to_string(),
                }),
            ),
            (
                "VRFY \"Hello\\\" Wo\\\\rld\"",
                Ok(Request::Vrfy {
                    value: "Hello\" Wo\\rld".to_string(),
                }),
            ),
            (
                "VRFY \"\"",
                Err(Error::SyntaxError {
                    syntax: "VRFY string",
                }),
            ),
            (
                "VRFY",
                Err(Error::SyntaxError {
                    syntax: "VRFY string",
                }),
            ),
            // EXPN
            (
                "EXPN Hello",
                Ok(Request::Expn {
                    value: "Hello".to_string(),
                }),
            ),
            (
                "EXPN \"Hello\\\" Wo\\\\rld\"",
                Ok(Request::Expn {
                    value: "Hello\" Wo\\rld".to_string(),
                }),
            ),
            (
                "EXPN \"\"",
                Err(Error::SyntaxError {
                    syntax: "EXPN string",
                }),
            ),
            (
                "EXPN",
                Err(Error::SyntaxError {
                    syntax: "EXPN string",
                }),
            ),
            // NOOP
            (
                "NOOP",
                Ok(Request::Noop {
                    value: "".to_string(),
                }),
            ),
            (
                "NOOP Hello",
                Ok(Request::Noop {
                    value: "Hello".to_string(),
                }),
            ),
            // HELP
            (
                "HELP",
                Ok(Request::Help {
                    value: "".to_string(),
                }),
            ),
            (
                "HELP Hello",
                Ok(Request::Help {
                    value: "Hello".to_string(),
                }),
            ),
            // No param commands
            ("DATA", Ok(Request::Data)),
            ("QUIT", Ok(Request::Quit)),
            ("RSET", Ok(Request::Rset)),
            ("STARTTLS", Ok(Request::StartTls)),
            // BDAT
            (
                "BDAT 0",
                Ok(Request::Bdat {
                    chunk_size: 0,
                    is_last: false,
                }),
            ),
            (
                "BDAT 123456",
                Ok(Request::Bdat {
                    chunk_size: 123456,
                    is_last: false,
                }),
            ),
            (
                "BDAT 123456 LAST",
                Ok(Request::Bdat {
                    chunk_size: 123456,
                    is_last: true,
                }),
            ),
            (
                "BDAT",
                Err(Error::SyntaxError {
                    syntax: "BDAT chunk-size [LAST]",
                }),
            ),
            (
                "BDAT 123LAST",
                Err(Error::SyntaxError {
                    syntax: "BDAT chunk-size [LAST]",
                }),
            ),
            (
                "BDAT 123x LAST",
                Err(Error::SyntaxError {
                    syntax: "BDAT chunk-size [LAST]",
                }),
            ),
            (
                "BDAT LAST",
                Err(Error::SyntaxError {
                    syntax: "BDAT chunk-size [LAST]",
                }),
            ),
            // AUTH
            (
                "AUTH GSSAPI",
                Ok(Request::Auth {
                    mechanism: AUTH_GSSAPI,
                    initial_response: "".to_string(),
                }),
            ),
            (
                "AUTH ECDSA-NIST256P-CHALLENGE =",
                Ok(Request::Auth {
                    mechanism: AUTH_ECDSA_NIST256P_CHALLENGE,
                    initial_response: "=".to_string(),
                }),
            ),
            (
                "AUTH SCRAM-SHA-256-PLUS base64_goes_here",
                Ok(Request::Auth {
                    mechanism: AUTH_SCRAM_SHA_256_PLUS,
                    initial_response: "base64_goes_here".to_string(),
                }),
            ),
            (
                "AUTH ECDSA-NIST256P-CHALLENGE100 abcde",
                Ok(Request::Auth {
                    mechanism: 0,
                    initial_response: "abcde".to_string(),
                }),
            ),
            (
                "AUTH",
                Err(Error::SyntaxError {
                    syntax: "AUTH mechanism [initial-response]",
                }),
            ),
            // ETRN
            (
                "ETRN Hello",
                Ok(Request::Etrn {
                    name: "Hello".to_string(),
                }),
            ),
            (
                "ETRN \"Hello\\\" Wo\\\\rld\"",
                Ok(Request::Etrn {
                    name: "Hello\" Wo\\rld".to_string(),
                }),
            ),
            (
                "ETRN \"\"",
                Err(Error::SyntaxError {
                    syntax: "ETRN name",
                }),
            ),
            (
                "ETRN",
                Err(Error::SyntaxError {
                    syntax: "ETRN name",
                }),
            ),
            // ATRN
            (
                "ATRN example.org",
                Ok(Request::Atrn {
                    domains: vec!["example.org".to_string()],
                }),
            ),
            (
                "ATRN example.org,example.com,example.net",
                Ok(Request::Atrn {
                    domains: vec![
                        "example.org".to_string(),
                        "example.com".to_string(),
                        "example.net".to_string(),
                    ],
                }),
            ),
            (
                "ATRN example.org, example.com, example.net",
                Ok(Request::Atrn {
                    domains: vec![
                        "example.org".to_string(),
                        "example.com".to_string(),
                        "example.net".to_string(),
                    ],
                }),
            ),
            (
                "ATRN",
                Err(Error::SyntaxError {
                    syntax: "ATRN domain[,domain]",
                }),
            ),
            // BURL
            (
                concat!(
                    "BURL imap://harry@gryffindor.example.com/outbox",
                    ";uidvalidity=1078863300/;uid=25;urlauth=submit+harry",
                    ":internal:91354a473744909de610943775f92038 LAST"
                ),
                Ok(Request::Burl {
                    uri: concat!(
                        "imap://harry@gryffindor.example.com/outbox",
                        ";uidvalidity=1078863300/;uid=25;urlauth=submit+harry",
                        ":internal:91354a473744909de610943775f92038"
                    )
                    .to_string(),
                    is_last: true,
                }),
            ),
            (
                "BURL imap:://test.example.org",
                Ok(Request::Burl {
                    uri: "imap:://test.example.org".to_string(),
                    is_last: false,
                }),
            ),
            (
                "BURL",
                Err(Error::SyntaxError {
                    syntax: "BURL absolute-uri [LAST]",
                }),
            ),
            // MAIL FROM
            (
                "MAIL FROM:<JQP@bar.com>",
                Ok(Request::Mail {
                    from: "JQP@bar.com".to_string(),
                    parameters: vec![],
                }),
            ),
            (
                "MAIL FROM:<@a,@b:user@d>",
                Ok(Request::Mail {
                    from: "user@d".to_string(),
                    parameters: vec![],
                }),
            ),
            (
                "MAIL FROM:<\"@a,@b:<user>\"@d>",
                Ok(Request::Mail {
                    from: "@a,@b:<user>@d".to_string(),
                    parameters: vec![],
                }),
            ),
            (
                "MAIL FROM: <\" hi there! \"@d>",
                Ok(Request::Mail {
                    from: " hi there! @d".to_string(),
                    parameters: vec![],
                }),
            ),
            (
                "MAIL  FROM : <>",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![],
                }),
            ),
            (
                "MAIL  FROM : < >",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![],
                }),
            ),
            (
                "MAIL FROM:<hi.there@valid.org>",
                Ok(Request::Mail {
                    from: "hi.there@valid.org".to_string(),
                    parameters: vec![],
                }),
            ),
            ("MAIL FROM:<@invalid>", Err(Error::InvalidSenderAddress)),
            (
                "MAIL FROM:<hi@@invalid.org>",
                Err(Error::InvalidSenderAddress),
            ),
            (
                "MAIL FROM:<hi..there@invalid.org>",
                Err(Error::InvalidSenderAddress),
            ),
            (
                "MAIL FROM:<hi.there@invalid..org>",
                Err(Error::InvalidSenderAddress),
            ),
            (
                "MAIL FROM:<hi.there@.invalid.org>",
                Err(Error::InvalidSenderAddress),
            ),
            (
                "MAIL FROM:<.hi.there@invalid.org>",
                Err(Error::InvalidSenderAddress),
            ),
            ("MAIL FROM:<@>", Err(Error::InvalidSenderAddress)),
            ("MAIL FROM:<.@.>", Err(Error::InvalidSenderAddress)),
            (
                "RCPT TO:<孫子@áéíóú.org>",
                Ok(Request::Rcpt {
                    to: "孫子@áéíóú.org".to_string(),
                    parameters: vec![],
                }),
            ),
            // RCPT TO
            (
                "RCPT TO:<Jones@XYZ.COM>",
                Ok(Request::Rcpt {
                    to: "Jones@XYZ.COM".to_string(),
                    parameters: vec![],
                }),
            ),
            (
                "RCPT TO:<>",
                Ok(Request::Rcpt {
                    to: "".to_string(),
                    parameters: vec![],
                }),
            ),
            // Invalid commands
            ("", Err(Error::UnknownCommand)),
            ("X-SPECIAL", Err(Error::UnknownCommand)),
            ("DATA_", Err(Error::UnknownCommand)),
            // Invalid parameters
            (
                "MAIL FROM:<> HELLO=WORLD",
                Err(Error::UnsupportedParameter {
                    param: "HELLO=WORLD".to_string(),
                }),
            ),
            (
                "MAIL FROM:<> VERY_LONG_AND_INVALID=PARAM",
                Err(Error::UnsupportedParameter {
                    param: "VERY_LONG_AND_INVALID=PARAM".to_string(),
                }),
            ),
            (
                "MAIL FROM:<> SMTPUTF8=YES",
                Err(Error::UnsupportedParameter {
                    param: "SMTPUTF8=YES".to_string(),
                }),
            ),
            (
                "MAIL FROM:<> SMTPUTF8=YES",
                Err(Error::UnsupportedParameter {
                    param: "SMTPUTF8=YES".to_string(),
                }),
            ),
            // Parameters
            (
                "MAIL FROM:<> SMTPUTF8",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![Parameter::SmtpUtf8],
                }),
            ),
            (
                "MAIL FROM:<> SMTPUTF8 REQUIRETLS CONPERM CONNEG",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::SmtpUtf8,
                        Parameter::RequireTls,
                        Parameter::ConPerm,
                        Parameter::ConNeg,
                    ],
                }),
            ),
            (
                "MAIL FROM:<> BODY=BINARYMIME BODY=7BIT BODY=8BITMIME",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::Body(Body::BinaryMime),
                        Parameter::Body(Body::SevenBit),
                        Parameter::Body(Body::EightBitMime),
                    ],
                }),
            ),
            (
                "MAIL FROM:<> BODY=OTHER",
                Err(Error::InvalidParameter { param: "BODY" }),
            ),
            (
                "MAIL FROM:<> SIZE=500000 SIZE=0",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![Parameter::Size(500000), Parameter::Size(0)],
                }),
            ),
            (
                "MAIL FROM:<> SIZE=ABC",
                Err(Error::InvalidParameter { param: "SIZE" }),
            ),
            (
                "MAIL FROM:<> SIZE=-100",
                Err(Error::InvalidParameter { param: "SIZE" }),
            ),
            (
                "MAIL FROM:<> SIZE=",
                Err(Error::InvalidParameter { param: "SIZE" }),
            ),
            (
                "MAIL FROM:<> BY=120;R BY=0;N BY=-10;RT BY=+22;NT",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::By(By::Return {
                            time: 120,
                            trace: false,
                        }),
                        Parameter::By(By::Notify {
                            time: 0,
                            trace: false,
                        }),
                        Parameter::By(By::Return {
                            time: -10,
                            trace: true,
                        }),
                        Parameter::By(By::Notify {
                            time: 22,
                            trace: true,
                        }),
                    ],
                }),
            ),
            (
                "MAIL FROM:<> BY=120",
                Err(Error::InvalidParameter { param: "BY" }),
            ),
            (
                "MAIL FROM:<> BY=120;T",
                Err(Error::InvalidParameter { param: "BY" }),
            ),
            (
                "MAIL FROM:<> BY=120;",
                Err(Error::InvalidParameter { param: "BY" }),
            ),
            (
                "MAIL FROM:<> BY=120;0",
                Err(Error::InvalidParameter { param: "BY" }),
            ),
            (
                "MAIL FROM:<> BY=120;;",
                Err(Error::InvalidParameter { param: "BY" }),
            ),
            (
                "MAIL FROM:<> BY=;",
                Err(Error::InvalidParameter { param: "BY" }),
            ),
            (
                "MAIL FROM:<> BY=;R",
                Err(Error::InvalidParameter { param: "BY" }),
            ),
            (
                "MAIL FROM:<> BY=",
                Err(Error::InvalidParameter { param: "BY" }),
            ),
            (
                "MAIL FROM:<> HOLDUNTIL=12345 HOLDFOR=67890",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![Parameter::HoldUntil(12345), Parameter::HoldFor(67890)],
                }),
            ),
            (
                "MAIL FROM:<> HOLDUNTIL=0ABC",
                Err(Error::InvalidParameter { param: "HOLDUNTIL" }),
            ),
            (
                "MAIL FROM:<> HOLDUNTIL=",
                Err(Error::InvalidParameter { param: "HOLDUNTIL" }),
            ),
            (
                "MAIL FROM:<> HOLDFOR=XYZ",
                Err(Error::InvalidParameter { param: "HOLDFOR" }),
            ),
            (
                "MAIL FROM:<> HOLDFOR=",
                Err(Error::InvalidParameter { param: "HOLDFOR" }),
            ),
            (
                concat!(
                    "MAIL FROM:<> NOTIFY=FAILURE NOTIFY=FAILURE,DELAY ",
                    "NOTIFY=SUCCESS,FAILURE,DELAY NOTIFY=NEVER"
                ),
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::Notify(NOTIFY_FAILURE),
                        Parameter::Notify(NOTIFY_FAILURE | NOTIFY_DELAY),
                        Parameter::Notify(NOTIFY_FAILURE | NOTIFY_DELAY | NOTIFY_SUCCESS),
                        Parameter::Notify(0),
                    ],
                }),
            ),
            (
                "MAIL FROM:<> NOTIFY=",
                Err(Error::InvalidParameter { param: "NOTIFY" }),
            ),
            (
                "MAIL FROM:<> NOTIFY=FAILURE,NEVER",
                Err(Error::InvalidParameter { param: "NOTIFY" }),
            ),
            (
                "MAIL FROM:<> NOTIFY=CHIMICHANGA",
                Err(Error::InvalidParameter { param: "NOTIFY" }),
            ),
            (
                concat!(
                    "MAIL FROM:<> ORCPT=rfc822;Bob@Example.COM ",
                    "ORCPT=rfc822;George+20@Tax-+20ME+20.GOV"
                ),
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::Orcpt(Orcpt {
                            addr_type: "rfc822".to_string(),
                            addr: "Bob@Example.COM".to_string(),
                        }),
                        Parameter::Orcpt(Orcpt {
                            addr_type: "rfc822".to_string(),
                            addr: "George @Tax- ME .GOV".to_string(),
                        }),
                    ],
                }),
            ),
            (
                "MAIL FROM:<> ORCPT=",
                Err(Error::InvalidParameter { param: "ORCPT" }),
            ),
            (
                "MAIL FROM:<> ORCPT=;hello@domain.org",
                Err(Error::InvalidParameter { param: "ORCPT" }),
            ),
            (
                "MAIL FROM:<> ORCPT=rfc822;",
                Err(Error::InvalidParameter { param: "ORCPT" }),
            ),
            (
                "MAIL FROM:<> ORCPT=;",
                Err(Error::InvalidParameter { param: "ORCPT" }),
            ),
            (
                "MAIL FROM:<> RET=HDRS RET=FULL",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![Parameter::Ret(Ret::Hdrs), Parameter::Ret(Ret::Full)],
                }),
            ),
            (
                "MAIL FROM:<> RET=",
                Err(Error::InvalidParameter { param: "RET" }),
            ),
            (
                "MAIL FROM:<> RET=ENCHILADA",
                Err(Error::InvalidParameter { param: "RET" }),
            ),
            (
                "MAIL FROM:<> ENVID=QQ314159 ENVID=hi+20there",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::EnvId("QQ314159".to_string()),
                        Parameter::EnvId("hi there".to_string()),
                    ],
                }),
            ),
            (
                "MAIL FROM:<> ENVID=",
                Err(Error::InvalidParameter { param: "ENVID" }),
            ),
            (
                concat!(
                    "MAIL FROM:<> SOLICIT=org.example:ADV:ADLT ",
                    " SOLICIT=net.example:ADV,org.example:ADV:ADLT"
                ),
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::Solicit("org.example:ADV:ADLT".to_string()),
                        Parameter::Solicit("net.example:ADV,org.example:ADV:ADLT".to_string()),
                    ],
                }),
            ),
            (
                "MAIL FROM:<> SOLICIT=",
                Err(Error::InvalidParameter { param: "SOLICIT" }),
            ),
            (
                "MAIL FROM:<> TRANSID=<12345@claremont.edu>",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![Parameter::TransId("12345@claremont.edu".to_string())],
                }),
            ),
            (
                "MAIL FROM:<> TRANSID=",
                Err(Error::InvalidParameter { param: "TRANSID" }),
            ),
            (
                "MAIL FROM:<> MTRK=my-ceritifier MTRK=other-certifier:1234",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::Mtrk(Mtrk {
                            certifier: "my-ceritifier".to_string(),
                            timeout: 0,
                        }),
                        Parameter::Mtrk(Mtrk {
                            certifier: "other-certifier".to_string(),
                            timeout: 1234,
                        }),
                    ],
                }),
            ),
            (
                "MAIL FROM:<> MTRK=",
                Err(Error::InvalidParameter { param: "MTRK" }),
            ),
            (
                "MAIL FROM:<> MTRK=:",
                Err(Error::InvalidParameter { param: "MTRK" }),
            ),
            (
                "MAIL FROM:<> MTRK=:998",
                Err(Error::InvalidParameter { param: "MTRK" }),
            ),
            (
                "MAIL FROM:<> MTRK=abc:",
                Err(Error::InvalidParameter { param: "MTRK" }),
            ),
            (
                "MAIL FROM:<> MTRK=abc:abc",
                Err(Error::InvalidParameter { param: "MTRK" }),
            ),
            (
                "MAIL FROM:<> AUTH=<> AUTH=e+3Dmc2@example.com",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::Auth("<>".to_string()),
                        Parameter::Auth("e=mc2@example.com".to_string()),
                    ],
                }),
            ),
            (
                "MAIL FROM:<> AUTH=",
                Err(Error::InvalidParameter { param: "AUTH" }),
            ),
            (
                "MAIL FROM:<> MT-PRIORITY=3 MT-PRIORITY=-6",
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![Parameter::MtPriority(3), Parameter::MtPriority(-6)],
                }),
            ),
            (
                "MAIL FROM:<> MT-PRIORITY=",
                Err(Error::InvalidParameter {
                    param: "MT-PRIORITY",
                }),
            ),
            (
                "MAIL FROM:<> MT-PRIORITY=ab",
                Err(Error::InvalidParameter {
                    param: "MT-PRIORITY",
                }),
            ),
            (
                "MAIL FROM:<> MT-PRIORITY=-",
                Err(Error::InvalidParameter {
                    param: "MT-PRIORITY",
                }),
            ),
            (
                concat!(
                    "MAIL FROM:<> RRVS=2014-04-03T23:01:00Z ",
                    "RRVS=1997-11-24T14:22:01-08:00;C ",
                    "RRVS=2003-07-01T10:52:37+02:00;R"
                ),
                Ok(Request::Mail {
                    from: "".to_string(),
                    parameters: vec![
                        Parameter::Rrvs(Rrvs::Reject(1396566060)),
                        Parameter::Rrvs(Rrvs::Continue(880410121)),
                        Parameter::Rrvs(Rrvs::Reject(1057049557)),
                    ],
                }),
            ),
            (
                "MAIL FROM:<> RRVS=",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
            (
                "MAIL FROM:<> RRVS=2022-01-02",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
            (
                "MAIL FROM:<> RRVS=2022-01-02T01:01:01",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
            (
                "MAIL FROM:<> RRVS=2022-01-02T01:01:01ZZ",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
            (
                "MAIL FROM:<> RRVS=ABC",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
        ] {
            let (request, parsed_request): (&str, Result<Request<String>, Error>) = item;

            for extra in ["\n", "\r\n", " \n", " \r\n"] {
                let request = format!("{}{}", request, extra);
                assert_eq!(
                    parsed_request,
                    Request::parse(&mut request.as_bytes().iter()),
                    "failed for {:?}",
                    request
                );
            }
        }
    }
}

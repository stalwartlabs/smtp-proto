/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use std::borrow::Cow;
use std::char;
use std::slice::Iter;

use crate::*;

use super::*;

const MAX_ADDRESS_LEN: usize = 256;
const MAX_DOMAIN_LEN: usize = 255;

impl<'a> Request<Cow<'a, str>> {
    pub fn parse(bytes: &mut Iter<'a, u8>) -> Result<Request<Cow<'a, str>>, Error> {
        let mut parser = Rfc5321Parser::new(bytes);
        let command = parser.hashed_value()?;
        if !parser.stop_char.is_ascii_whitespace() {
            parser.seek_lf()?;
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
                                to: parser.rcpt_to_parameters(to)?,
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
                                from: parser.mail_from_parameters(from)?,
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
                    if (1..=MAX_DOMAIN_LEN).contains(&host.len()) {
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
                if parser.stop_char != LF
                    && let Some(mechanism) = parser.mechanism()?
                {
                    let initial_response = if parser.stop_char != LF {
                        parser.text()?
                    } else {
                        Cow::Borrowed("")
                    };
                    parser.seek_lf()?;
                    return Ok(Request::Auth {
                        mechanism,
                        initial_response,
                    });
                }
                Err(Error::SyntaxError {
                    syntax: "AUTH mechanism [initial-response]",
                })
            }
            EXPN => {
                if parser.stop_char != LF {
                    let value = parser.string()?;
                    parser.seek_lf()?;
                    if (1..=MAX_ADDRESS_LEN).contains(&value.len()) {
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
                        value: Cow::Borrowed(""),
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
                    if (1..=MAX_DOMAIN_LEN).contains(&host.len()) {
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
                    if (1..=MAX_ADDRESS_LEN).contains(&value.len()) {
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
                        value: Cow::Borrowed(""),
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
                    if (1..=MAX_DOMAIN_LEN).contains(&host.len()) {
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

    pub fn address(&mut self) -> Result<Option<Cow<'y, str>>, Error> {
        let mut value = self.start_zero_copy();
        let mut last_ch = 0;
        let mut in_quote = false;
        let mut at_count = 0;
        let mut lp_len = 0;

        while let Some(&ch) = self.bytes.next() {
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
                | 0x7f..=u8::MAX => {}
                b'.' if !in_quote => {
                    if last_ch == b'.' || last_ch == b'@' || self.len_excluding_current(&value) == 0
                    {
                        self.stop_char = ch;
                        return Ok(None);
                    }
                }
                b'@' if !in_quote => {
                    at_count += 1;
                    lp_len = self.len_excluding_current(&value);
                }
                b'>' if !in_quote => {
                    self.stop_char = ch;
                    self.flush_excluding_current(&mut value);
                    let value = value.data;

                    let is_valid = value.is_empty()
                        || value.len() <= MAX_ADDRESS_LEN && at_count == 1 && lp_len > 0;

                    return Ok(is_valid.then_some(value));
                }
                b'\r' => self.flush_excluding_current(&mut value),
                b':' if !in_quote && self.first_excluding_current(&value) == Some(b'@') => {
                    // Remove source route
                    value = self.start_zero_copy();
                    at_count = 0;
                    lp_len = 0;
                }
                // Note that if there is an @ at the start, we require `:` a to be in the string
                // later, since otherwise `at_count == 1 && lp_len > 0` cannot be satisfied. So it
                // doesn't matter what we do here (other than not error).
                b',' if !in_quote && self.first_excluding_current(&value) == Some(b'@') => (),
                b' ' if !in_quote => {
                    self.flush_excluding_current(&mut value);
                    if !value.data.is_empty() {
                        self.stop_char = b' ';
                        let value = value.data;

                        let is_valid = value.is_empty()
                            || value.len() <= MAX_ADDRESS_LEN && at_count == 1 && lp_len > 0;

                        return Ok(is_valid.then_some(value));
                    }
                }
                b'\n' => {
                    self.stop_char = b'\n';
                    self.flush_excluding_current(&mut value);
                    let value = value.data;

                    let is_valid = value.is_empty()
                        || value.len() <= MAX_ADDRESS_LEN && at_count == 1 && lp_len > 0;

                    return Ok(is_valid.then_some(value));
                }
                b'\"' if !in_quote || last_ch != b'\\' => {
                    in_quote = !in_quote;
                    self.flush_excluding_current(&mut value);
                }
                b'\\' if in_quote => {
                    if last_ch != b'\\' {
                        self.flush_excluding_current(&mut value);
                    } else {
                        // Escaped backslash
                        last_ch = 0;
                        continue;
                    }
                }
                _ if in_quote => {}
                _ => {
                    self.stop_char = ch;
                    return Ok(None);
                }
            }

            last_ch = ch;
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    pub fn string(&mut self) -> Result<Cow<'y, str>, Error> {
        let mut in_quote = false;
        let mut value = self.start_zero_copy();
        let mut last_ch = 0;

        while let Some(&ch) = self.bytes.next() {
            match ch {
                b' ' if !in_quote => {
                    self.flush_excluding_current(&mut value);
                    if !value.data.is_empty() {
                        self.stop_char = b' ';
                        return Ok(value.data);
                    }
                }
                b'\n' => {
                    self.flush_excluding_current(&mut value);
                    self.stop_char = b'\n';
                    return Ok(value.data);
                }
                b'\"' if !in_quote || last_ch != b'\\' => {
                    in_quote = !in_quote;
                    self.flush_excluding_current(&mut value);
                }
                b'\\' if in_quote => {
                    if last_ch != b'\\' {
                        self.flush_excluding_current(&mut value);
                    } else {
                        last_ch = 0;
                        continue;
                    }
                }
                b'\r' => self.flush_excluding_current(&mut value),
                _ => {}
            }

            last_ch = ch;
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn text(&mut self) -> Result<Cow<'y, str>, Error> {
        let mut value = self.start_zero_copy();
        while let Some(&ch) = self.bytes.next() {
            match ch {
                b'\n' | b' ' => {
                    self.flush_excluding_current(&mut value);
                    self.stop_char = ch;
                    return Ok(value.data);
                }
                b'\r' => self.flush_excluding_current(&mut value),
                _ => {}
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn xtext(&mut self) -> Result<Cow<'y, str>, Error> {
        let mut value = self.start_zero_copy();
        while let Some(&ch) = self.bytes.next() {
            match ch {
                b'\n' | b' ' => {
                    self.flush_excluding_current(&mut value);
                    self.stop_char = ch;
                    return Ok(value.data);
                }
                b'+' => {
                    self.flush_excluding_current(&mut value);

                    let mut hex1 = None;

                    while let Some(&ch) = self.bytes.next() {
                        if let Some(digit) = char::from(ch).to_digit(16) {
                            if let Some(hex1) = hex1 {
                                let data = value.data.to_mut();
                                data.push(char::from(((hex1 as u8) << 4) | digit as u8));
                                break;
                            } else {
                                hex1 = Some(digit);
                            }
                        } else if ch == LF {
                            self.stop_char = b'\n';
                            return Ok(value.data);
                        } else {
                            break;
                        }
                    }

                    self.drop_extra(&mut value);
                }
                b'\r' => self.flush_excluding_current(&mut value),
                _ => {}
            }
        }

        Err(Error::NeedsMoreData {
            bytes_left: self.bytes_left,
        })
    }

    #[allow(clippy::while_let_on_iterator)]
    pub fn seek_char(&mut self, stop_char: u8) -> Result<Cow<'y, str>, Error> {
        let mut value = self.start_zero_copy();
        while let Some(&ch) = self.bytes.next() {
            match ch {
                b'\n' => {
                    self.flush_excluding_current(&mut value);
                    self.stop_char = b'\n';
                    return Ok(value.data);
                }
                b' ' => {
                    self.flush_excluding_current(&mut value);
                    if !value.data.is_empty() {
                        self.stop_char = b' ';
                        return Ok(value.data);
                    }
                }
                b'\r' => self.flush_excluding_current(&mut value),
                _ if ch == stop_char => {
                    self.flush_excluding_current(&mut value);
                    self.stop_char = ch;
                    return Ok(value.data);
                }
                _ => {}
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

    pub fn mail_from_parameters(
        &mut self,
        address: Cow<'y, str>,
    ) -> Result<MailFrom<Cow<'y, str>>, Error> {
        let mut params = MailFrom {
            address,
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
        };
        while self.stop_char != LF {
            let key = self.hashed_value_long()?;
            match key {
                SMTPUTF8 if self.stop_char.is_ascii_whitespace() => {
                    params.flags |= MAIL_SMTPUTF8;
                }
                BODY if self.stop_char == b'=' => {
                    params.flags |= match self.hashed_value_long()? {
                        EIGHBITMIME if self.stop_char.is_ascii_whitespace() => MAIL_BODY_8BITMIME,
                        BINARYMIME if self.stop_char.is_ascii_whitespace() => MAIL_BODY_BINARYMIME,
                        SEVENBIT if self.stop_char.is_ascii_whitespace() => MAIL_BODY_7BIT,
                        _ => {
                            self.seek_lf()?;
                            return Err(Error::InvalidParameter { param: "BODY" });
                        }
                    }
                }
                SIZE if self.stop_char == b'=' => {
                    let size = self.size()?;
                    if size != usize::MAX && self.stop_char.is_ascii_whitespace() {
                        params.size = size;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "SIZE" });
                    }
                }
                BY if self.stop_char == b'=' => {
                    let time = self.integer()?;
                    if time != i64::MAX && self.stop_char == b';' {
                        params.flags |= match self.hashed_value()? {
                            N if self.stop_char.is_ascii_whitespace() => MAIL_BY_NOTIFY,
                            NT if self.stop_char.is_ascii_whitespace() => {
                                MAIL_BY_NOTIFY | MAIL_BY_TRACE
                            }
                            R if self.stop_char.is_ascii_whitespace() => MAIL_BY_RETURN,
                            RT if self.stop_char.is_ascii_whitespace() => {
                                MAIL_BY_RETURN | MAIL_BY_TRACE
                            }
                            _ => {
                                self.seek_lf()?;
                                return Err(Error::InvalidParameter { param: "BY" });
                            }
                        };
                        params.by = time;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "BY" });
                    }
                }
                HOLDUNTIL if self.stop_char == b'=' => {
                    let hold = self.size()?;
                    if hold != usize::MAX && self.stop_char.is_ascii_whitespace() {
                        params.hold_until = hold as u64;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "HOLDUNTIL" });
                    }
                }
                HOLDFOR if self.stop_char == b'=' => {
                    let hold = self.size()?;
                    if hold != usize::MAX && self.stop_char.is_ascii_whitespace() {
                        params.hold_for = hold as u64;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "HOLDFOR" });
                    }
                }
                RET if self.stop_char == b'=' => {
                    params.flags |= match self.hashed_value()? {
                        FULL if self.stop_char.is_ascii_whitespace() => MAIL_RET_FULL,
                        HDRS if self.stop_char.is_ascii_whitespace() => MAIL_RET_HDRS,
                        _ => {
                            self.seek_lf()?;
                            return Err(Error::InvalidParameter { param: "RET" });
                        }
                    };
                }
                ENVID if self.stop_char == b'=' => {
                    let env_id = self.xtext()?;
                    if self.stop_char.is_ascii_whitespace() && (1..=100).contains(&env_id.len()) {
                        params.env_id = env_id.into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "ENVID" });
                    }
                }
                REQUIRETLS if self.stop_char.is_ascii_whitespace() => {
                    params.flags |= MAIL_REQUIRETLS;
                }
                SOLICIT if self.stop_char == b'=' => {
                    let solicit = self.text()?;
                    if !solicit.is_empty() && self.stop_char.is_ascii_whitespace() {
                        params.solicit = solicit.into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "SOLICIT" });
                    }
                }
                TRANSID if self.stop_char == b'=' => {
                    if self.next_char()? == b'<' {
                        let transid = self.seek_char(b'>')?;
                        if self.stop_char == b'>' && !transid.is_empty() {
                            params.trans_id = transid.into();
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
                        params.mtrk = Mtrk {
                            certifier,
                            timeout: timeout as u64,
                        }
                        .into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "MTRK" });
                    }
                }
                AUTH_ if self.stop_char == b'=' => {
                    let mailbox = self.xtext()?;
                    if (1..=MAX_ADDRESS_LEN).contains(&mailbox.len())
                        && self.stop_char.is_ascii_whitespace()
                    {
                        params.auth = mailbox.into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "AUTH" });
                    }
                }
                MT_PRIORITY if self.stop_char == b'=' => {
                    let priority = self.integer()?;
                    if priority != i64::MAX && self.stop_char.is_ascii_whitespace() {
                        params.mt_priority = priority;
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter {
                            param: "MT-PRIORITY",
                        });
                    }
                }
                CONPERM if self.stop_char.is_ascii_whitespace() => {
                    params.flags |= MAIL_CONPERM;
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

    pub fn rcpt_to_parameters(
        &mut self,
        address: Cow<'y, str>,
    ) -> Result<RcptTo<Cow<'y, str>>, Error> {
        let mut params = RcptTo {
            address,
            orcpt: None,
            rrvs: 0,
            flags: 0,
        };
        while self.stop_char != LF {
            let key = self.hashed_value_long()?;
            match key {
                NOTIFY if self.stop_char == b'=' => loop {
                    match self.hashed_value_long()? {
                        NEVER
                            if (params.flags
                                & (RCPT_NOTIFY_NEVER
                                    | RCPT_NOTIFY_SUCCESS
                                    | RCPT_NOTIFY_FAILURE
                                    | RCPT_NOTIFY_DELAY))
                                == 0 =>
                        {
                            params.flags |= RCPT_NOTIFY_NEVER;
                        }
                        SUCCESS => {
                            params.flags |= RCPT_NOTIFY_SUCCESS;
                        }
                        FAILURE => {
                            params.flags |= RCPT_NOTIFY_FAILURE;
                        }
                        DELAY => {
                            params.flags |= RCPT_NOTIFY_DELAY;
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
                },
                ORCPT if self.stop_char == b'=' => {
                    let v = self.hashed_value()?;
                    if v != RFC822 || self.stop_char != b';' {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "ORCPT" });
                    }
                    let addr = self.xtext()?;
                    if self.stop_char.is_ascii_whitespace()
                        && (1..=MAX_ADDRESS_LEN).contains(&addr.len())
                    {
                        params.orcpt = addr.into();
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "ORCPT" });
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
                        params.rrvs = time;
                        params.flags |= if is_reject {
                            RCPT_RRVS_REJECT
                        } else {
                            RCPT_RRVS_CONTINUE
                        };
                    } else {
                        self.seek_lf()?;
                        return Err(Error::InvalidParameter { param: "RRVS" });
                    }
                }
                CONNEG if self.stop_char.is_ascii_whitespace() => {
                    params.flags |= RCPT_CONNEG;
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

    /// Construct a new `MaybeZeroCopy`, beginning a potentially zero-copy read from the input.
    fn start_zero_copy(&self) -> MaybeZeroCopy<'y> {
        MaybeZeroCopy {
            remaining: self.bytes.as_slice(),
            data: Cow::Borrowed(""),
        }
    }

    /// Get the slice starting at the last time `MaybeZeroCopy` was flushed and ending one byte
    /// before where `Self` currently is. This is what will be pushed to the `MaybeZeroCopy` on
    /// flush.
    fn extra_before_current(&self, out: &MaybeZeroCopy<'y>) -> &'y [u8] {
        // Calculate the number of bytes we have advanced our iterator from the start of the
        // `MaybeZeroCopy`. Subtract one to remove the current byte.
        let new_len = self.bytes.as_slice().as_ptr().addr() - out.remaining.as_ptr().addr() - 1;
        &out.remaining[..new_len]
    }

    /// Get the length of a `MaybeZeroCopy`.
    fn len_excluding_current(&self, out: &MaybeZeroCopy<'y>) -> usize {
        out.data.len() + self.extra_before_current(out).len()
    }

    /// Get the first byte of a `MaybeZeroCopy`.
    fn first_excluding_current(&self, out: &MaybeZeroCopy<'y>) -> Option<u8> {
        let first = out.data.bytes().next();
        first.or_else(|| self.extra_before_current(out).first().copied())
    }

    /// Drop data up to the current cursor from the `MaybeZeroCopy`.
    fn drop_extra(&self, out: &mut MaybeZeroCopy<'y>) {
        out.remaining = self.bytes.as_slice();
    }

    /// Extend a `MaybeZeroCopy` with new bytes.
    fn flush_excluding_current(&self, out: &mut MaybeZeroCopy<'y>) {
        let extra = self.extra_before_current(out);
        self.drop_extra(out);

        if out.data.is_empty() {
            out.data = String::from_utf8_lossy(extra);
        } else {
            if let Cow::Borrowed(s) = out.data {
                let mut buf = String::with_capacity(32);
                buf.push_str(s);
                out.data = Cow::Owned(buf);
            }

            // The same algorithm as `String::from_utf8_lossy`, but appending to an existing
            // buffer.
            let out = out.data.to_mut();
            for chunk in extra.utf8_chunks() {
                out.push_str(chunk.valid());
                if !chunk.invalid().is_empty() {
                    out.push(char::REPLACEMENT_CHARACTER);
                }
            }
        }
    }
}

/// A state machine enabling parsing to be potentially zero-copy.
struct MaybeZeroCopy<'y> {
    /// Slice from where we start parsing to the end of the input.
    remaining: &'y [u8],
    /// The data itself.
    data: Cow<'y, str>,
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use crate::*;

    #[test]
    fn parse_request() {
        for item in [
            // HELO et al.
            (
                "EHLO bar.com",
                Ok(Request::Ehlo {
                    host: Cow::Borrowed("bar.com"),
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
                    host: "bar.com".into(),
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
                    host: "bar.com".into(),
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
                    value: "Hello".into(),
                }),
            ),
            (
                "VRFY \"Hello\\\" Wo\\\\rld\"",
                Ok(Request::Vrfy {
                    value: "Hello\" Wo\\rld".into(),
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
                    value: "Hello".into(),
                }),
            ),
            (
                "EXPN \"Hello\\\" Wo\\\\rld\"",
                Ok(Request::Expn {
                    value: "Hello\" Wo\\rld".into(),
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
            ("NOOP", Ok(Request::Noop { value: "".into() })),
            (
                "NOOP Hello",
                Ok(Request::Noop {
                    value: "Hello".into(),
                }),
            ),
            // HELP
            ("HELP", Ok(Request::Help { value: "".into() })),
            (
                "HELP Hello",
                Ok(Request::Help {
                    value: "Hello".into(),
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
                    initial_response: "".into(),
                }),
            ),
            (
                "AUTH ECDSA-NIST256P-CHALLENGE =",
                Ok(Request::Auth {
                    mechanism: AUTH_ECDSA_NIST256P_CHALLENGE,
                    initial_response: "=".into(),
                }),
            ),
            (
                "AUTH SCRAM-SHA-256-PLUS base64_goes_here",
                Ok(Request::Auth {
                    mechanism: AUTH_SCRAM_SHA_256_PLUS,
                    initial_response: "base64_goes_here".into(),
                }),
            ),
            (
                "AUTH ECDSA-NIST256P-CHALLENGE100 abcde",
                Ok(Request::Auth {
                    mechanism: 0,
                    initial_response: "abcde".into(),
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
                    name: "Hello".into(),
                }),
            ),
            (
                "ETRN \"Hello\\\" Wo\\\\rld\"",
                Ok(Request::Etrn {
                    name: "Hello\" Wo\\rld".into(),
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
                    domains: vec!["example.org".into()],
                }),
            ),
            (
                "ATRN example.org,example.com,example.net",
                Ok(Request::Atrn {
                    domains: vec![
                        "example.org".into(),
                        "example.com".into(),
                        "example.net".into(),
                    ],
                }),
            ),
            (
                "ATRN example.org, example.com, example.net",
                Ok(Request::Atrn {
                    domains: vec![
                        "example.org".into(),
                        "example.com".into(),
                        "example.net".into(),
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
                    .into(),
                    is_last: true,
                }),
            ),
            (
                "BURL imap:://test.example.org",
                Ok(Request::Burl {
                    uri: "imap:://test.example.org".into(),
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
                    from: "JQP@bar.com".into(),
                }),
            ),
            (
                "MAIL FROM:<@a,@b:user@d>",
                Ok(Request::Mail {
                    from: "user@d".into(),
                }),
            ),
            (
                "MAIL FROM:<\"@a,@b:<user>\"@d>",
                Ok(Request::Mail {
                    from: "@a,@b:<user>@d".into(),
                }),
            ),
            (
                "MAIL FROM: <\" hi there! \"@d>",
                Ok(Request::Mail {
                    from: " hi there! @d".into(),
                }),
            ),
            ("MAIL  FROM : <>", Ok(Request::Mail { from: "".into() })),
            ("MAIL  FROM : < >", Ok(Request::Mail { from: "".into() })),
            (
                "MAIL FROM:<hi.there@valid.org>",
                Ok(Request::Mail {
                    from: "hi.there@valid.org".into(),
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
                    to: "孫子@áéíóú.org".into(),
                }),
            ),
            // RCPT TO
            (
                "RCPT TO:<Jones@XYZ.COM>",
                Ok(Request::Rcpt {
                    to: "Jones@XYZ.COM".into(),
                }),
            ),
            ("RCPT TO:<>", Ok(Request::Rcpt { to: "".into() })),
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
                    from: MailFrom {
                        address: "".into(),
                        flags: MAIL_SMTPUTF8,
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> SMTPUTF8 REQUIRETLS CONPERM",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        flags: MAIL_SMTPUTF8 | MAIL_REQUIRETLS | MAIL_CONPERM,
                        ..Default::default()
                    },
                }),
            ),
            (
                "RCPT TO:<> CONNEG",
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        flags: RCPT_CONNEG,
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> BODY=BINARYMIME BODY=7BIT BODY=8BITMIME",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        flags: MAIL_BODY_7BIT | MAIL_BODY_8BITMIME | MAIL_BODY_BINARYMIME,
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> BODY=OTHER",
                Err(Error::InvalidParameter { param: "BODY" }),
            ),
            (
                "MAIL FROM:<> SIZE=500000",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        size: 500000,
                        ..Default::default()
                    },
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
                "MAIL FROM:<> BY=120;R",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        by: 120,
                        flags: MAIL_BY_RETURN,
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> BY=0;N",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        by: 0,
                        flags: MAIL_BY_NOTIFY,
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> BY=-10;RT",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        by: -10,
                        flags: MAIL_BY_RETURN | MAIL_BY_TRACE,
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> BY=+22;NT",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        by: 22,
                        flags: MAIL_BY_NOTIFY | MAIL_BY_TRACE,
                        ..Default::default()
                    },
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
                    from: MailFrom {
                        address: "".into(),
                        hold_for: 67890,
                        hold_until: 12345,
                        ..Default::default()
                    },
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
                "RCPT TO:<> NOTIFY=FAILURE",
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        flags: RCPT_NOTIFY_FAILURE,
                        ..Default::default()
                    },
                }),
            ),
            (
                "RCPT TO:<> NOTIFY=FAILURE,DELAY",
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        flags: RCPT_NOTIFY_FAILURE | RCPT_NOTIFY_DELAY,
                        ..Default::default()
                    },
                }),
            ),
            (
                "RCPT TO:<> NOTIFY=SUCCESS,FAILURE,DELAY",
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        flags: RCPT_NOTIFY_FAILURE | RCPT_NOTIFY_DELAY | RCPT_NOTIFY_SUCCESS,
                        ..Default::default()
                    },
                }),
            ),
            (
                "RCPT TO:<> NOTIFY=NEVER",
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        flags: RCPT_NOTIFY_NEVER,
                        ..Default::default()
                    },
                }),
            ),
            (
                "RCPT TO:<> NOTIFY=",
                Err(Error::InvalidParameter { param: "NOTIFY" }),
            ),
            (
                "RCPT TO:<> NOTIFY=FAILURE,NEVER",
                Err(Error::InvalidParameter { param: "NOTIFY" }),
            ),
            (
                "RCPT TO:<> NOTIFY=CHIMICHANGA",
                Err(Error::InvalidParameter { param: "NOTIFY" }),
            ),
            (
                "RCPT TO:<> ORCPT=rfc822;Bob@Example.COM",
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        orcpt: Some("Bob@Example.COM".into()),
                        ..Default::default()
                    },
                }),
            ),
            (
                concat!("RCPT TO:<> ", "ORCPT=rfc822;George+20@Tax-+20ME+20.GOV"),
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        orcpt: Some("George @Tax- ME .GOV".into()),
                        ..Default::default()
                    },
                }),
            ),
            (
                "RCPT TO:<> ORCPT=",
                Err(Error::InvalidParameter { param: "ORCPT" }),
            ),
            (
                "RCPT TO:<> ORCPT=;hello@domain.org",
                Err(Error::InvalidParameter { param: "ORCPT" }),
            ),
            (
                "RCPT TO:<> ORCPT=rfc822;",
                Err(Error::InvalidParameter { param: "ORCPT" }),
            ),
            (
                "RCPT TO:<> ORCPT=;",
                Err(Error::InvalidParameter { param: "ORCPT" }),
            ),
            (
                "MAIL FROM:<> RET=HDRS RET=FULL",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        flags: MAIL_RET_FULL | MAIL_RET_HDRS,
                        ..Default::default()
                    },
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
                "MAIL FROM:<> ENVID=QQ314159",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        env_id: Some("QQ314159".into()),
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> ENVID=hi+20there",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        env_id: Some("hi there".into()),
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> ENVID=",
                Err(Error::InvalidParameter { param: "ENVID" }),
            ),
            (
                "MAIL FROM:<> SOLICIT=org.example:ADV:ADLT",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        solicit: Some("org.example:ADV:ADLT".into()),
                        ..Default::default()
                    },
                }),
            ),
            (
                concat!(
                    "MAIL FROM:<> ",
                    " SOLICIT=net.example:ADV,org.example:ADV:ADLT"
                ),
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        solicit: Some("net.example:ADV,org.example:ADV:ADLT".into()),
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> SOLICIT=",
                Err(Error::InvalidParameter { param: "SOLICIT" }),
            ),
            (
                "MAIL FROM:<> TRANSID=<12345@claremont.edu>",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        trans_id: Some("12345@claremont.edu".into()),
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> TRANSID=",
                Err(Error::InvalidParameter { param: "TRANSID" }),
            ),
            (
                "MAIL FROM:<> MTRK=my-ceritifier",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        mtrk: Mtrk {
                            certifier: "my-ceritifier".into(),
                            timeout: 0,
                        }
                        .into(),
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> MTRK=other-certifier:1234",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        mtrk: Mtrk {
                            certifier: "other-certifier".into(),
                            timeout: 1234,
                        }
                        .into(),
                        ..Default::default()
                    },
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
                "MAIL FROM:<> AUTH=<>",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        auth: Some("<>".into()),
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> AUTH=e+3Dmc2@example.com",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        auth: Some("e=mc2@example.com".into()),
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> AUTH=",
                Err(Error::InvalidParameter { param: "AUTH" }),
            ),
            (
                "MAIL FROM:<> MT-PRIORITY=3",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        mt_priority: 3,
                        ..Default::default()
                    },
                }),
            ),
            (
                "MAIL FROM:<> MT-PRIORITY=-6",
                Ok(Request::Mail {
                    from: MailFrom {
                        address: "".into(),
                        mt_priority: -6,
                        ..Default::default()
                    },
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
                "RCPT TO:<> RRVS=2014-04-03T23:01:00Z",
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        rrvs: 1396566060,
                        flags: RCPT_RRVS_REJECT,
                        ..Default::default()
                    },
                }),
            ),
            (
                "RCPT TO:<> RRVS=1997-11-24T14:22:01-08:00;C",
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        rrvs: 880410121,
                        flags: RCPT_RRVS_CONTINUE,
                        ..Default::default()
                    },
                }),
            ),
            (
                "RCPT TO:<> RRVS=2003-07-01T10:52:37+02:00;R",
                Ok(Request::Rcpt {
                    to: RcptTo {
                        address: "".into(),
                        rrvs: 1057049557,
                        flags: RCPT_RRVS_REJECT,
                        ..Default::default()
                    },
                }),
            ),
            (
                "RCPT TO:<> RRVS=",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
            (
                "RCPT TO:<> RRVS=2022-01-02",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
            (
                "RCPT TO:<> RRVS=2022-01-02T01:01:01",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
            (
                "RCPT TO:<> RRVS=2022-01-02T01:01:01ZZ",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
            (
                "RCPT TO:<> RRVS=ABC",
                Err(Error::InvalidParameter { param: "RRVS" }),
            ),
            (
                r#"MAIL FROM:<foo@bar"aa\\" hello world".com>"#,
                Err(Error::SyntaxError {
                    syntax: "MAIL FROM:<reverse-path> [parameters]",
                }),
            ),
            (
                r#"MAIL FROM:<foo@bar"aa\" hello world".com>"#,
                Ok(Request::Mail {
                    from: r#"foo@baraa" hello world.com"#.into(),
                }),
            ),
        ] {
            let (request, parsed_request): (&str, Result<Request<Cow<'_, str>>, Error>) = item;

            for extra in ["\n", "\r\n", " \n", " \r\n"] {
                let request = format!("{request}{extra}");
                assert_eq!(
                    parsed_request,
                    Request::parse(&mut request.as_bytes().iter()),
                    "failed for {request:?}"
                );
            }
        }
    }

    impl<'a> From<&'a str> for MailFrom<Cow<'a, str>> {
        fn from(value: &'a str) -> Self {
            Self {
                address: value.into(),
                ..Default::default()
            }
        }
    }

    impl<'a> From<&'a str> for RcptTo<Cow<'a, str>> {
        fn from(value: &'a str) -> Self {
            Self {
                address: value.into(),
                ..Default::default()
            }
        }
    }
}

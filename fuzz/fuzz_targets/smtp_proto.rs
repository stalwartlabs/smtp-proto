/*
 * Copyright (c) 2020-2023, Stalwart Labs Ltd.
 *
 * This file is part of the Stalwart SMTP protocol parser.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 * in the LICENSE file at the top-level directory of this distribution.
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * You can be released from the requirements of the AGPLv3 license by
 * purchasing a commercial license. Please contact licensing@stalw.art
 * for more details.
*/

#![no_main]
use libfuzzer_sys::fuzz_target;

use smtp_proto::{
    request::{
        parser::Rfc5321Parser,
        receiver::{
            BdatReceiver, DataReceiver, DummyDataReceiver, DummyLineReceiver, LineReceiver,
            RequestReceiver,
        },
    },
    response::parser::ResponseReceiver,
    EhloResponse, Request,
};

static RFC5321_ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz:=-<>,; \r\n";

fuzz_target!(|data: &[u8]| {
    let data_rfc5321 = into_alphabet(data, RFC5321_ALPHABET);

    for bytes in [data, &data_rfc5321] {
        let _ = Request::parse(&mut bytes.iter());
        let _ = RequestReceiver::default().ingest(&mut bytes.iter(), &[]);
        let _ = DataReceiver::new().ingest(&mut bytes.iter(), &mut vec![]);
        let _ = BdatReceiver::new(bytes.len(), true).ingest(&mut bytes.iter(), &mut vec![]);
        let _ = BdatReceiver::new(bytes.len(), false).ingest(&mut bytes.iter(), &mut vec![]);
        let _ = DummyDataReceiver::new_bdat(bytes.len()).ingest(&mut bytes.iter());
        let _ = DummyDataReceiver::new_data(&DataReceiver::new()).ingest(&mut bytes.iter());
        let _ = LineReceiver::new(()).ingest(&mut bytes.iter());
        let _ = DummyLineReceiver::default().ingest(&mut bytes.iter());
        let _ = ResponseReceiver::default().parse(&mut bytes.iter());
        let _ = EhloResponse::<String>::parse(&mut bytes.iter());

        let _ = Rfc5321Parser::new(&mut bytes.iter()).hashed_value();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).hashed_value_long();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).address();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).string();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).text();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).xtext();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).seek_char(0);
        let _ = Rfc5321Parser::new(&mut bytes.iter()).seek_lf();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).next_char();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).read_char();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).size();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).integer();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).timestamp();
        let _ = Rfc5321Parser::new(&mut bytes.iter()).mail_from_parameters(String::new());
        let _ = Rfc5321Parser::new(&mut bytes.iter()).rcpt_to_parameters(String::new());
        let _ = Rfc5321Parser::new(&mut bytes.iter()).mechanism();
    }
});

fn into_alphabet(data: &[u8], alphabet: &[u8]) -> Vec<u8> {
    data.iter()
        .map(|&byte| alphabet[byte as usize % alphabet.len()])
        .collect()
}

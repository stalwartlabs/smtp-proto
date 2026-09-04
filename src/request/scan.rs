/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use crate::LF;
pub(super) const MEMCHR_MIN_LEN: usize = 16;

const SWAR_LOW: u64 = 0x0101_0101_0101_0101;
const SWAR_HIGH: u64 = 0x8080_8080_8080_8080;
const ATEXT: [bool; 256] = build_atext();

pub(super) const TOKEN_UPPER: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut index = 0;
    while index < table.len() {
        let ch = index as u8;
        table[index] = match ch {
            b'A'..=b'Z' | b'0'..=b'9' | b'-' => ch,
            b'a'..=b'z' => ch - b'a' + b'A',
            _ => 0,
        };
        index += 1;
    }
    table
};

const fn build_atext() -> [bool; 256] {
    let mut table = [false; 256];
    let mut index = 0;
    while index < 256 {
        table[index] = is_atext(index as u8);
        index += 1;
    }
    table
}

#[inline(always)]
const fn is_atext(ch: u8) -> bool {
    matches!(
        ch,
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
            | 0x7f..=u8::MAX
    )
}

#[inline(always)]
const fn swar_splat(byte: u8) -> u64 {
    SWAR_LOW.wrapping_mul(byte as u64)
}

#[inline(always)]
const fn swar_zero_byte(word: u64) -> u64 {
    word.wrapping_sub(SWAR_LOW) & !word & SWAR_HIGH
}

#[inline(always)]
pub(super) fn find_lf(slice: &[u8]) -> Option<usize> {
    memchr::memchr(LF, slice)
}

#[inline(always)]
pub(super) fn find_any3(slice: &[u8], a: u8, b: u8, c: u8) -> Option<usize> {
    if slice.len() < MEMCHR_MIN_LEN {
        slice.iter().position(|&ch| ch == a || ch == b || ch == c)
    } else {
        memchr::memchr3(a, b, c, slice)
    }
}

#[inline(always)]
pub(super) fn find_any4(slice: &[u8], a: u8, b: u8, c: u8, d: u8) -> Option<usize> {
    let (chunks, rest) = slice.as_chunks::<8>();
    for (index, chunk) in chunks.iter().enumerate() {
        let word = u64::from_le_bytes(*chunk);
        let hits = swar_zero_byte(word ^ swar_splat(a))
            | swar_zero_byte(word ^ swar_splat(b))
            | swar_zero_byte(word ^ swar_splat(c))
            | swar_zero_byte(word ^ swar_splat(d));
        if hits != 0 {
            return Some(index * 8 + (hits.trailing_zeros() / 8) as usize);
        }
    }

    rest.iter()
        .position(|&ch| ch == a || ch == b || ch == c || ch == d)
        .map(|pos| chunks.len() * 8 + pos)
}

#[inline(always)]
pub(super) fn find_non_atext(slice: &[u8]) -> Option<usize> {
    slice.iter().position(|&ch| !ATEXT[ch as usize])
}

#[inline(always)]
pub(super) fn split_at_index(slice: &[u8], pos: Option<usize>) -> (Option<u8>, &[u8]) {
    match pos.and_then(|pos| slice.split_at_checked(pos + 1)) {
        Some((head, tail)) => (head.last().copied(), tail),
        None => (None, &slice[slice.len()..]),
    }
}

#[inline(always)]
pub(super) fn preceding_byte(slice: &[u8], rest: &[u8]) -> Option<u8> {
    slice
        .len()
        .checked_sub(rest.len() + 2)
        .and_then(|pos| slice.get(pos).copied())
}

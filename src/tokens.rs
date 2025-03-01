/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs LLC <hello@stalw.art>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

const fn str_to_array<const N: usize>(s: &str) -> [u8; N] {
    let s = s.as_bytes();
    let mut arr = [0; N];
    let mut i = 0;
    while i < s.len() {
        arr[i] = s[i];
        i += 1;
    }
    arr
}

pub(crate) const fn token64(s: &str) -> u64 {
    u64::from_le_bytes(str_to_array(s))
}

pub(crate) const fn token128(s: &str) -> u128 {
    u128::from_le_bytes(str_to_array(s))
}

macro_rules! first {
    ($head:expr$(, $tail:expr)*) => {
        $head
    };
}

macro_rules! define_tokens_64 {
    ($($a:ident $(= $b:expr)?,)*) => {
        $(pub(crate) const $a: u64 = $crate::tokens::token64($crate::tokens::first!($($b,)* stringify!($a)));)*
    };
}

macro_rules! define_tokens_128 {
    ($($a:ident $(= $b:expr)?,)*) => {
        $(pub(crate) const $a: u128 = $crate::tokens::token128($crate::tokens::first!($($b,)* stringify!($a)));)*
    };
}

pub(crate) use define_tokens_128;
pub(crate) use define_tokens_64;
pub(crate) use first;

pub mod parser;

// SMTP commands
pub(crate) const EHLO: u64 =
    (b'e' as u64) | (b'h' as u64) << 8 | (b'l' as u64) << 16 | (b'o' as u64) << 24;
pub(crate) const HELO: u64 =
    (b'h' as u64) | (b'e' as u64) << 8 | (b'l' as u64) << 16 | (b'o' as u64) << 24;
pub(crate) const LHLO: u64 =
    (b'l' as u64) | (b'h' as u64) << 8 | (b'l' as u64) << 16 | (b'o' as u64) << 24;
pub(crate) const MAIL: u64 =
    (b'm' as u64) | (b'a' as u64) << 8 | (b'i' as u64) << 16 | (b'l' as u64) << 24;
pub(crate) const RCPT: u64 =
    (b'r' as u64) | (b'c' as u64) << 8 | (b'p' as u64) << 16 | (b't' as u64) << 24;
pub(crate) const DATA: u64 =
    (b'd' as u64) | (b'a' as u64) << 8 | (b't' as u64) << 16 | (b'a' as u64) << 24;
pub(crate) const BDAT: u64 =
    (b'b' as u64) | (b'd' as u64) << 8 | (b'a' as u64) << 16 | (b't' as u64) << 24;
pub(crate) const RSET: u64 =
    (b'r' as u64) | (b's' as u64) << 8 | (b'e' as u64) << 16 | (b't' as u64) << 24;
pub(crate) const VRFY: u64 =
    (b'v' as u64) | (b'r' as u64) << 8 | (b'f' as u64) << 16 | (b'y' as u64) << 24;
pub(crate) const EXPN: u64 =
    (b'e' as u64) | (b'x' as u64) << 8 | (b'p' as u64) << 16 | (b'n' as u64) << 24;
pub(crate) const HELP: u64 =
    (b'h' as u64) | (b'e' as u64) << 8 | (b'l' as u64) << 16 | (b'p' as u64) << 24;
pub(crate) const NOOP: u64 =
    (b'n' as u64) | (b'o' as u64) << 8 | (b'o' as u64) << 16 | (b'p' as u64) << 24;
pub(crate) const QUIT: u64 =
    (b'q' as u64) | (b'u' as u64) << 8 | (b'i' as u64) << 16 | (b't' as u64) << 24;
pub(crate) const ETRN: u64 =
    (b'e' as u64) | (b't' as u64) << 8 | (b'r' as u64) << 16 | (b'n' as u64) << 24;
pub(crate) const ATRN: u64 =
    (b'a' as u64) | (b't' as u64) << 8 | (b'r' as u64) << 16 | (b'n' as u64) << 24;
pub(crate) const AUTH: u64 =
    (b'a' as u64) | (b'u' as u64) << 8 | (b't' as u64) << 16 | (b'h' as u64) << 24;
pub(crate) const BURL: u64 =
    (b'b' as u64) | (b'u' as u64) << 8 | (b'r' as u64) << 16 | (b'l' as u64) << 24;
pub(crate) const STARTTLS: u64 = (b's' as u64)
    | (b't' as u64) << 8
    | (b'a' as u64) << 16
    | (b'r' as u64) << 24
    | (b't' as u64) << 32
    | (b't' as u64) << 40
    | (b'l' as u64) << 48
    | (b's' as u64) << 56;

// Arguments
pub(crate) const FROM: u64 =
    (b'f' as u64) | (b'r' as u64) << 8 | (b'o' as u64) << 16 | (b'm' as u64) << 24;
pub(crate) const TO: u64 = (b't' as u64) | (b'o' as u64) << 8;
pub(crate) const LAST: u64 =
    (b'l' as u64) | (b'a' as u64) << 8 | (b's' as u64) << 16 | (b't' as u64) << 24;

// Parameters
pub(crate) const BODY: u128 =
    (b'b' as u128) | (b'o' as u128) << 8 | (b'd' as u128) << 16 | (b'y' as u128) << 24;
pub(crate) const SEVENBIT: u128 =
    (b'7' as u128) | (b'b' as u128) << 8 | (b'i' as u128) << 16 | (b't' as u128) << 24;
pub(crate) const EIGHBITMIME: u128 = (b'8' as u128)
    | (b'b' as u128) << 8
    | (b'i' as u128) << 16
    | (b't' as u128) << 24
    | (b'm' as u128) << 32
    | (b'i' as u128) << 40
    | (b'm' as u128) << 48
    | (b'e' as u128) << 56;
pub(crate) const BINARYMIME: u128 = (b'b' as u128)
    | (b'i' as u128) << 8
    | (b'n' as u128) << 16
    | (b'a' as u128) << 24
    | (b'r' as u128) << 32
    | (b'y' as u128) << 40
    | (b'm' as u128) << 48
    | (b'i' as u128) << 56
    | (b'm' as u128) << 64
    | (b'e' as u128) << 72;
pub(crate) const SIZE: u128 =
    (b's' as u128) | (b'i' as u128) << 8 | (b'z' as u128) << 16 | (b'e' as u128) << 24;
pub(crate) const TRANSID: u128 = (b't' as u128)
    | (b'r' as u128) << 8
    | (b'a' as u128) << 16
    | (b'n' as u128) << 24
    | (b's' as u128) << 32
    | (b'i' as u128) << 40
    | (b'd' as u128) << 48;
pub(crate) const BY: u128 = (b'b' as u128) | (b'y' as u128) << 8;

pub(crate) const N: u64 = b'n' as u64;
pub(crate) const NT: u64 = (b'n' as u64) | (b't' as u64) << 8;
pub(crate) const C: u64 = b'c' as u64;
pub(crate) const R: u64 = b'r' as u64;
pub(crate) const RT: u64 = (b'r' as u64) | (b't' as u64) << 8;

pub(crate) const NOTIFY: u128 = (b'n' as u128)
    | (b'o' as u128) << 8
    | (b't' as u128) << 16
    | (b'i' as u128) << 24
    | (b'f' as u128) << 32
    | (b'y' as u128) << 40;
pub(crate) const ORCPT: u128 = (b'o' as u128)
    | (b'r' as u128) << 8
    | (b'c' as u128) << 16
    | (b'p' as u128) << 24
    | (b't' as u128) << 32;
pub(crate) const RET: u128 = (b'r' as u128) | (b'e' as u128) << 8 | (b't' as u128) << 16;
pub(crate) const ENVID: u128 = (b'e' as u128)
    | (b'n' as u128) << 8
    | (b'v' as u128) << 16
    | (b'i' as u128) << 24
    | (b'd' as u128) << 32;
pub(crate) const NEVER: u128 = (b'n' as u128)
    | (b'e' as u128) << 8
    | (b'v' as u128) << 16
    | (b'e' as u128) << 24
    | (b'r' as u128) << 32;
pub(crate) const SUCCESS: u128 = (b's' as u128)
    | (b'u' as u128) << 8
    | (b'c' as u128) << 16
    | (b'c' as u128) << 24
    | (b'e' as u128) << 32
    | (b's' as u128) << 40
    | (b's' as u128) << 48;
pub(crate) const FAILURE: u128 = (b'f' as u128)
    | (b'a' as u128) << 8
    | (b'i' as u128) << 16
    | (b'l' as u128) << 24
    | (b'u' as u128) << 32
    | (b'r' as u128) << 40
    | (b'e' as u128) << 48;
pub(crate) const DELAY: u128 = (b'd' as u128)
    | (b'e' as u128) << 8
    | (b'l' as u128) << 16
    | (b'a' as u128) << 24
    | (b'y' as u128) << 32;
pub(crate) const FULL: u64 =
    (b'f' as u64) | (b'u' as u64) << 8 | (b'l' as u64) << 16 | (b'l' as u64) << 24;
pub(crate) const HDRS: u64 =
    (b'h' as u64) | (b'd' as u64) << 8 | (b'r' as u64) << 16 | (b's' as u64) << 24;
pub(crate) const SOLICIT: u128 = (b's' as u128)
    | (b'o' as u128) << 8
    | (b'l' as u128) << 16
    | (b'i' as u128) << 24
    | (b'c' as u128) << 32
    | (b'i' as u128) << 40
    | (b't' as u128) << 48;
pub(crate) const MTRK: u128 =
    (b'm' as u128) | (b't' as u128) << 8 | (b'r' as u128) << 16 | (b'k' as u128) << 24;
pub(crate) const AUTH_: u128 =
    (b'a' as u128) | (b'u' as u128) << 8 | (b't' as u128) << 16 | (b'h' as u128) << 24;
pub(crate) const HOLDFOR: u128 = (b'h' as u128)
    | (b'o' as u128) << 8
    | (b'l' as u128) << 16
    | (b'd' as u128) << 24
    | (b'f' as u128) << 32
    | (b'o' as u128) << 40
    | (b'r' as u128) << 48;
pub(crate) const HOLDUNTIL: u128 = (b'h' as u128)
    | (b'o' as u128) << 8
    | (b'l' as u128) << 16
    | (b'd' as u128) << 24
    | (b'u' as u128) << 32
    | (b'n' as u128) << 40
    | (b't' as u128) << 48
    | (b'i' as u128) << 56
    | (b'l' as u128) << 64;
pub(crate) const SMTPUTF8: u128 = (b's' as u128)
    | (b'm' as u128) << 8
    | (b't' as u128) << 16
    | (b'p' as u128) << 24
    | (b'u' as u128) << 32
    | (b't' as u128) << 40
    | (b'f' as u128) << 48
    | (b'8' as u128) << 56;
pub(crate) const CONPERM: u128 = (b'c' as u128)
    | (b'o' as u128) << 8
    | (b'n' as u128) << 16
    | (b'p' as u128) << 24
    | (b'e' as u128) << 32
    | (b'r' as u128) << 40
    | (b'm' as u128) << 48;
pub(crate) const CONNEG: u128 = (b'c' as u128)
    | (b'o' as u128) << 8
    | (b'n' as u128) << 16
    | (b'n' as u128) << 24
    | (b'e' as u128) << 32
    | (b'g' as u128) << 40;
pub(crate) const MT_PRIORITY: u128 = (b'm' as u128)
    | (b't' as u128) << 8
    | (b'-' as u128) << 16
    | (b'p' as u128) << 24
    | (b'r' as u128) << 32
    | (b'i' as u128) << 40
    | (b'o' as u128) << 48
    | (b'r' as u128) << 56
    | (b'i' as u128) << 64
    | (b't' as u128) << 72
    | (b'y' as u128) << 80;
pub(crate) const RRVS: u128 =
    (b'r' as u128) | (b'r' as u128) << 8 | (b'v' as u128) << 16 | (b's' as u128) << 24;
pub(crate) const REQUIRETLS: u128 = (b'r' as u128)
    | (b'e' as u128) << 8
    | (b'q' as u128) << 16
    | (b'u' as u128) << 24
    | (b'i' as u128) << 32
    | (b'r' as u128) << 40
    | (b'e' as u128) << 48
    | (b't' as u128) << 56
    | (b'l' as u128) << 64
    | (b's' as u128) << 72;

// SASL Mechanisms
pub(crate) const _9798_M_DSA_SHA1: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'm' as u128) << 40
    | (b'-' as u128) << 48
    | (b'd' as u128) << 56
    | (b's' as u128) << 64
    | (b'a' as u128) << 72
    | (b'-' as u128) << 80
    | (b's' as u128) << 88
    | (b'h' as u128) << 96
    | (b'a' as u128) << 104
    | (b'1' as u128) << 112;
pub(crate) const _9798_M_ECDSA_SHA: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'm' as u128) << 40
    | (b'-' as u128) << 48
    | (b'e' as u128) << 56
    | (b'c' as u128) << 64
    | (b'd' as u128) << 72
    | (b's' as u128) << 80
    | (b'a' as u128) << 88
    | (b'-' as u128) << 96
    | (b's' as u128) << 104
    | (b'h' as u128) << 112
    | (b'a' as u128) << 120;
pub(crate) const _9798_M_RSA_SHA1_: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'm' as u128) << 40
    | (b'-' as u128) << 48
    | (b'r' as u128) << 56
    | (b's' as u128) << 64
    | (b'a' as u128) << 72
    | (b'-' as u128) << 80
    | (b's' as u128) << 88
    | (b'h' as u128) << 96
    | (b'a' as u128) << 104
    | (b'1' as u128) << 112
    | (b'-' as u128) << 120;
pub(crate) const _9798_U_DSA_SHA1: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'u' as u128) << 40
    | (b'-' as u128) << 48
    | (b'd' as u128) << 56
    | (b's' as u128) << 64
    | (b'a' as u128) << 72
    | (b'-' as u128) << 80
    | (b's' as u128) << 88
    | (b'h' as u128) << 96
    | (b'a' as u128) << 104
    | (b'1' as u128) << 112;
pub(crate) const _9798_U_ECDSA_SHA: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'u' as u128) << 40
    | (b'-' as u128) << 48
    | (b'e' as u128) << 56
    | (b'c' as u128) << 64
    | (b'd' as u128) << 72
    | (b's' as u128) << 80
    | (b'a' as u128) << 88
    | (b'-' as u128) << 96
    | (b's' as u128) << 104
    | (b'h' as u128) << 112
    | (b'a' as u128) << 120;
pub(crate) const _9798_U_RSA_SHA1_: u128 = (b'9' as u128)
    | (b'7' as u128) << 8
    | (b'9' as u128) << 16
    | (b'8' as u128) << 24
    | (b'-' as u128) << 32
    | (b'u' as u128) << 40
    | (b'-' as u128) << 48
    | (b'r' as u128) << 56
    | (b's' as u128) << 64
    | (b'a' as u128) << 72
    | (b'-' as u128) << 80
    | (b's' as u128) << 88
    | (b'h' as u128) << 96
    | (b'a' as u128) << 104
    | (b'1' as u128) << 112
    | (b'-' as u128) << 120;
pub(crate) const ANONYMOUS: u128 = (b'a' as u128)
    | (b'n' as u128) << 8
    | (b'o' as u128) << 16
    | (b'n' as u128) << 24
    | (b'y' as u128) << 32
    | (b'm' as u128) << 40
    | (b'o' as u128) << 48
    | (b'u' as u128) << 56
    | (b's' as u128) << 64;
pub(crate) const CRAM_MD5: u128 = (b'c' as u128)
    | (b'r' as u128) << 8
    | (b'a' as u128) << 16
    | (b'm' as u128) << 24
    | (b'-' as u128) << 32
    | (b'm' as u128) << 40
    | (b'd' as u128) << 48
    | (b'5' as u128) << 56;
pub(crate) const DIGEST_MD5: u128 = (b'd' as u128)
    | (b'i' as u128) << 8
    | (b'g' as u128) << 16
    | (b'e' as u128) << 24
    | (b's' as u128) << 32
    | (b't' as u128) << 40
    | (b'-' as u128) << 48
    | (b'm' as u128) << 56
    | (b'd' as u128) << 64
    | (b'5' as u128) << 72;
pub(crate) const EAP_AES128: u128 = (b'e' as u128)
    | (b'a' as u128) << 8
    | (b'p' as u128) << 16
    | (b'-' as u128) << 24
    | (b'a' as u128) << 32
    | (b'e' as u128) << 40
    | (b's' as u128) << 48
    | (b'1' as u128) << 56
    | (b'2' as u128) << 64
    | (b'8' as u128) << 72;
pub(crate) const EAP_AES128_PLUS: u128 = (b'e' as u128)
    | (b'a' as u128) << 8
    | (b'p' as u128) << 16
    | (b'-' as u128) << 24
    | (b'a' as u128) << 32
    | (b'e' as u128) << 40
    | (b's' as u128) << 48
    | (b'1' as u128) << 56
    | (b'2' as u128) << 64
    | (b'8' as u128) << 72
    | (b'-' as u128) << 80
    | (b'p' as u128) << 88
    | (b'l' as u128) << 96
    | (b'u' as u128) << 104
    | (b's' as u128) << 112;
pub(crate) const ECDH_X25519_CHAL: u128 = (b'e' as u128)
    | (b'c' as u128) << 8
    | (b'd' as u128) << 16
    | (b'h' as u128) << 24
    | (b'-' as u128) << 32
    | (b'x' as u128) << 40
    | (b'2' as u128) << 48
    | (b'5' as u128) << 56
    | (b'5' as u128) << 64
    | (b'1' as u128) << 72
    | (b'9' as u128) << 80
    | (b'-' as u128) << 88
    | (b'c' as u128) << 96
    | (b'h' as u128) << 104
    | (b'a' as u128) << 112
    | (b'l' as u128) << 120;
pub(crate) const ECDSA_NIST256P_C: u128 = (b'e' as u128)
    | (b'c' as u128) << 8
    | (b'd' as u128) << 16
    | (b's' as u128) << 24
    | (b'a' as u128) << 32
    | (b'-' as u128) << 40
    | (b'n' as u128) << 48
    | (b'i' as u128) << 56
    | (b's' as u128) << 64
    | (b't' as u128) << 72
    | (b'2' as u128) << 80
    | (b'5' as u128) << 88
    | (b'6' as u128) << 96
    | (b'p' as u128) << 104
    | (b'-' as u128) << 112
    | (b'c' as u128) << 120;
pub(crate) const EXTERNAL: u128 = (b'e' as u128)
    | (b'x' as u128) << 8
    | (b't' as u128) << 16
    | (b'e' as u128) << 24
    | (b'r' as u128) << 32
    | (b'n' as u128) << 40
    | (b'a' as u128) << 48
    | (b'l' as u128) << 56;
pub(crate) const GS2_KRB5: u128 = (b'g' as u128)
    | (b's' as u128) << 8
    | (b'2' as u128) << 16
    | (b'-' as u128) << 24
    | (b'k' as u128) << 32
    | (b'r' as u128) << 40
    | (b'b' as u128) << 48
    | (b'5' as u128) << 56;
pub(crate) const GS2_KRB5_PLUS: u128 = (b'g' as u128)
    | (b's' as u128) << 8
    | (b'2' as u128) << 16
    | (b'-' as u128) << 24
    | (b'k' as u128) << 32
    | (b'r' as u128) << 40
    | (b'b' as u128) << 48
    | (b'5' as u128) << 56
    | (b'-' as u128) << 64
    | (b'p' as u128) << 72
    | (b'l' as u128) << 80
    | (b'u' as u128) << 88
    | (b's' as u128) << 96;
pub(crate) const GSS_SPNEGO: u128 = (b'g' as u128)
    | (b's' as u128) << 8
    | (b's' as u128) << 16
    | (b'-' as u128) << 24
    | (b's' as u128) << 32
    | (b'p' as u128) << 40
    | (b'n' as u128) << 48
    | (b'e' as u128) << 56
    | (b'g' as u128) << 64
    | (b'o' as u128) << 72;
pub(crate) const GSSAPI: u128 = (b'g' as u128)
    | (b's' as u128) << 8
    | (b's' as u128) << 16
    | (b'a' as u128) << 24
    | (b'p' as u128) << 32
    | (b'i' as u128) << 40;
pub(crate) const KERBEROS_V4: u128 = (b'k' as u128)
    | (b'e' as u128) << 8
    | (b'r' as u128) << 16
    | (b'b' as u128) << 24
    | (b'e' as u128) << 32
    | (b'r' as u128) << 40
    | (b'o' as u128) << 48
    | (b's' as u128) << 56
    | (b'_' as u128) << 64
    | (b'v' as u128) << 72
    | (b'4' as u128) << 80;
pub(crate) const KERBEROS_V5: u128 = (b'k' as u128)
    | (b'e' as u128) << 8
    | (b'r' as u128) << 16
    | (b'b' as u128) << 24
    | (b'e' as u128) << 32
    | (b'r' as u128) << 40
    | (b'o' as u128) << 48
    | (b's' as u128) << 56
    | (b'_' as u128) << 64
    | (b'v' as u128) << 72
    | (b'5' as u128) << 80;
pub(crate) const LOGIN: u128 = (b'l' as u128)
    | (b'o' as u128) << 8
    | (b'g' as u128) << 16
    | (b'i' as u128) << 24
    | (b'n' as u128) << 32;
pub(crate) const NMAS_SAMBA_AUTH: u128 = (b'n' as u128)
    | (b'm' as u128) << 8
    | (b'a' as u128) << 16
    | (b's' as u128) << 24
    | (b'-' as u128) << 32
    | (b's' as u128) << 40
    | (b'a' as u128) << 48
    | (b'm' as u128) << 56
    | (b'b' as u128) << 64
    | (b'a' as u128) << 72
    | (b'-' as u128) << 80
    | (b'a' as u128) << 88
    | (b'u' as u128) << 96
    | (b't' as u128) << 104
    | (b'h' as u128) << 112;
pub(crate) const NMAS_AUTHEN: u128 = (b'n' as u128)
    | (b'm' as u128) << 8
    | (b'a' as u128) << 16
    | (b's' as u128) << 24
    | (b'_' as u128) << 32
    | (b'a' as u128) << 40
    | (b'u' as u128) << 48
    | (b't' as u128) << 56
    | (b'h' as u128) << 64
    | (b'e' as u128) << 72
    | (b'n' as u128) << 80;
pub(crate) const NMAS_LOGIN: u128 = (b'n' as u128)
    | (b'm' as u128) << 8
    | (b'a' as u128) << 16
    | (b's' as u128) << 24
    | (b'_' as u128) << 32
    | (b'l' as u128) << 40
    | (b'o' as u128) << 48
    | (b'g' as u128) << 56
    | (b'i' as u128) << 64
    | (b'n' as u128) << 72;
pub(crate) const NTLM: u128 =
    (b'n' as u128) | (b't' as u128) << 8 | (b'l' as u128) << 16 | (b'm' as u128) << 24;
pub(crate) const OAUTH10A: u128 = (b'o' as u128)
    | (b'a' as u128) << 8
    | (b'u' as u128) << 16
    | (b't' as u128) << 24
    | (b'h' as u128) << 32
    | (b'1' as u128) << 40
    | (b'0' as u128) << 48
    | (b'a' as u128) << 56;
pub(crate) const OAUTHBEARER: u128 = (b'o' as u128)
    | (b'a' as u128) << 8
    | (b'u' as u128) << 16
    | (b't' as u128) << 24
    | (b'h' as u128) << 32
    | (b'b' as u128) << 40
    | (b'e' as u128) << 48
    | (b'a' as u128) << 56
    | (b'r' as u128) << 64
    | (b'e' as u128) << 72
    | (b'r' as u128) << 80;
pub(crate) const OPENID20: u128 = (b'o' as u128)
    | (b'p' as u128) << 8
    | (b'e' as u128) << 16
    | (b'n' as u128) << 24
    | (b'i' as u128) << 32
    | (b'd' as u128) << 40
    | (b'2' as u128) << 48
    | (b'0' as u128) << 56;
pub(crate) const OTP: u128 = (b'o' as u128) | (b't' as u128) << 8 | (b'p' as u128) << 16;
pub(crate) const PLAIN: u128 = (b'p' as u128)
    | (b'l' as u128) << 8
    | (b'a' as u128) << 16
    | (b'i' as u128) << 24
    | (b'n' as u128) << 32;
pub(crate) const SAML20: u128 = (b's' as u128)
    | (b'a' as u128) << 8
    | (b'm' as u128) << 16
    | (b'l' as u128) << 24
    | (b'2' as u128) << 32
    | (b'0' as u128) << 40;
pub(crate) const SCRAM_SHA_1: u128 = (b's' as u128)
    | (b'c' as u128) << 8
    | (b'r' as u128) << 16
    | (b'a' as u128) << 24
    | (b'm' as u128) << 32
    | (b'-' as u128) << 40
    | (b's' as u128) << 48
    | (b'h' as u128) << 56
    | (b'a' as u128) << 64
    | (b'-' as u128) << 72
    | (b'1' as u128) << 80;
pub(crate) const SCRAM_SHA_1_PLUS: u128 = (b's' as u128)
    | (b'c' as u128) << 8
    | (b'r' as u128) << 16
    | (b'a' as u128) << 24
    | (b'm' as u128) << 32
    | (b'-' as u128) << 40
    | (b's' as u128) << 48
    | (b'h' as u128) << 56
    | (b'a' as u128) << 64
    | (b'-' as u128) << 72
    | (b'1' as u128) << 80
    | (b'-' as u128) << 88
    | (b'p' as u128) << 96
    | (b'l' as u128) << 104
    | (b'u' as u128) << 112
    | (b's' as u128) << 120;
pub(crate) const SCRAM_SHA_256: u128 = (b's' as u128)
    | (b'c' as u128) << 8
    | (b'r' as u128) << 16
    | (b'a' as u128) << 24
    | (b'm' as u128) << 32
    | (b'-' as u128) << 40
    | (b's' as u128) << 48
    | (b'h' as u128) << 56
    | (b'a' as u128) << 64
    | (b'-' as u128) << 72
    | (b'2' as u128) << 80
    | (b'5' as u128) << 88
    | (b'6' as u128) << 96;
pub(crate) const SCRAM_SHA_256_PL: u128 = (b's' as u128)
    | (b'c' as u128) << 8
    | (b'r' as u128) << 16
    | (b'a' as u128) << 24
    | (b'm' as u128) << 32
    | (b'-' as u128) << 40
    | (b's' as u128) << 48
    | (b'h' as u128) << 56
    | (b'a' as u128) << 64
    | (b'-' as u128) << 72
    | (b'2' as u128) << 80
    | (b'5' as u128) << 88
    | (b'6' as u128) << 96
    | (b'-' as u128) << 104
    | (b'p' as u128) << 112
    | (b'l' as u128) << 120;
pub(crate) const SECURID: u128 = (b's' as u128)
    | (b'e' as u128) << 8
    | (b'c' as u128) << 16
    | (b'u' as u128) << 24
    | (b'r' as u128) << 32
    | (b'i' as u128) << 40
    | (b'd' as u128) << 48;
pub(crate) const SKEY: u128 =
    (b's' as u128) | (b'k' as u128) << 8 | (b'e' as u128) << 16 | (b'y' as u128) << 24;
pub(crate) const SPNEGO: u128 = (b's' as u128)
    | (b'p' as u128) << 8
    | (b'n' as u128) << 16
    | (b'e' as u128) << 24
    | (b'g' as u128) << 32
    | (b'o' as u128) << 40;
pub(crate) const SPNEGO_PLUS: u128 = (b's' as u128)
    | (b'p' as u128) << 8
    | (b'n' as u128) << 16
    | (b'e' as u128) << 24
    | (b'g' as u128) << 32
    | (b'o' as u128) << 40
    | (b'-' as u128) << 48
    | (b'p' as u128) << 56
    | (b'l' as u128) << 64
    | (b'u' as u128) << 72
    | (b's' as u128) << 80;
pub(crate) const SXOVER_PLUS: u128 = (b's' as u128)
    | (b'x' as u128) << 8
    | (b'o' as u128) << 16
    | (b'v' as u128) << 24
    | (b'e' as u128) << 32
    | (b'r' as u128) << 40
    | (b'-' as u128) << 48
    | (b'p' as u128) << 56
    | (b'l' as u128) << 64
    | (b'u' as u128) << 72
    | (b's' as u128) << 80;
pub(crate) const XOAUTH: u128 = (b'x' as u128)
    | (b'o' as u128) << 8
    | (b'a' as u128) << 16
    | (b'u' as u128) << 24
    | (b't' as u128) << 32
    | (b'h' as u128) << 40;
pub(crate) const XOAUTH2: u128 = (b'x' as u128)
    | (b'o' as u128) << 8
    | (b'a' as u128) << 16
    | (b'u' as u128) << 24
    | (b't' as u128) << 32
    | (b'h' as u128) << 40
    | (b'2' as u128) << 48;

/*
 * Adapted from Daniel Lemire's source:
 * https://github.com/lemire/Code-used-on-Daniel-Lemire-s-blog/blob/master/2019/04/17/hexparse.cpp
 *
 */

pub(crate) static HEX_MAP: &[i8] = &[
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1, -1, 10, 11, 12, 13, 14, 15, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 10,
    11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

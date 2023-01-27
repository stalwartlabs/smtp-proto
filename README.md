# smtp-proto

[![crates.io](https://img.shields.io/crates/v/smtp-proto)](https://crates.io/crates/smtp-proto)
[![build](https://github.com/stalwartlabs/sieve/actions/workflows/rust.yml/badge.svg)](https://github.com/stalwartlabs/sieve/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/smtp-proto)](https://docs.rs/smtp-proto)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

_smtp-proto_ is a fast SMTP/LMTP parser for Rust that supports all [registered SMTP service extensions](https://www.iana.org/assignments/mail-parameters/mail-parameters.xhtml).
The library is part of Stalwart SMTP and LMTP servers. It is not yet documented so if you need help using the library please start a discussion.


## Testing & Fuzzing

To run the testsuite:

```bash
 $ cargo test
```

To fuzz the library with `cargo-fuzz`:

```bash
 $ cargo +nightly fuzz run smtp_proto
```

## License

Licensed under the terms of the [GNU Affero General Public License](https://www.gnu.org/licenses/agpl-3.0.en.html) as published by
the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
See [LICENSE](LICENSE) for more details.

You can be released from the requirements of the AGPLv3 license by purchasing
a commercial license. Please contact licensing@stalw.art for more details.
  
## Copyright

Copyright (C) 2020-2023, Stalwart Labs Ltd.

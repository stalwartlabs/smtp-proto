# smtp-proto

[![crates.io](https://img.shields.io/crates/v/smtp-proto)](https://crates.io/crates/smtp-proto)
[![build](https://github.com/stalwartlabs/sieve/actions/workflows/rust.yml/badge.svg)](https://github.com/stalwartlabs/sieve/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/smtp-proto)](https://docs.rs/smtp-proto)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![License: Apache](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

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

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
  
## Copyright

Copyright (C) 2020, Stalwart Labs LLC


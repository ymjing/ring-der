// Copyright 2021 Yiming Jing.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! *ring-der*
//! ==========
//!
//! This library providers an extended version of the DER parser in
//! [ring::io::der](https://github.com/briansmith/ring/blob/main/src/io/der.rs).
//!
//! What's added:
//!
//! * All tag types as defined in X.680 section 8.4;
//! * High tag number, for tag numbers 31 and greater;
//! * Error handling with [thiserror](https://crates.io/crates/thiserror).
//!
//! ### Example
//!
//! ```rust
//! use ring_der::der::parse_boolean;
//! use ring_der::Error;
//!
//! let input = untrusted::Input::from(&[0x01, 0x01, 0xff]);
//! let result = input.read_all(Error::IncompleteRead, |r| parse_boolean(r));
//! assert_eq!(result, Ok(true));
//! ```

pub mod der;
pub mod error;

pub use der::expect_tag_and_get_value;
pub use der::nested;
pub use der::read_tag_and_get_value;
pub use der::Tag;
pub use error::Error;

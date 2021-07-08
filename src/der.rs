// Copyright 2015 Brian Smith.
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

//! Building blocks for parsing DER-encoded ASN.1 structures.
//!
//! This module contains the foundational parts of an ASN.1 DER parser.
//! Derived from ring::io::der

use crate::error::Error;
use untrusted::{Input, Reader};

pub const CONSTRUCTED: u8 = 1 << 5;
pub const CONTEXT_SPECIFIC: u8 = 2 << 6;

/// Tag types as defined in X.680 section 8.4;
#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
#[allow(unused)]
pub enum Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    Oid = 0x06,
    ObjDescriptor = 0x07,
    External = 0x08,
    RealType = 0x09,
    Enumerated = 0x0a,
    EmbeddedPdv = 0xb,
    Utf8String = 0xc,
    RelativeOid = 0xd,

    Sequence = 0x10,
    Set = 0x11,
    NumericString = 0x12,
    PrintableString = 0x13,
    T61String = 0x14,
    VideotexString = 0x15,
    Ia5String = 0x16,
    UTCTime = 0x17,
    GeneralizedTime = 0x18,
    GraphicString = 0x19,
    VisibleString = 0x1a,
    GeneralString = 0x1b,
    UniversalString = 0x1c,
    BmpString = 0x1e,

    ContextSpecificConstructed0 = CONTEXT_SPECIFIC | CONSTRUCTED,
    ContextSpecificConstructed1 = CONTEXT_SPECIFIC | CONSTRUCTED | 1,
    ContextSpecificConstructed3 = CONTEXT_SPECIFIC | CONSTRUCTED | 3,

    Invalid = 0xff,
}

impl From<Tag> for usize {
    fn from(tag: Tag) -> Self {
        tag as Self
    }
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> Self {
        tag as Self
    } // XXX: narrowing conversion.
}

/// Reads the value after a given tag; returns an UnexpectedTag error is tag mismatches.
pub fn expect_tag_and_get_value<'a>(r: &mut Reader<'a>, tag: Tag) -> Result<Input<'a>, Error> {
    let (actual_tag, inner) = read_tag_and_get_value(r)?;
    if usize::from(tag) != actual_tag {
        return Err(Error::UnexpectedTag);
    }
    Ok(inner)
}

/// Reads the tag and the subsequent value.
pub fn read_tag_and_get_value<'a>(r: &mut Reader<'a>) -> Result<(usize, Input<'a>), Error> {
    let tag = read_tag_number(r)?;
    let length = parse_length(r)?;
    let inner = r.read_bytes(length)?;
    Ok((tag, inner))
}

fn read_tag_number(r: &mut Reader) -> Result<usize, Error> {
    let mut octet = r.read_byte()?;
    if octet & 0x1F != 0x1F {
        // low-tag-number form
        Ok((octet & 0x1F) as usize)
    } else {
        // high-tag-number form
        let mut tag_number = 0;
        loop {
            octet = r.read_byte()?;
            tag_number = (tag_number << 7) | (usize::from(octet) & 0x7f);
            if octet & 0x80 == 0 {
                break;
            }
        }
        Ok(tag_number)
    }
}

fn parse_length(r: &mut Reader) -> Result<usize, Error> {
    let length = match r.read_byte()? {
        n if (n & 0x80) == 0 => usize::from(n),
        0x81 => {
            let second_byte = r.read_byte()?;
            if second_byte < 128 {
                return Err(Error::BadEncoding); // Not the canonical encoding.
            }
            usize::from(second_byte)
        }
        0x82 => {
            let second_byte = usize::from(r.read_byte()?);
            let third_byte = usize::from(r.read_byte()?);
            let combined = (second_byte << 8) | third_byte;
            if combined < 256 {
                return Err(Error::BadEncoding); // Not the canonical encoding.
            }
            combined
        }
        _ => {
            return Err(Error::BadEncoding); // We don't support longer lengths.
        }
    };
    Ok(length)
}

/// Reads nested tags, such as SEQUENCE and SET.
pub fn nested<'a, F, R, E: Copy>(r: &mut Reader<'a>, tag: Tag, error: E, decoder: F) -> Result<R, E>
where
    F: FnOnce(&mut Reader<'a>) -> Result<R, E>,
{
    let inner = expect_tag_and_get_value(r, tag).map_err(|_| error)?;
    inner.read_all(error, decoder)
}

fn nonnegative_integer_bytes<'a>(r: &mut Reader<'a>) -> Result<Input<'a>, Error> {
    let value = expect_tag_and_get_value(r, Tag::Integer)?;
    match value
        .as_slice_less_safe()
        .split_first()
        .ok_or(Error::BadEncoding)?
    {
        (0, rest) => match rest.first() {
            None => Ok(value),
            Some(&second) if second & 0x80 == 0x80 => Ok(Input::from(rest)),
            _ => Err(Error::BadEncoding),
        },
        (first, _) if first & 0x80 == 0 => Ok(value),
        (_, _) => Err(Error::BadEncoding), // Negative value, unsupported
    }
}

/// Reads a small and non-negative integer.
#[inline]
pub fn parse_u8(r: &mut Reader) -> Result<u8, Error> {
    let octets = nonnegative_integer_bytes(r)?;
    match *octets.as_slice_less_safe() {
        [b] => Ok(b),
        _ => Err(Error::BadEncoding),
    }
}

/// Reads a large and non-negative integer. Note that the return value is bytes.
#[inline]
pub fn parse_non_negative_integer_as_bytes<'a>(r: &mut Reader<'a>) -> Result<&'a [u8], Error> {
    nonnegative_integer_bytes(r).map(|octets| octets.as_slice_less_safe())
}

/// Read a null value
#[inline]
pub fn parse_null(r: &mut Reader) -> Result<(), Error> {
    let _ = expect_tag_and_get_value(r, Tag::Null)?;
    Ok(())
}

/// Read a boolean value
///
/// The encoding of a boolean value shall be primitive. The contents octets shall consist of a
/// single octet.
///
/// If the boolean value is FALSE, the octet shall be zero.
/// If the boolean value is TRUE, the octet shall be one byte, and have all bits set to one (0xff).
#[inline]
pub fn parse_boolean(r: &mut Reader) -> Result<bool, Error> {
    let octets = expect_tag_and_get_value(r, Tag::Boolean)?;
    // b/119541233: Decode a non-zero byte as True for Google Pixel 3 and XL Key Attestation
    octets.read_all(Error::IncompleteRead, |x| Ok(x.read_byte()? != 0))
}

#[cfg(test)]
mod tests {
    use crate::der::{parse_boolean, parse_non_negative_integer_as_bytes, parse_null, parse_u8};
    use crate::error::Error;

    fn with_i<'a, F, R>(value: &'a [u8], f: F) -> Result<R, Error>
    where
        F: FnOnce(&mut untrusted::Reader<'a>) -> Result<R, Error>,
    {
        untrusted::Input::from(value).read_all(Error::IncompleteRead, f)
    }

    static ZERO_INTEGER: &'static [u8] = &[0x02, 0x01, 0x00];

    static GOOD_POSITIVE_INTEGERS_SMALL: &'static [(&'static [u8], u8)] = &[
        (&[0x02, 0x01, 0x01], 0x01),
        (&[0x02, 0x01, 0x02], 0x02),
        (&[0x02, 0x01, 0x7e], 0x7e),
        (&[0x02, 0x01, 0x7f], 0x7f),
        // Values that need to have an 0x00 prefix to disambiguate them from
        // them from negative values.
        (&[0x02, 0x02, 0x00, 0x80], 0x80),
        (&[0x02, 0x02, 0x00, 0x81], 0x81),
        (&[0x02, 0x02, 0x00, 0xfe], 0xfe),
        (&[0x02, 0x02, 0x00, 0xff], 0xff),
    ];

    static GOOD_POSITIVE_INTEGERS_LARGE: &[(&[u8], &[u8])] = &[
        (&[0x02, 0x02, 0x01, 0x00], &[0x01, 0x00]),
        (&[0x02, 0x02, 0x02, 0x01], &[0x02, 0x01]),
        (&[0x02, 0x02, 0x7e, 0xfe], &[0x7e, 0xfe]),
        (&[0x02, 0x02, 0x7f, 0xff], &[0x7f, 0xff]),
        // Values that need to have an 0x00 prefix to disambiguate them from
        // them from negative values.
        (&[0x02, 0x03, 0x00, 0x80, 0x00], &[0x80, 0x00]),
        (&[0x02, 0x03, 0x00, 0x81, 0x01], &[0x81, 0x01]),
        (&[0x02, 0x03, 0x00, 0xfe, 0xfe], &[0xfe, 0xfe]),
        (&[0x02, 0x03, 0x00, 0xff, 0xff], &[0xff, 0xff]),
    ];

    static BAD_NONNEGATIVE_INTEGERS: &'static [&'static [u8]] = &[
        &[],           // At end of r
        &[0x02],       // Tag only
        &[0x02, 0x00], // Empty value
        // Length mismatch
        &[0x02, 0x00, 0x01],
        &[0x02, 0x01],
        &[0x02, 0x01, 0x00, 0x01],
        &[0x02, 0x01, 0x01, 0x00], // Would be valid if last byte is ignored.
        &[0x02, 0x02, 0x01],
        // Negative values
        &[0x02, 0x01, 0x80],
        &[0x02, 0x01, 0xfe],
        &[0x02, 0x01, 0xff],
        // Values that have an unnecessary leading 0x00
        &[0x02, 0x02, 0x00, 0x00],
        &[0x02, 0x02, 0x00, 0x01],
        &[0x02, 0x02, 0x00, 0x02],
        &[0x02, 0x02, 0x00, 0x7e],
        &[0x02, 0x02, 0x00, 0x7f],
    ];

    static GOOD_BOOLEANS: &'static [(&'static [u8], bool)] = &[
        (&[0x01, 0x01, 0x00], false),
        (&[0x01, 0x01, 0xff], true),
        (&[0x01, 0x01, 0x01], true),
    ];

    #[test]
    fn test_small_integers() {
        let zero = (ZERO_INTEGER, 0x00);
        for &(test_in, test_out) in
            core::iter::once(&zero).chain(GOOD_POSITIVE_INTEGERS_SMALL.iter())
        {
            let result = with_i(test_in, |r| {
                assert_eq!(parse_u8(r)?, test_out);
                Ok(())
            });
            assert_eq!(result, Ok(()));
        }
        for &test_in in BAD_NONNEGATIVE_INTEGERS
            .iter()
            .chain(GOOD_POSITIVE_INTEGERS_LARGE.iter().map(|(r, _)| r))
        {
            let result = with_i(test_in, parse_u8);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_large_integers() {
        for (test_in, test_out) in GOOD_POSITIVE_INTEGERS_SMALL
            .iter()
            .map(|(test_in, test_out)| (*test_in, core::slice::from_ref(test_out)))
            .chain(GOOD_POSITIVE_INTEGERS_LARGE.iter().copied())
        {
            let result = with_i(test_in, |r| {
                assert_eq!(parse_non_negative_integer_as_bytes(r)?, &test_out[..],);
                Ok(())
            });
            assert_eq!(result, Ok(()))
        }

        for &test_in in BAD_NONNEGATIVE_INTEGERS.iter() {
            let result = with_i(test_in, parse_non_negative_integer_as_bytes);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_parse_boolean() {
        for &(test_in, test_out) in GOOD_BOOLEANS.iter() {
            let result = with_i(test_in, |r| {
                assert_eq!(parse_boolean(r)?, test_out);
                Ok(())
            });
            assert_eq!(result, Ok(()))
        }
    }

    #[test]
    fn test_parse_null() {
        let result = with_i(&[0x05, 0x00], |r| {
            assert_eq!(parse_null(r)?, ());
            Ok(())
        });
        assert_eq!(result, Ok(()))
    }
}

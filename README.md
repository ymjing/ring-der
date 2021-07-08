ring-der
==========

This crate providers an extended version of the DER parser in
[ring::io::der](https://github.com/briansmith/ring/blob/main/src/io/der.rs).

What's extended:

* All tag types as defined in X.680 section 8.4;
* High tag number, for tag numbers 31 and greater;
* Error handling with [thiserror](https://crates.io/crates/thiserror).

### Example

```rust
use ring_der::der::parse_boolean;
use ring_der::Error;

let input = untrusted::Input::from(&[0x01, 0x01, 0xff]);
let result = input.read_all(Error::IncompleteRead, |r| parse_boolean(r));
assert_eq!(result, Ok(true));
```

### License
See [LICENSE](LICENSE).
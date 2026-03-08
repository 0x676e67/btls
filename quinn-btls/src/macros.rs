macro_rules! bounded_array {
    {$(
        $(#[$struct_docs:meta])*
        $vis:vis struct $struct_name:ident($max_len:ident)
    ),*} => {
    $(
        $(#[$struct_docs])*
        #[derive(Copy, Clone, Eq, PartialEq)]
        $vis struct $struct_name {
            buf: [u8; Self::MAX_LEN],
            len: u8,
        }

        #[allow(dead_code)]
        impl $struct_name {
            /// Maximum value allowed.
            $vis const MAX_LEN: usize = $max_len;

            /// Creates a new instance, taking ownership of the buffer.
            #[inline]
            $vis fn new(buf: [u8; Self::MAX_LEN], len: usize) -> Self {
                Self { buf, len: len as _ }
            }

            /// Creates a new instance with an empty buffer of the given size.
            #[inline]
            $vis fn with_len(len: usize) -> Self {
                Self::new([0u8; Self::MAX_LEN], len)
            }

            /// Creates a new instance, copying the buffer.
            #[inline]
            $vis fn from(input: &[u8]) -> Self {
                assert!(input.len() <= Self::MAX_LEN);
                let mut buf = [0u8; Self::MAX_LEN];
                let len = input.len();
                buf[..len].copy_from_slice(input);

                Self::new(buf, len)
            }

            /// Creates a new instance with random contents.
            #[inline]
            $vis fn random() -> Self {
                use rand::Rng;

                let mut buf = [0u8; Self::MAX_LEN];
                rand::rng().fill_bytes(&mut buf);
                Self::new(buf, Self::MAX_LEN)
            }

            /// Creates a new instance from the parsed hex string.
            #[inline]
            $vis fn parse_hex_string(
                input: &str,
            ) -> crate::error::Result<Self> {
                if input.len() % 2 != 0 {
                    return Err(crate::error::Error::invalid_input(
                        "hex string with odd length".to_string(),
                    ));
                }

                let out_len = input.len() / 2;
                if out_len > Self::MAX_LEN {
                    return Err(crate::error::Error::invalid_input(
                        "hex string value exceeds buffer size".to_string(),
                    ));
                }

                let mut out = [0u8; Self::MAX_LEN];

                let mut out_ix = 0;
                let mut in_ix = 0;
                while in_ix < input.len() {
                    let next_two_chars = &input[in_ix..in_ix + 2];
                    out[out_ix] = u8::from_str_radix(next_two_chars, 16).unwrap();

                    in_ix += 2;
                    out_ix += 1;
                }

                Ok($struct_name {
                    buf: out,
                    len: out_len as _,
                })
            }

            /// Returns the length of the buffer.
            #[inline]
            $vis fn len(&self) -> usize {
                self.len as _
            }

            /// Returns a slice of the buffer for its length.
            #[inline]
            $vis fn slice(&self) -> &[u8] {
                &self.buf[..self.len as _]
            }

            /// Returns a mutable slice of the buffer for its length.
            #[inline]
            $vis fn slice_mut(&mut self) -> &mut [u8] {
                &mut self.buf[..self.len as _]
            }

            /// Returns a raw pointer to the buffer.
            #[inline]
            $vis fn as_ptr(&self) -> *const u8 {
                self.buf.as_ptr()
            }
        }

        impl std::fmt::Debug for $struct_name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "{:02x?}", self.slice())
            }
        }
    )*
    }
}

pub(crate) use bounded_array;

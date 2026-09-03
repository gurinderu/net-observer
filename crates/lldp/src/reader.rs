//! A minimal, bounds-checked byte cursor.
//!
//! Every read returns a [`Result`] instead of panicking on a short buffer —
//! this is the single choke point that makes "never index out of bounds" a
//! property of the decoder rather than a hope. All slicing in the crate goes
//! through here.

use crate::error::LldpError;

/// A forward-only cursor over a byte slice.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a slice at offset zero.
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// True once the cursor has reached the end.
    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Read one byte.
    pub(crate) fn u8(&mut self, context: &'static str) -> Result<u8, LldpError> {
        // `take(1, ..)` guarantees exactly one element.
        Ok(self.take(1, context)?[0])
    }

    /// Read a big-endian `u16`.
    pub(crate) fn u16_be(&mut self, context: &'static str) -> Result<u16, LldpError> {
        let s = self.take(2, context)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }

    /// Read a big-endian `u32`.
    pub(crate) fn u32_be(&mut self, context: &'static str) -> Result<u32, LldpError> {
        let s = self.take(4, context)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }

    /// Borrow the next `n` bytes and advance, or fail if fewer remain.
    pub(crate) fn take(&mut self, n: usize, context: &'static str) -> Result<&'a [u8], LldpError> {
        let have = self.remaining();
        if n > have {
            return Err(LldpError::Truncated {
                context,
                need: n,
                have,
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

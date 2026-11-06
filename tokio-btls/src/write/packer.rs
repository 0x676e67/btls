use std::io;

use super::MAX_RECORD;

/// Packs the slices of one write into the plaintext of successive records.
///
/// A record within the current slice is borrowed in place; one spanning slices is copied into
/// `scratch`.
pub(super) struct Packer<'a> {
    bufs: &'a [io::IoSlice<'a>],
    // The next unsealed byte is `bufs[i][off]`.
    i: usize,
    off: usize,
    // Largest record to pack: `MAX_RECORD` until a short seal reveals a smaller send fragment.
    pub(super) limit: usize,
    scratch: Vec<u8>,
}

impl<'a> Packer<'a> {
    #[inline]
    pub(super) fn new(bufs: &'a [io::IoSlice<'a>]) -> Self {
        Packer {
            bufs,
            i: 0,
            off: 0,
            limit: MAX_RECORD,
            scratch: Vec::new(),
        }
    }

    /// Skips empty slices and returns the plaintext of the next record, or `None` once every
    /// slice is sealed.
    ///
    /// Always inlined: it is the body of the `ssl_write_records` loop.
    #[inline(always)]
    pub(super) fn next_record(&mut self) -> Option<&[u8]> {
        let bufs = self.bufs;
        let head = loop {
            let head = &bufs.get(self.i)?[self.off..];
            if !head.is_empty() {
                break head;
            }
            self.i += 1;
            self.off = 0;
        };

        let head_len = head.len().min(self.limit);
        let (len, end, tail) = self.pack();
        if len == head_len {
            return Some(&head[..len]);
        }
        Some(self.gather(head, len, end, tail))
    }

    /// Copies `head`, the whole slices up to `end` and `tail` bytes of `bufs[end]` into `scratch`.
    ///
    /// Never inlined: in its own function the per-slice copy loop takes fewer instructions.
    #[inline(never)]
    fn gather(&mut self, head: &[u8], len: usize, end: usize, tail: usize) -> &[u8] {
        let bufs = self.bufs;
        self.scratch.clear();
        self.scratch.reserve(len);
        self.scratch.extend_from_slice(head);
        for buf in &bufs[self.i + 1..end] {
            self.scratch.extend_from_slice(buf);
        }
        if tail > 0 {
            self.scratch.extend_from_slice(&bufs[end][..tail]);
        }
        &self.scratch
    }

    /// Chooses a record length of at most `limit`, the end of grouped slices, and a prefix of the
    /// next slice.
    #[inline]
    fn pack(&self) -> (usize, usize, usize) {
        let Packer {
            bufs,
            i,
            off,
            limit,
            ..
        } = *self;
        let head_len = (bufs[i].len() - off).min(limit);
        let mut len = head_len;
        let (mut end, mut tail) = (i + 1, 0);
        while end < bufs.len() && len < limit {
            let next = bufs[end].len();
            if len + next <= limit {
                len += next;
                end += 1;
            } else {
                // Avoid copying a prefix from slices larger than half a record to fill it.
                // An isolated head and final slice already need two records; keep their boundary.
                if next <= limit / 2
                    && (len > head_len || bufs[end + 1..].iter().any(|buf| !buf.is_empty()))
                {
                    tail = limit - len;
                    len = limit;
                }
                break;
            }
        }
        (len, end, tail)
    }

    /// Moves past `n` sealed bytes.
    #[inline]
    pub(super) fn advance(&mut self, mut n: usize) {
        while n > 0 {
            let left = self.bufs[self.i].len() - self.off;
            if n < left {
                self.off += n;
                break;
            }
            n -= left;
            self.i += 1;
            self.off = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packing_preserves_in_place_heads_and_fills_longer_inputs() {
        type PackingCase<'a> = (&'a [usize], usize, usize, (usize, usize, usize));
        let cases: &[PackingCase<'_>] = &[
            (&[10000, 7000], 0, 0, (10000, 1, 0)),
            (&[8193, 8192], 0, 0, (8193, 1, 0)),
            (&[16000, 500], 0, 0, (16000, 1, 0)),
            (&[10000, 0, 7000, 0], 0, 0, (10000, 2, 0)),
            (&[8193, 8192, 0], 0, 0, (8193, 1, 0)),
            (&[7000, 0, 0], 0, 0, (7000, 3, 0)),
            (&[0, 7000, 0], 1, 0, (7000, 3, 0)),
            (&[23000, 7000, 0], 0, 13000, (10000, 1, 0)),
            (&[10000, 7000, 10000], 0, 0, (MAX_RECORD, 1, 6384)),
            (&[10000, 7000, 0, 10000], 0, 0, (MAX_RECORD, 1, 6384)),
            (&[6000, 6000, 7000], 0, 0, (MAX_RECORD, 2, 4384)),
            (&[8191, 8192], 0, 0, (16383, 2, 0)),
            (&[8192, 8192], 0, 0, (MAX_RECORD, 2, 0)),
            (&[8192, 8193, 1], 0, 0, (8192, 1, 0)),
        ];
        // After a short seal, records hold at most one 512-byte fragment.
        let short: &[PackingCase<'_>] = &[
            (&[16384], 0, 0, (512, 1, 0)),
            (&[10000, 7000], 0, 9728, (272, 1, 0)),
            (&[300, 100, 7000], 0, 0, (400, 2, 0)),
            (&[300, 100, 200, 50], 0, 0, (512, 2, 112)),
            (&[9, 16384, 9, 16384], 0, 0, (9, 1, 0)),
            (&[9, 16384, 9, 16384], 1, 16000, (393, 3, 0)),
        ];
        let cases = cases.iter().map(|&case| (MAX_RECORD, case));
        for (limit, (lengths, i, off, expected)) in
            cases.chain(short.iter().map(|&case| (512, case)))
        {
            let data: Vec<_> = lengths.iter().map(|&len| vec![0; len]).collect();
            let bufs: Vec<_> = data.iter().map(|buf| io::IoSlice::new(buf)).collect();
            assert_eq!(
                Packer {
                    bufs: &bufs,
                    i,
                    off,
                    limit,
                    scratch: Vec::new()
                }
                .pack(),
                expected,
                "{lengths:?}, {i}, {off}, {limit}"
            );
        }

        // Whole writes: every record fits the limit, and the records add up to the input.
        let segments: Vec<Vec<u8>> = [0, 3, 16384, 0, 40965, 1, 0, 300, 100, 200, 32771, 9]
            .into_iter()
            .enumerate()
            .map(|(i, len)| (0..len).map(|offset| (offset as u8) ^ (i as u8)).collect())
            .collect();
        let bufs: Vec<_> = segments.iter().map(|buf| io::IoSlice::new(buf)).collect();
        for limit in [512, 1000, MAX_RECORD] {
            let mut packer = Packer::new(&bufs);
            packer.limit = limit;
            let mut packed = Vec::new();
            while let Some(record) = packer.next_record() {
                assert!(!record.is_empty() && record.len() <= limit, "{limit}");
                packed.extend_from_slice(record);
                let n = record.len();
                packer.advance(n);
            }
            assert_eq!(packed, segments.concat(), "{limit}");
        }
    }
}

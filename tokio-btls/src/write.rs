//! The write path: seals plaintext into records and writes them with as few transport writes as
//! possible.

mod buffer;
mod packer;

use std::{
    io::{self, Write},
    mem::{self, MaybeUninit},
    slice,
};

use btls::ssl::{self, SslStream as SslStreamCore};
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) use self::buffer::WriteBuffer;
use self::packer::Packer;
use crate::bio::StreamWrapper;

/// Buffered ciphertext threshold at which writes stop sealing, except for a final
/// plaintext tail of at most `MAX_RECORD` bytes.
pub(crate) const WRITE_BUF_CAPACITY: usize = 64 * 1024;

/// Largest plaintext in one TLS record
/// ([RFC 8446 §5.1](https://www.rfc-editor.org/rfc/rfc8446#section-5.1)).
pub(crate) const MAX_RECORD: usize = 16 * 1024;

/// Estimated per-record overhead (header, nonce, tag) reserved for `SSL_write` records; the
/// buffer grows when CBC records need more.
pub(crate) const RECORD_OVERHEAD: usize = 64;

/// Output room for writes sealed on the stack: one full record plus a ticket flight.
pub(crate) const SEAL_STACK_LEN: usize = 17 * 1024;

/// Seals `bufs` into records and writes them with as few transport writes as possible.
///
/// BoringSSL seals records across slice boundaries straight into caller memory: on the stack
/// for a write of at most `MAX_RECORD` bytes with nothing buffered, otherwise after the
/// buffered records within the budget of [`WriteBuffer::seal`]; [`ssl_write_records`] handles
/// what it declines. Once the transport refuses a record, the rest of the write is only buffered;
/// only BoringSSL's own flush inside `SSL_write` ignores `blocked`.
///
/// Returns the plaintext consumed, `Ok(0)` only when `bufs` holds no bytes. Errors after sealing
/// are dropped, as sealed bytes must not be resent; the next write reports them if they recur.
pub(crate) fn write_records<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    bufs: &[io::IoSlice<'_>],
) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite,
{
    let wrapper = s.get_mut();
    wrapper.write_buf.retry(&mut wrapper.transport)?;
    // Slices may alias, so the sum can exceed `usize::MAX` on 32-bit targets.
    let total = bufs.iter().fold(0usize, |n, b| n.saturating_add(b.len()));
    if total == 0 {
        // Sealing nothing would still send the pending handshake records. Past this point every
        // seal consumes at least one byte, so no path reports `Ok(0)`.
        return Ok(0);
    }
    if total <= MAX_RECORD && wrapper.write_buf.is_empty() {
        match seal_on_stack(s, bufs, total)? {
            Some(n) if n < total => {
                // The stack records are buffered; the rest follows them in the same transport
                // write. `n < total`, the exact sum here, so the advance stays in bounds.
                let mut slices = bufs.to_vec();
                let mut rest = &mut slices[..];
                io::IoSlice::advance_slices(&mut rest, n);
                // Sealed plaintext must be reported; an error after it is dropped and reported
                // by the next call only if it recurs.
                return Ok(n + write_buffered(s, rest, total - n).unwrap_or(0));
            }
            Some(n) => return Ok(n),
            None => {}
        }
    }
    write_buffered(s, bufs, total)
}

/// Seals `bufs` after the buffered records and drains them unless the transport is blocked, or
/// writes them with [`ssl_write_records`] where BoringSSL declines.
fn write_buffered<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    bufs: &[io::IoSlice<'_>],
    total: usize,
) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite,
{
    if let Some(limits) = s.ssl().seal_app_data_limits() {
        // The buffer lives behind the BIO; move it out while the `SslRef` is borrowed mutably.
        let mut write_buf = mem::take(&mut s.get_mut().write_buf);
        let sealed = write_buf.seal(s.ssl_mut(), limits, bufs, total);
        let wrapper = s.get_mut();
        debug_assert!(wrapper.write_buf.is_empty(), "sealing wrote to the BIO");
        wrapper.write_buf = write_buf;
        if let Some(n) = sealed? {
            let StreamWrapper {
                transport,
                write_buf,
                ..
            } = wrapper;
            write_buf.drain_unless_blocked(transport);
            return Ok(n);
        }
    }
    ssl_write_records(s, bufs, total)
}

/// Seals a write of at most `MAX_RECORD` bytes on the stack and sends it with one transport
/// write.
///
/// If small send fragments split the write and not every record fits, the sealed ones are
/// buffered for the caller to send with the rest. Returns `Ok(None)` if BoringSSL declines,
/// changing nothing.
#[inline(never)] // keep the 17 KiB frame out of `write_records`
fn seal_on_stack<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    bufs: &[io::IoSlice<'_>],
    total: usize,
) -> io::Result<Option<usize>>
where
    S: AsyncRead + AsyncWrite,
{
    let mut out = [MaybeUninit::<u8>::uninit(); SEAL_STACK_LEN];
    let sealed = match s.ssl_mut().seal_app_data(bufs, total, &mut out) {
        Ok(Some(sealed)) => sealed,
        Ok(None) => return Ok(None),
        Err(e) => return Err(io::Error::other(ssl::Error::from(e))),
    };
    // SAFETY: `seal_app_data` initialized the first `written` bytes of `out`, and `written` is
    // at most `out.len()`.
    let records = unsafe { slice::from_raw_parts(out.as_ptr().cast::<u8>(), sealed.written) };
    let StreamWrapper {
        transport,
        write_buf,
        ..
    } = s.get_mut();
    debug_assert!(write_buf.is_empty(), "sealing wrote to the BIO");
    if sealed.consumed < total {
        write_buf.push(records);
    } else {
        // What the transport does not take stays buffered; an error is dropped, and the next
        // retry reports it only if it recurs.
        write_buf.write_last(transport, records);
    }
    Ok(Some(sealed.consumed))
}

/// Seals `bufs` with one `SSL_write` per record and writes them with as few transport writes as
/// possible.
///
/// Small adjacent slices share records as in a flattened buffer. Sealing stops once buffered
/// ciphertext reaches `WRITE_BUF_CAPACITY`, except when at most `MAX_RECORD` plaintext bytes
/// remain. Records are buffered as sealed; unless `blocked`, the one packed last goes out with
/// them and a final drain sends anything left. The BIO accepts every record, so BoringSSL never
/// holds a pending write that a retry with less data would fail.
///
/// Must follow [`WriteBuffer::retry`], with `total` the saturating sum of `bufs`. Returns like
/// [`write_records`].
pub(crate) fn ssl_write_records<S>(
    s: &mut SslStreamCore<StreamWrapper<S>>,
    bufs: &[io::IoSlice<'_>],
    total: usize,
) -> io::Result<usize>
where
    S: AsyncRead + AsyncWrite,
{
    s.get_mut().write_buf.reserve(total);

    let mut written = 0usize;
    let mut err = None;
    let mut packer = Packer::new(bufs);
    // A short seal means a smaller send fragment or a 0-RTT budget; batch the rest instead.
    let mut through = true;
    while let Some(plaintext) = packer.next_record() {
        let len = plaintext.len();
        s.get_mut().write_through = through && written.saturating_add(len) >= total;
        let n = match s.write(plaintext) {
            Ok(n) => n,
            Err(e) => {
                err = Some(e);
                break;
            }
        };
        if n < len {
            // Pack no more than one fragment, so a smaller one copies no plaintext twice. A
            // client still in 0-RTT may instead have hit the early data budget.
            if s.ssl().is_server() || !s.ssl().in_early_data() {
                packer.limit = n;
            }
            through = false;
        }
        written += n;
        packer.advance(n);

        // Finish a tail of at most one default record, even if backpressure leaves it buffered.
        if s.get_ref().write_buf.is_full() && total.saturating_sub(written) > MAX_RECORD {
            break;
        }
    }

    let StreamWrapper {
        transport,
        write_buf,
        write_through,
        ..
    } = s.get_mut();
    *write_through = false;
    write_buf.drain_unless_blocked(transport);
    match err {
        Some(e) if written == 0 => Err(e),
        // Sealed plaintext must be reported, or a retry would send it twice.
        _ => Ok(written),
    }
}

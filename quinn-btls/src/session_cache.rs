use crate::error::Result;
use crate::{Error, QuicSslSession};
use btls::ssl::{SslContextRef, SslSession};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use lru::LruCache;
use quinn_proto::{transport_parameters::TransportParameters, Side};
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// A client-side Session cache for the BoringSSL crypto provider.
pub trait SessionCache: Send + Sync {
    /// Adds the given value to the session cache.
    fn put(&self, key: Bytes, value: Bytes);

    /// Returns the cached session, if it exists.
    fn get(&self, key: Bytes) -> Option<Bytes>;

    /// Removes the cached session, if it exists.
    fn remove(&self, key: Bytes);

    /// Removes all entries from the cache.
    fn clear(&self);
}

/// A utility for combining an [SslSession] and server [TransportParameters] as a
/// [SessionCache] entry.
pub struct Entry {
    pub session: SslSession,
    pub params: TransportParameters,
}

impl Entry {
    /// Encodes this [Entry] into a [SessionCache] value.
    pub fn encode(&self) -> Result<Bytes> {
        let mut out = BytesMut::with_capacity(2048);

        // Split the buffer in two: the length prefix buffer and the encoded session buffer.
        // This will be O(1) as both will refer to the same underlying buffer.
        let mut encoded = out.split_off(8);

        // Store the session in the second buffer.
        self.session.encode(&mut encoded)?;

        // Go back and write the length to the first buffer.
        out.put_u64(encoded.len() as u64);

        // Unsplit to merge the two buffers back together. This will be O(1) since
        // the buffers are already contiguous in memory.
        out.unsplit(encoded);

        // Now add the transport parameters.
        out.reserve(128);
        let mut encoded = out.split_off(out.len() + 8);
        self.params.write(&mut encoded);
        out.put_u64(encoded.len() as u64);
        out.unsplit(encoded);

        Ok(out.freeze())
    }

    /// Decodes a [SessionCache] value into an [Entry].
    pub fn decode(ctx: &SslContextRef, mut encoded: Bytes) -> Result<Self> {
        // Decode the session.
        let len = encoded.get_u64() as usize;
        let mut encoded_session = encoded.split_to(len);
        let session = SslSession::decode(ctx, &mut encoded_session)?;

        // Decode the transport parameters.
        let len = encoded.get_u64() as usize;
        let mut encoded_params = encoded.split_to(len);
        let params = TransportParameters::read(Side::Client, &mut encoded_params).map_err(|e| {
            Error::invalid_input(format!("failed parsing cached transport parameters: {e:?}"))
        })?;

        Ok(Self { session, params })
    }
}

/// A [SessionCache] implementation that will never cache anything. Requires no storage.
pub struct NoSessionCache;

impl SessionCache for NoSessionCache {
    fn put(&self, _: Bytes, _: Bytes) {}

    fn get(&self, _: Bytes) -> Option<Bytes> {
        None
    }

    fn remove(&self, _: Bytes) {}

    fn clear(&self) {}
}

pub struct SimpleCache {
    cache: Mutex<LruCache<Bytes, Bytes>>,
}

impl SimpleCache {
    pub fn new(num_entries: usize) -> Self {
        SimpleCache {
            cache: Mutex::new(LruCache::new(NonZeroUsize::new(num_entries).unwrap())),
        }
    }
}

impl SessionCache for SimpleCache {
    fn put(&self, key: Bytes, value: Bytes) {
        let _ = self.cache.lock().unwrap().put(key, value);
    }

    fn get(&self, key: Bytes) -> Option<Bytes> {
        self.cache.lock().unwrap().get(&key).cloned()
    }

    fn remove(&self, key: Bytes) {
        let _ = self.cache.lock().unwrap().pop(&key);
    }

    fn clear(&self) {
        self.cache.lock().unwrap().clear()
    }
}

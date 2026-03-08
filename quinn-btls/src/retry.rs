use crate::key::{AeadKey, Key, Nonce};
use crate::suite::CipherSuite;
use crate::{aead, QuicVersion};
use quinn_proto::ConnectionId;

const TAG_LEN: usize = aead::AES_GCM_TAG_LEN;

#[inline]
pub(crate) fn retry_tag(
    version: &QuicVersion,
    orig_dst_cid: &ConnectionId,
    packet: &[u8],
) -> [u8; TAG_LEN] {
    let suite = CipherSuite::aes128_gcm_sha256();
    let key = Key::from(version.retry_integrity_key());
    let nonce = Nonce::from(version.retry_integrity_nonce());
    let key = AeadKey::new(suite, key).unwrap();

    let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
    pseudo_packet.push(orig_dst_cid.len() as u8);
    pseudo_packet.extend_from_slice(orig_dst_cid);
    pseudo_packet.extend_from_slice(packet);

    // Encrypt using the packet as additional data.
    let mut encrypted = Vec::from(&[0; TAG_LEN][..]);
    key.seal_in_place(&nonce, &mut encrypted, &pseudo_packet)
        .unwrap();
    let tag_start = encrypted.len() - TAG_LEN;

    // Now extract the tag that was written.
    let mut tag = [0; TAG_LEN];
    tag.copy_from_slice(&encrypted[tag_start..]);
    tag
}

#[inline]
pub(crate) fn is_valid_retry(
    version: &QuicVersion,
    orig_dst_cid: &ConnectionId,
    header: &[u8],
    payload: &[u8],
) -> bool {
    let tag_start = match payload.len().checked_sub(TAG_LEN) {
        Some(x) => x,
        None => return false,
    };

    let mut pseudo_packet =
        Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
    pseudo_packet.push(orig_dst_cid.len() as u8);
    pseudo_packet.extend_from_slice(orig_dst_cid);
    pseudo_packet.extend_from_slice(header);
    let tag_start = tag_start + pseudo_packet.len();
    pseudo_packet.extend_from_slice(payload);

    let suite = CipherSuite::aes128_gcm_sha256();
    let key = Key::from(version.retry_integrity_key());
    let nonce = Nonce::from(version.retry_integrity_nonce());
    let key = AeadKey::new(suite, key).unwrap();

    let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
    key.open_in_place(&nonce, tag, aad).is_ok()
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use quinn_proto::ConnectionId;

    #[test]
    fn test_is_valid_retry() {
        let orig_dst_cid = ConnectionId::new(&hex!("e080ab63f82458c1fd4d64f66faa9216f3f8b481"));
        let header = hex!("f0000000010884d5a4bdfc1811e108648f4abb039d0c0a");
        let packet = hex!("e9088adb79f9"
            "7eabc8b5c8e78f4cc23da7a9dfa43a48a9b2dedc00c3a928ce501e2067300f1be896c2bde90af634ea8a"
            "7fd1bb7ffd7c5ba7087cdb8c2a060eb360017e850bf5d27b063eedffa9"
            "dfcdb8ebb4499c60cd86a84a9b2a2adf");
        assert!(is_valid_retry(
            &QuicVersion::V1,
            &orig_dst_cid,
            &header,
            &packet
        ))
    }

    #[test]
    fn test_retry_tag() {
        let orig_dst_cid = ConnectionId::new(&hex!("e080ab63f82458c1fd4d64f66faa9216f3f8b481"));
        let packet = hex!("f0000000010884d5a4bdfc1811e108648f4abb039d0c0ae9088adb79f9"
            "7eabc8b5c8e78f4cc23da7a9dfa43a48a9b2dedc00c3a928ce501e2067300f1be896c2bde90af634ea8a"
            "7fd1bb7ffd7c5ba7087cdb8c2a060eb360017e850bf5d27b063eedffa9");
        let expected = hex!("dfcdb8ebb4499c60cd86a84a9b2a2adf");

        let tag = retry_tag(&QuicVersion::V1, &orig_dst_cid, &packet);
        assert_eq!(expected, tag)
    }
}

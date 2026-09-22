use boring::hash::{hash, MessageDigest};
use boring::hkdf::HkdfSuite;

const RFC5869_CASE_2_INFO: &str = concat!(
    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
    "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef",
    "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
);
const RFC5869_CASE_2_PRK: &str = "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244";
const RFC5869_CASE_2_OKM: &str = concat!(
    "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c",
    "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71",
    "cc30c58179ec3e87c14c01d5c1f3434f1d87",
);

#[derive(Copy, Clone)]
struct TestVector {
    ikm: &'static str,
    salt: &'static str,
    info: &'static str,
    prk: &'static str,
    okm: &'static str,
}

fn decode(value: &str) -> Vec<u8> {
    hex::decode(value).unwrap()
}

fn assert_vectors(digest: MessageDigest, vectors: &[TestVector]) {
    let suite = HkdfSuite::new(digest);

    for vector in vectors {
        let ikm = decode(vector.ikm);
        let salt = decode(vector.salt);
        let info = decode(vector.info);
        let expected_prk = decode(vector.prk);
        let expected_okm = decode(vector.okm);

        let prk = suite.extract(&salt, &ikm).unwrap();
        assert_eq!(prk.as_ref(), expected_prk.as_slice());
        assert_eq!(prk.len(), suite.prk_size());

        let mut okm = vec![0u8; expected_okm.len()];
        suite.expand(prk.as_ref(), &info, &mut okm).unwrap();
        assert_eq!(okm, expected_okm);
    }
}

#[test]
fn rfc5869_sha256_vectors() {
    // Test vectors from RFC 5869, sections A.1 through A.3.
    assert_vectors(
        MessageDigest::sha256(),
        &[
            TestVector {
                ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                salt: "000102030405060708090a0b0c",
                info: "f0f1f2f3f4f5f6f7f8f9",
                prk: "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                okm: "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            },
            TestVector {
                ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                info: RFC5869_CASE_2_INFO,
                prk: RFC5869_CASE_2_PRK,
                okm: RFC5869_CASE_2_OKM,
            },
            TestVector {
                ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                salt: "",
                info: "",
                prk: "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                okm: "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
            },
        ],
    );
}

#[test]
fn rfc5869_sha1_vectors() {
    // Test vectors from RFC 5869, sections A.4 through A.7.
    assert_vectors(
        MessageDigest::sha1(),
        &[
            TestVector {
                ikm: "0b0b0b0b0b0b0b0b0b0b0b",
                salt: "000102030405060708090a0b0c",
                info: "f0f1f2f3f4f5f6f7f8f9",
                prk: "9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243",
                okm: "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
            },
            TestVector {
                ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
                salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
                info: RFC5869_CASE_2_INFO,
                prk: "8adae09a2a307059478d309b26c4115a224cfaf6",
                okm: "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4",
            },
            TestVector {
                ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
                salt: "",
                info: "",
                prk: "da8c8a73c7fa77288ec6f5e7c297786aa0d32d01",
                okm: "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918",
            },
            TestVector {
                ikm: "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
                salt: "",
                info: "",
                prk: "2adccada18779e7c2077ad2eb19d3f3e731385dd",
                okm: "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48",
            },
        ],
    );
}

#[test]
fn independent_sha384_and_sha512_vectors() {
    // These vectors were generated independently with Python 3's standard
    // library `hmac` and `hashlib` modules.
    assert_vectors(
        MessageDigest::sha384(),
        &[TestVector {
            ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            salt: "000102030405060708090a0b0c",
            info: "f0f1f2f3f4f5f6f7f8f9",
            prk: "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8dec70ee9a7e1f3e293ef68eceb072a5ade",
            okm: "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f748b6457763e4f0204fc5d95d1da3e62587b22eb8943d0fab6bb631a2fe9df1a68c6ce5d56116a52005b3f122b88b39b7251fcd6c44d3ef25f20ed96802bf1b2c1d98bf74",
        }],
    );
    assert_vectors(
        MessageDigest::sha512(),
        &[TestVector {
            ikm: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f",
            salt: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
            info: RFC5869_CASE_2_INFO,
            prk: "35672542907d4e142c00e84499e74e1de08be86535f924e022804ad775dde27ec86cd1e5b7d178c74489bdbeb30712beb82d4f97416c5a94ea81ebdf3e629e4a",
            okm: "ce6c97192805b346e6161e821ed165673b84f400a2b514b2fe23d84cd189ddf1b695b48cbd1c8388441137b3ce28f16aa64ba33ba466b24df6cfcb021ecff235f6a2056ce3af1de44d572097a8505d9e7a9354e5796284151c2dd39c39b3cd3d8e50fcc383ebdec37476e03b721ef5efef873c281f018b8ca42e1245b2271f871ba6",
        }],
    );
}

#[test]
fn expand_matches_rfc5869_case_2_at_block_boundaries() {
    let suite = HkdfSuite::new(MessageDigest::sha256());
    let prk = decode(RFC5869_CASE_2_PRK);
    let info = decode(RFC5869_CASE_2_INFO);
    let expected = decode(RFC5869_CASE_2_OKM);

    for length in [1, 31, 32, 33, 63, 64, 65] {
        let mut okm = vec![0; length];
        suite.expand(&prk, &info, &mut okm).unwrap();
        assert_eq!(okm, expected[..length]);
    }
}

#[test]
fn empty_inputs_and_zero_output() {
    let suite = HkdfSuite::new(MessageDigest::sha256());
    let prk = suite.extract(&[], &[]).unwrap();
    assert_eq!(
        prk.as_ref(),
        decode("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad").as_slice()
    );

    let mut okm = [];
    suite.expand(prk.as_ref(), &[], &mut okm).unwrap();
}

#[test]
fn extract_accepts_empty_ikm_with_a_nonempty_salt() {
    let suite = HkdfSuite::new(MessageDigest::sha256());
    let prk = suite.extract(b"salt", &[]).unwrap();
    assert_eq!(
        prk.as_ref(),
        decode("379d7f7966f400cb6e3c0b2cca4bf8a2db03b8c81fef8020015b5a3103c30460").as_slice()
    );
}

#[test]
fn output_limit_is_enforced_for_each_digest() {
    struct DigestCase {
        digest: MessageDigest,
        prk_size: usize,
        prk: &'static str,
        output_hash: &'static str,
        output_tail: &'static str,
    }

    // The output hashes and tails were generated independently with Python
    // 3's standard library `hmac` and `hashlib` modules.
    let cases = [
        DigestCase {
            digest: MessageDigest::sha1(),
            prk_size: 20,
            prk: "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
            output_hash: "1a587819ead9e13e0e04def8721c723beb780740",
            output_tail: "9a1fd0b1687548543fa811c5117cb8bc784634dc",
        },
        DigestCase {
            digest: MessageDigest::sha256(),
            prk_size: 32,
            prk: "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
            output_hash: "8f06b0d3c135da7d77534048a98ce5d5ed37c379996be1c43f0b8f264ffedde7",
            output_tail: "d088fc3911508c67b985be209d5e5720b9e9d4d98c145952a1aa4362caf53fce",
        },
        DigestCase {
            digest: MessageDigest::sha384(),
            prk_size: 48,
            prk: "6c1f2ee938fad2e24bd91298474382ca218c75db3d83e114b3d4367776d14d3551289e75e8209cd4b792302840234adc",
            output_hash: "bdbb33e0026747dd19126067deb66fd6fa1d9e60e01d72645e935c4b571f98ad1156d48f54e140cedf64b791051467ff",
            output_tail: "d298f9f97fe2ca14527503d2c47e2da0c4940702ebd12ad0dc3fbb65e44edc3e9fe8cb67fcc7da85fe9453015a3480ef",
        },
        DigestCase {
            digest: MessageDigest::sha512(),
            prk_size: 64,
            prk: "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47",
            output_hash: "3fa5497792fb0deed77e259b3fcf5a3b1fe36a1e07de8c3ffa4499224027f798a62f3a066f50be7f41a6d4a292ad1b82d2d21dbae703834121ec6bf1bc0d076b",
            output_tail: "fefd61f23f2b4dc19789052152b2aebb1b4e9068a255b0b4a684efd0e99784a41242a6dfc85064bd8b13fd8be604ee34e83073619c21f3a00b5103b85f72097a",
        },
    ];

    for case in cases {
        let suite = HkdfSuite::new(case.digest);
        assert_eq!(suite.prk_size(), case.prk_size);

        let prk = suite.extract(&[], &[]).unwrap();
        assert_eq!(prk.as_ref(), decode(case.prk).as_slice());

        let mut max = vec![0xa5; 255 * case.prk_size];
        suite.expand(prk.as_ref(), &[], &mut max).unwrap();
        let digest = hash(case.digest, &max).unwrap();
        assert_eq!(digest.as_ref(), decode(case.output_hash).as_slice());
        assert_eq!(
            &max[max.len() - case.prk_size..],
            decode(case.output_tail).as_slice()
        );

        let mut too_long = vec![0xa5; max.len() + 1];
        let error = suite.expand(prk.as_ref(), &[], &mut too_long).unwrap_err();
        assert!(!error.errors().is_empty());
        assert_eq!(error.errors()[0].reason(), Some("OUTPUT_TOO_LARGE"));
        assert!(too_long.iter().all(|&byte| byte == 0xa5));
    }
}

#[test]
fn expand_accepts_a_prk_longer_than_hash_len() {
    struct DigestCase {
        digest: MessageDigest,
        expected: &'static str,
    }

    // Expected OKM was generated independently with Python 3's standard
    // library `hmac` module using a PRK of HashLen + 1 bytes.
    let cases = [
        DigestCase {
            digest: MessageDigest::sha1(),
            expected: "9324f49000a5f860846f69d962a74fa296b3f66292a36c84132251",
        },
        DigestCase {
            digest: MessageDigest::sha256(),
            expected: "54884956024c4667f33553b446e944d602ae41b99d61abe34da1cf2c59ee13fc3d96f8b767a227",
        },
        DigestCase {
            digest: MessageDigest::sha384(),
            expected: "118b9db28f338f697460cb1ffe872d29bcdf8a0b3bced52053c87242f0b3efca84f748e5b0011156cb380195c412049982b0719e766594",
        },
        DigestCase {
            digest: MessageDigest::sha512(),
            expected: "53272e5bd3bc509ffe6e1039c39390051ad5a133f01fe85b99a59e429310368721b17dc64ec7cf90b8d285cf62c1ee98e7d83d92009d8cf3e0d5c0ea75a5a9b9f08cec559d1819",
        },
    ];

    for case in cases {
        let suite = HkdfSuite::new(case.digest);
        let prk: Vec<_> = (0..=suite.prk_size() as u8).collect();
        let info = b"longer than HashLen PRK";
        let mut okm = vec![0; decode(case.expected).len()];
        suite.expand(&prk, info, &mut okm).unwrap();
        assert_eq!(okm, decode(case.expected));
    }
}

#[test]
fn expand_rejects_a_prk_shorter_than_hash_len() {
    for digest in [
        MessageDigest::sha1(),
        MessageDigest::sha256(),
        MessageDigest::sha384(),
        MessageDigest::sha512(),
    ] {
        let suite = HkdfSuite::new(digest);
        for prk_len in [0, suite.prk_size() - 1] {
            let prk = vec![0; prk_len];
            let mut okm = [0xa5];
            let error = suite.expand(&prk, b"info", &mut okm).unwrap_err();
            assert!(!error.errors().is_empty());
            assert_eq!(okm, [0xa5]);
        }
    }
}

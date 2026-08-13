use hex::{self, FromHex};

use crate::asn1::Asn1Time;
use crate::bn::{BigNum, MsbOption};
use crate::hash::MessageDigest;
use crate::nid::Nid;
use crate::pkey::{PKey, Private};
use crate::rsa::Rsa;
use crate::stack::Stack;
use crate::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use crate::x509::store::X509StoreBuilder;
use crate::x509::{X509Extension, X509Name, X509Req, X509StoreContext, X509};

mod trusted_first;

fn pkey() -> PKey<Private> {
    let rsa = Rsa::generate(2048).unwrap();
    PKey::from_rsa(rsa).unwrap()
}

#[test]
fn test_cert_loading() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let fingerprint = cert.digest(MessageDigest::sha1()).unwrap();

    let hash_str = "582f63a9d73ce9cd3df62fe26a6415ef5aceda30";
    let hash_vec = Vec::from_hex(hash_str).unwrap();

    assert_eq!(hash_vec, &*fingerprint);
}

#[test]
fn test_debug() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let debugged = format!("{cert:#?}");

    assert!(debugged.contains(r#"serial_number: "8771f7bdee982fa5""#));
    assert!(debugged.contains(r#"signature_algorithm: sha256WithRSAEncryption"#));
    assert!(debugged.contains(r#"countryName = "AU""#));
    assert!(debugged.contains(r#"stateOrProvinceName = "Some-State""#));
    assert!(debugged.contains(r#"not_before: Aug 13 01:04:28 2026 GMT"#));
    assert!(debugged.contains(r#"not_after: May  4 01:04:28 2049 GMT"#));
}

#[test]
fn test_cert_issue_validity() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let not_before = cert.not_before().to_string();
    let not_after = cert.not_after().to_string();

    assert_eq!(not_before, "Aug 13 01:04:28 2026 GMT");
    assert_eq!(not_after, "May  4 01:04:28 2049 GMT");
}

#[test]
fn test_save_der() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let der = cert.to_der().unwrap();
    assert!(!der.is_empty());
}

#[test]
fn test_subject_read_cn() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();
    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"foobar.com");
}

#[test]
fn test_nid_values() {
    let cert = include_bytes!("../../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(Nid::COMMONNAME).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"example.com");

    let email = subject
        .entries_by_nid(Nid::PKCS9_EMAILADDRESS)
        .next()
        .unwrap();
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let friendly = subject.entries_by_nid(Nid::FRIENDLYNAME).next().unwrap();
    assert_eq!(&**friendly.data().as_utf8().unwrap(), "Example");
}

#[test]
fn test_nameref_iterator() {
    let cert = include_bytes!("../../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();
    let mut all_entries = subject.entries();

    let email = all_entries.next().unwrap();
    assert_eq!(
        email.object().nid().as_raw(),
        Nid::PKCS9_EMAILADDRESS.as_raw()
    );
    assert_eq!(email.data().as_slice(), b"test@example.com");

    let cn = all_entries.next().unwrap();
    assert_eq!(cn.object().nid().as_raw(), Nid::COMMONNAME.as_raw());
    assert_eq!(cn.data().as_slice(), b"example.com");

    let friendly = all_entries.next().unwrap();
    assert_eq!(friendly.object().nid().as_raw(), Nid::FRIENDLYNAME.as_raw());
    assert_eq!(&**friendly.data().as_utf8().unwrap(), "Example");

    if all_entries.next().is_some() {
        panic!();
    }
}

#[test]
fn test_nid_uid_value() {
    let cert = include_bytes!("../../../test/nid_uid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let subject = cert.subject_name();

    let cn = subject.entries_by_nid(Nid::USERID).next().unwrap();
    assert_eq!(cn.data().as_slice(), b"this is the userId");
}

#[test]
fn test_subject_alt_name() {
    let cert = include_bytes!("../../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    assert_eq!(5, subject_alt_names.len());
    assert_eq!(Some("example.com"), subject_alt_names[0].dnsname());
    assert_eq!(subject_alt_names[1].ipaddress(), Some(&[127, 0, 0, 1][..]));
    assert_eq!(
        subject_alt_names[2].ipaddress(),
        Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..])
    );
    assert_eq!(Some("test@example.com"), subject_alt_names[3].email());
    assert_eq!(Some("http://www.example.com"), subject_alt_names[4].uri());
}

#[test]
fn test_subject_alt_name_iter() {
    let cert = include_bytes!("../../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let subject_alt_names = cert.subject_alt_names().unwrap();
    let mut subject_alt_names_iter = subject_alt_names.iter();
    assert_eq!(
        subject_alt_names_iter.next().unwrap().dnsname(),
        Some("example.com")
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().ipaddress(),
        Some(&[127, 0, 0, 1][..])
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().ipaddress(),
        Some(&b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01"[..])
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().email(),
        Some("test@example.com")
    );
    assert_eq!(
        subject_alt_names_iter.next().unwrap().uri(),
        Some("http://www.example.com")
    );
    assert!(subject_alt_names_iter.next().is_none());
}

#[test]
fn test_subject_key_id() {
    // nid_test_cert_pem has SKI, but no AKI
    let cert = include_bytes!("../../../test/nid_test_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let ski = cert.subject_key_id().expect("unable to extract SKI");
    assert_eq!(
        ski.as_slice(),
        [
            80, 107, 158, 237, 95, 61, 235, 100, 212, 115, 249, 244, 219, 163, 124, 55, 141, 2, 76,
            5
        ]
    );

    let aki = cert.authority_key_id();
    assert!(aki.is_none());
}

#[test]
fn test_x509_name_print_ex() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let name_no_flags = cert
        .subject_name()
        .print_ex(0)
        .expect("failed to print cert subject name");
    assert_eq!(
        name_no_flags,
        "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd, CN=foobar.com"
    );

    let name_rfc2253 = cert
        .subject_name()
        .print_ex(ffi::XN_FLAG_RFC2253)
        .expect("failed to print cert subject name");
    assert_eq!(
        name_rfc2253,
        "CN=foobar.com,O=Internet Widgits Pty Ltd,ST=Some-State,C=AU"
    );
}

#[test]
fn x509_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com")
        .unwrap();
    let name = name.build();

    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(365).unwrap())
        .unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    builder
        .set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();

    let basic_constraints = BasicConstraints::new().critical().ca().build().unwrap();
    builder
        .append_extension(basic_constraints.as_ref())
        .unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    builder.append_extension(&key_usage).unwrap();
    let ext_key_usage = ExtendedKeyUsage::new()
        .client_auth()
        .server_auth()
        .other("2.999.1")
        .build()
        .unwrap();
    builder.append_extension(&ext_key_usage).unwrap();
    let subject_key_identifier = SubjectKeyIdentifier::new()
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&subject_key_identifier).unwrap();
    let authority_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(true)
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&authority_key_identifier).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&builder.x509v3_context(None, None))
        .unwrap();
    builder.append_extension(&subject_alternative_name).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let x509 = builder.build();

    assert!(pkey.public_eq(&x509.public_key().unwrap()));
    assert!(x509.verify(&pkey).unwrap());

    let cn = x509
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    assert_eq!(cn.data().as_slice(), b"foobar.com");
    assert_eq!(serial, x509.serial_number().to_bn().unwrap());
}

#[test]
fn x509_extension_new() {
    assert!(X509Extension::new(None, None, "crlDistributionPoints", "section").is_err());
    assert!(X509Extension::new(None, None, "proxyCertInfo", "").is_err());
    assert!(X509Extension::new(None, None, "certificatePolicies", "").is_err());
    assert!(X509Extension::new(None, None, "subjectAltName", "dirName:section").is_err());
}

#[test]
fn x509_extension_to_der() {
    let builder = X509::builder().unwrap();

    for (ext, expected) in [
        (
            BasicConstraints::new().critical().ca().build().unwrap(),
            b"0\x0f\x06\x03U\x1d\x13\x01\x01\xff\x04\x050\x03\x01\x01\xff" as &[u8],
        ),
        (
            SubjectAlternativeName::new()
                .dns("example.com,DNS:example2.com")
                .build(&builder.x509v3_context(None, None))
                .unwrap(),
            b"0'\x06\x03U\x1d\x11\x04 0\x1e\x82\x1cexample.com,DNS:example2.com",
        ),
        (
            SubjectAlternativeName::new()
                .rid("1.2.3.4")
                .uri("https://example.com")
                .build(&builder.x509v3_context(None, None))
                .unwrap(),
            b"0#\x06\x03U\x1d\x11\x04\x1c0\x1a\x88\x03*\x03\x04\x86\x13https://example.com",
        ),
        (
            ExtendedKeyUsage::new()
                .server_auth()
                .other("2.999.1")
                .other("clientAuth")
                .build()
                .unwrap(),
            b"0\x22\x06\x03U\x1d%\x04\x1b0\x19\x06\x08+\x06\x01\x05\x05\x07\x03\x01\x06\x03\x887\x01\x06\x08+\x06\x01\x05\x05\x07\x03\x02",
        ),
    ] {
        assert_eq!(&ext.to_der().unwrap(), expected);
    }
}

#[test]
fn eku_invalid_other() {
    assert!(ExtendedKeyUsage::new()
        .other("1.1.1.1.1,2.2.2.2.2")
        .build()
        .is_err());
}

#[test]
fn x509_req_builder() {
    let pkey = pkey();

    let mut name = X509Name::builder().unwrap();
    name.append_entry_by_nid(Nid::COMMONNAME, "foobar.com")
        .unwrap();
    let name = name.build();

    let mut builder = X509Req::builder().unwrap();
    builder.set_version(0).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_pubkey(&pkey).unwrap();

    let mut extensions = Stack::new().unwrap();
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    extensions.push(key_usage).unwrap();
    let subject_alternative_name = SubjectAlternativeName::new()
        .dns("example.com")
        .build(&builder.x509v3_context(None))
        .unwrap();
    extensions.push(subject_alternative_name).unwrap();
    builder.add_extensions(&extensions).unwrap();

    builder.sign(&pkey, MessageDigest::sha256()).unwrap();

    let req = builder.build();
    assert!(req.public_key().unwrap().public_eq(&pkey));
    assert_eq!(req.extensions().unwrap().len(), extensions.len());
    assert!(req.verify(&pkey).unwrap());
}

#[test]
fn test_stack_from_pem() {
    let certs = include_bytes!("../../../test/certs.pem");
    let certs = X509::stack_from_pem(certs).unwrap();

    assert_eq!(certs.len(), 2);
    assert_eq!(
        hex::encode(certs[0].digest(MessageDigest::sha1()).unwrap()),
        "582f63a9d73ce9cd3df62fe26a6415ef5aceda30"
    );
    assert_eq!(
        hex::encode(certs[1].digest(MessageDigest::sha1()).unwrap()),
        "345131cbb40a5afed959d0c8ce537d235fe422c5"
    );
}

#[test]
fn issued() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();

    assert_eq!(ca.issued(&cert), Ok(()));
    assert!(cert.issued(&cert).is_err());
}

#[test]
fn signature() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let signature = cert.signature();
    assert_eq!(
        hex::encode(signature.as_slice()),
        "988f1702931aa8c6cab05efa22eac03f29e9c774d3c154fe6008d29bc4823bf9966070fabe45dcbd\
         87084cac1393fb583fe41fbb8afcef598dc38a8a11fe5fe37a8431e1e24d51e032ae885ed16ed9b9\
         6b255dc4eb3886567992313f62b63d89449455c8856eea5b68a6a6282cf275a2c1242e68824182d9\
         514c1de1781fd743118fbaa1f892ca9ffba0a395fc53c9c3497e539a3cc4dae05fe0604499d56cdb\
         a61740ef63da1043ae5a39778b7303a383f439cf40337e81dc7e1b98736f7414dfe51a1a328d3661\
         5691759417501fbec2c08e2c1c305aeaf06b36f341f86d63e69b8e176d5aa1432df81b41b6428901\
         7b2fe52a436ab5515eea3a4517f159ca"
    );
    let algorithm = cert.signature_algorithm();
    assert_eq!(algorithm.object().nid(), Nid::SHA256WITHRSAENCRYPTION);
    assert_eq!(algorithm.object().to_string(), "sha256WithRSAEncryption");
}

#[test]
#[allow(clippy::redundant_clone)]
fn clone_x509() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    drop(cert.clone());
}

#[test]
fn test_verify_cert() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../../test/root-ca.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(&ca).unwrap();
    let store = store_bldr.build();
    let empty_store = X509StoreBuilder::new().unwrap().build();

    let mut context = X509StoreContext::new().unwrap();
    assert!(context
        .init(&store, &cert, &chain, |c| c.verify_cert())
        .unwrap());
    assert!(!context
        .init(&empty_store, &cert, &chain, |c| c.verify_cert())
        .unwrap());
    assert!(context
        .init(&store, &cert, &chain, |c| c.verify_cert())
        .unwrap());

    context
        .reset_with_context_data(empty_store, cert.clone(), Stack::new().unwrap())
        .unwrap();
    assert!(!context.verify_cert().unwrap());

    context.reset_with_context_data(store, cert, chain).unwrap();
    assert!(context.verify_cert().unwrap());
}

#[test]
fn test_verify_fails() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();
    let ca = include_bytes!("../../../test/alt_name_cert.pem");
    let ca = X509::from_pem(ca).unwrap();
    let chain = Stack::new().unwrap();

    let mut store_bldr = X509StoreBuilder::new().unwrap();
    store_bldr.add_cert(&ca).unwrap();
    let store = store_bldr.build();

    let mut context = X509StoreContext::new().unwrap();
    assert!(!context
        .init(&store, &cert, &chain, |c| c.verify_cert())
        .unwrap());
}

#[test]
fn test_save_subject_der() {
    let cert = include_bytes!("../../../test/cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    let der = cert.subject_name().to_der().unwrap();
    println!("der: {der:?}");
    assert!(!der.is_empty());
}

#[test]
fn test_load_subject_der() {
    // The subject from ../../../test/cert.pem
    const SUBJECT_DER: &[u8] = &[
        48, 90, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 65, 85, 49, 19, 48, 17, 6, 3, 85, 4, 8, 12,
        10, 83, 111, 109, 101, 45, 83, 116, 97, 116, 101, 49, 33, 48, 31, 6, 3, 85, 4, 10, 12, 24,
        73, 110, 116, 101, 114, 110, 101, 116, 32, 87, 105, 100, 103, 105, 116, 115, 32, 80, 116,
        121, 32, 76, 116, 100, 49, 19, 48, 17, 6, 3, 85, 4, 3, 12, 10, 102, 111, 111, 98, 97, 114,
        46, 99, 111, 109,
    ];
    X509Name::from_der(SUBJECT_DER).unwrap();
}

#[test]
fn test_check_ip_asc() {
    // Covers 127.0.0.1 and 0:0:0:0:0:0:0:1
    let cert = include_bytes!("../../../test/alt_name_cert.pem");
    let cert = X509::from_pem(cert).unwrap();

    assert!(cert.check_ip_asc("127.0.0.1").unwrap());
    assert!(!cert.check_ip_asc("127.0.0.2").unwrap());

    assert!(cert.check_ip_asc("0:0:0:0:0:0:0:1").unwrap());
    assert!(!cert.check_ip_asc("0:0:0:0:0:0:0:2").unwrap());
}

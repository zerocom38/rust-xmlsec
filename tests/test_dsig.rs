//!
//! Unit Tests for DSig Context
//!
use xmlsec::XmlSecCanonicalizationMethod;
use xmlsec::XmlSecDocumentExt;
use xmlsec::XmlSecDocumentTemplating;
use xmlsec::XmlSecKey;
use xmlsec::XmlSecKeyDataType;
use xmlsec::XmlSecKeyFormat;
use xmlsec::XmlSecSignatureContext;

use libxml::parser::Parser as XmlParser;

#[test]
fn test_dsig_context_creation() {
    XmlSecSignatureContext::new();
}

#[test]
fn test_dsig_key_setting() {
    let mut ctx = XmlSecSignatureContext::new();

    let key = XmlSecKey::from_file(
        "tests/resources/key.pem",
        XmlSecKeyDataType::Unknown,
        XmlSecKeyFormat::Pem,
        None,
    )
    .expect("Failed to properly load key for test");

    let key_ptr = unsafe { key.as_ptr() };

    let oldkey = ctx.insert_key(key);

    assert!(
        oldkey.is_none(),
        "It should never have been set at this point"
    );

    let newkey = ctx
        .release_key()
        .expect("Should have had a set key now being released");

    let newkey_ptr = unsafe { newkey.as_ptr() };

    assert_eq!(
        key_ptr, newkey_ptr,
        "Key should have remained to be exactly the same"
    );
}

#[test]
fn test_signing_template() {
    let ctx = common_setup_context_and_key();

    let doc = XmlParser::default()
        .parse_file("tests/resources/sign1-tmpl.xml")
        .expect("Failed to load signature template");

    if let Err(e) = ctx.sign_document(&doc) {
        panic!("{}", e);
    }

    // compare signature results
    let reference =
        String::from_utf8(include_bytes!("./resources/sign1-res.xml").to_vec()).unwrap();

    assert_eq!(doc.to_string(), reference);
}

#[test]
fn test_verify_template_signature() {
    let ctx = common_setup_context_and_key();

    let doc = XmlParser::default()
        .parse_file("tests/resources/sign1-res.xml")
        .expect("Failed to load signature for verification testing");

    match ctx.verify_document(&doc) {
        Ok(valid) => {
            if !valid {
                panic!("Signature in testing resources should have returned to be valid");
            }
        }

        Err(e) => {
            panic!("{}", e)
        }
    }
}

#[test]
fn test_verify_custom_id_signature() {
    let ctx = common_setup_context_and_key();

    let doc = XmlParser::default()
        .parse_file("tests/resources/sign3-signed.xml")
        .expect("Failed to load signature for verification testing");

    doc.specify_idattr("//sig:Data", "ThisID", Some(&[("sig", "urn:envelope")]))
        .expect("Unable to set 'ThisID' as the ID attribute name");

    match ctx.verify_document(&doc) {
        Ok(valid) => {
            if !valid {
                panic!("Signature in testing resources should have returned to be valid");
            }
        }

        Err(e) => {
            panic!("Failed while verify signature. Caused by: {}", e);
        }
    }
}

fn common_setup_context_and_key() -> XmlSecSignatureContext {
    let mut ctx = XmlSecSignatureContext::new();

    let key = XmlSecKey::from_file(
        "tests/resources/key.pem",
        XmlSecKeyDataType::Unknown,
        XmlSecKeyFormat::Pem,
        None,
    )
    .expect("Failed to properly load key for test");

    ctx.insert_key(key);

    ctx
}
use libxml::tree::{Document, Namespace, Node};
use xmlsec::XmlSecSignatureMethod;
use xmlsec::XmlSecTemplateBuilder;

#[test]
fn test_create_signature() {
    let mut doc = Document::new().unwrap();
    let mut root = Node::new("LogReport", None, &doc).unwrap();
    let ns = Namespace::new(
        "lr",
        "http://www.smpte-ra.org/schemas/430-4/2008/LogRecord/",
        &mut root,
    )
    .unwrap();
    Namespace::new(
        "dcml",
        "http://www.smpte-ra.org/schemas/433/2008/dcmlTypes/",
        &mut root,
    )
    .unwrap();
    let ds = Namespace::new("ds", "http://www.w3.org/2000/09/xmldsig#", &mut root).unwrap();
    Namespace::new("xs", "http://www.w3.org/2001/XMLSchema", &mut root).unwrap();
    Namespace::new(
        "xsi",
        "http://www.w3.org/2001/XMLSchema-instance",
        &mut root,
    )
    .unwrap();
    root.set_namespace(&ns).unwrap();
    doc.set_root_element(&root);

    let mut node = Node::new("RecordAuthData", Some(ns.clone()), &doc).unwrap();
    node.set_attribute("Id", "ID_RecordAuthData").unwrap();

    root.add_child(&mut node).unwrap();
    let mut header_hash = Node::new("RecordHeaderHash", Some(ns.clone()), &doc).unwrap();
    header_hash
        .set_content("gB4+3kwOkyyxqN18Zv+15rfcqRM=")
        .unwrap();
    node.add_child(&mut header_hash).unwrap();
    let mut signer_cert_info = Node::new("SignerCertInfo", Some(ds.clone()), &doc).unwrap();
    node.add_child(&mut signer_cert_info).unwrap();
    let mut x509_issuer_name = Node::new("X509IssuerName", Some(ds.clone()), &doc).unwrap();
    x509_issuer_name.set_content("issuer_name_content").unwrap();
    signer_cert_info.add_child(&mut x509_issuer_name).unwrap();
    let mut x509_serial_number = Node::new("X509SerialNumber", Some(ds.clone()), &doc).unwrap();
    x509_serial_number.set_content("47").unwrap();
    signer_cert_info.add_child(&mut x509_serial_number).unwrap();

    doc.specify_idattr(
        "/lr:LogReport/lr:RecordAuthData",
        "Id",
        Some(&[(
            "lr",
            "http://www.smpte-ra.org/schemas/430-4/2008/LogRecord/",
        )]),
    )
    .unwrap();

    doc.template()
        .canonicalization(XmlSecCanonicalizationMethod::InclusiveC14N)
        .signature(XmlSecSignatureMethod::RsaSha256)
        .ns_prefix("ds")
        .reference_signature(XmlSecSignatureMethod::Sha1)
        .uri("#ID_RecordAuthData")
        .done()
        .unwrap();

    let mut sign_ctx = XmlSecSignatureContext::new();
    sign_ctx.insert_key(
        XmlSecKey::from_file(
            "tests/resources/key.pem",
            XmlSecKeyDataType::Unknown,
            XmlSecKeyFormat::Pem,
            None,
        )
        .unwrap(),
    );
    sign_ctx.sign_document(&doc).unwrap();

    println!("{}", doc.to_string());

    assert!(false);

    /*
               <lr:RecordAuthData Id="ID_RecordAuthData">
           <lr:RecordHeaderHash>gB4+3kwOkyyxqN18Zv+15rfcqRM=</lr:RecordHeaderHash>
           <lr:SignerCertInfo>
               <ds:X509IssuerName>/O=mikrom.com/OU=test-int-inter.mikrom.com/CN=.MikroM.TEST-INT-INTER.V1.000001/dnQualifier=e6fwMBm9jiAMiCx79aK3eN2Byr4=</ds:X509IssuerName>
               <ds:X509SerialNumber>47</ds:X509SerialNumber>
           </lr:SignerCertInfo>
       </lr:RecordAuthData>

    */
}

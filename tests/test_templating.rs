//!
//! Testing of Template Creation
//!
use xmlsec::XmlSecCanonicalizationMethod;
use xmlsec::XmlSecDocumentTemplateBuilder;
use xmlsec::XmlSecDocumentTemplating;
use xmlsec::XmlSecSignatureMethod;
use xmlsec::XmlSecTemplateBuilder;

use libxml::parser::Parser as XmlParser;

#[test]
fn test_template_creation() {
    // load document
    let parser = XmlParser::default();

    let doc = parser
        .parse_file("tests/resources/sign2-doc.xml")
        .expect("Could not load template document");

    // add signature node structure
    doc.template()
        .canonicalization(XmlSecCanonicalizationMethod::ExclusiveC14N)
        .signature(XmlSecSignatureMethod::RsaSha1)
        .keyname(true)
        .keyvalue(true)
        .x509data(true)
        .uri("ReferencedID")
        .done()
        .expect("Failed to build and attach signature");

    // compare template results
    let reference =
        String::from_utf8(include_bytes!("./resources/sign2-tmpl.xml").to_vec()).unwrap();

    assert_eq!(doc.to_string(), reference);
}

#[test]
fn test_template_creation_with_ns_prefix() {
    // load document
    let parser = XmlParser::default();

    let doc = parser
        .parse_file("tests/resources/sign2-doc.xml")
        .expect("Could not load template document");

    // add signature node structure
    let sign_node = XmlSecDocumentTemplateBuilder::new(&doc)
        .canonicalization(XmlSecCanonicalizationMethod::ExclusiveC14N)
        .signature(XmlSecSignatureMethod::RsaSha1)
        .ns_prefix("dsig")
        .build()
        .expect("Failed to build and attach signature");

    sign_node.reference_signature(XmlSecSignatureMethod::Sha1, Some("ReferencedID"), true);

    // doc.template()
    //     .canonicalization(XmlSecCanonicalizationMethod::ExclusiveC14N)
    //     .signature(XmlSecSignatureMethod::RsaSha1)
    //     .ns_prefix("dsig")
    //     .keyname(true)
    //     .keyvalue(true)
    //     .x509data(true)
    //     .uri("ReferencedID")
    //     .done()
    //     .expect("Failed to build and attach signature");

    // compare template results
    let reference =
        String::from_utf8(include_bytes!("./resources/sign2-tmpl-ns-prefix-dsig.xml").to_vec())
            .unwrap();

    assert_eq!(doc.to_string(), reference);
}

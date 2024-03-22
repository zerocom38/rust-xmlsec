use libxml::tree::{Document, Namespace, Node};
use xmlsec::{XmlSecNodeSet, XmlSecTransform, XmlSecTransformCtx};

#[test]
fn test_node_set_with_children() {
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
    Namespace::new("ds", "http://www.w3.org/2000/09/xmldsig#", &mut root).unwrap();
    Namespace::new("xs", "http://www.w3.org/2001/XMLSchema", &mut root).unwrap();
    Namespace::new(
        "xsi",
        "http://www.w3.org/2001/XMLSchema-instance",
        &mut root,
    )
    .unwrap();
    root.set_namespace(&ns).unwrap();
    doc.set_root_element(&root);

    let mut node = Node::new("LogRecordBody", Some(ns.clone()), &doc).unwrap();
    root.add_child(&mut node).unwrap();
    let mut eventid = Node::new("EventID", Some(ns.clone()), &doc).unwrap();
    eventid
        .set_content("urn:uuid:1f9d3a08-edd6-4402-99c0-b80d9c7614fc")
        .unwrap();
    node.add_child(&mut eventid).unwrap();
    let mut eventsubtype = Node::new("EventSubType", Some(ns), &doc).unwrap();
    eventsubtype
        .set_attribute(
            "scope",
            "http://www.smpte-ra.org/430-5/2008/SecurityLog/#EventSubTypes-operations",
        )
        .unwrap();
    eventsubtype.set_content("SPBStartup").unwrap();
    node.add_child(&mut eventsubtype).unwrap();

    println!("{:?}", doc.to_string());

    let node_set = XmlSecNodeSet::get_children(&doc, &node, false, false);

    let mut trans_ctx = XmlSecTransformCtx::new();
    let trans = XmlSecTransform::new(xmlsec::XmlSecCanonicalizationMethod::InclusiveC14N);
    trans_ctx.append(trans);
    let trans = XmlSecTransform::with_operation(
        xmlsec::XmlSecCanonicalizationMethod::Sha1,
        xmlsec::XmlSecTransformOperation::Sign,
    );
    trans_ctx.append(trans);
    let trans = XmlSecTransform::with_operation(
        xmlsec::XmlSecCanonicalizationMethod::Base64,
        xmlsec::XmlSecTransformOperation::Encode,
    );
    trans_ctx.append(trans);
    let data = trans_ctx.xml_execute(&node_set).unwrap();
    let base64_data = std::str::from_utf8(data).unwrap();

    assert_eq!(base64_data, "0HwjYW3B/l79oq2NHVctyN7qMhE=");
}

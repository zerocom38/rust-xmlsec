use libxml::tree::{Document, Node};
use xmlsec::{XmlSecNodeSet, XmlSecTransform, XmlSecTransformCtx};

#[test]
fn test_node_set() {
    let doc = Document::new().unwrap();
    let mut node = Node::new("test", None, &doc).unwrap();
    let node_set = XmlSecNodeSet::new(&doc);

    // let trans_ctx = XmlSecTransformCtx::new();
    // let trans = XmlSecTransform::with_operation(
    //     xmlsec::XmlSecCanonicalizationMethod::InclusiveC14N,
    //     xmlsec::XmlSecTransformOperation::Sign,
    // );
    // trans_ctx.append(trans);
}

#[test]
fn test_node_set_with_children() {
    let doc = Document::new().unwrap();
    let node = Node::new("test", None, &doc).unwrap();
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
    println!("{:?}", data);
    assert_eq!(data, b"");
}

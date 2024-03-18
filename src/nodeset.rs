//!
//! Wrapper for XmlSec NodeSet Methods
//!
use crate::bindings;
use crate::XmlDocument;
use crate::XmlNode;

/// NodeSet
pub struct XmlSecNodeSet {
    ctx: *mut bindings::xmlSecNodeSet,
}

/*
   int nodeNr;			/* number of nodes in the set */
   int nodeMax;		/* size of the array as allocated */
   xmlNodePtr *nodeTab;	/* array of nodes in no particular order */
*/
impl XmlSecNodeSet {
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new(doc: &XmlDocument) -> Self {
        crate::xmlsec::guarantee_xmlsec_init();

        let ctx = unsafe {
            let doc_ptr = doc.doc_ptr() as *mut bindings::xmlDoc;
            let node_set_ptr: *mut bindings::_xmlNodeSet = std::ptr::null_mut();
            bindings::xmlSecNodeSetCreate(
                doc_ptr,
                //                node_set.as_mut() as *mut bindings::_xmlNodeSet,
                node_set_ptr,
                bindings::xmlSecNodeSetType_xmlSecNodeSetNormal,
            )
        };
        if ctx.is_null() {
            panic!("Failed to create node set");
        }

        Self { ctx }
    }

    /// builds a context from an existing node set
    pub fn get_children(
        doc: &XmlDocument,
        parent: &XmlNode,
        with_comments: bool,
        invert: bool,
    ) -> Self {
        let node_ptr = parent.node_ptr() as *mut bindings::xmlNode;
        let with_comments = if with_comments { 1 } else { 0 };
        let invert = if invert { 1 } else { 0 };
        let ctx = unsafe {
            bindings::xmlSecNodeSetGetChildren(
                doc.doc_ptr() as *mut bindings::xmlDoc,
                node_ptr,
                with_comments,
                invert,
            )
        };
        Self { ctx }
    }

    /// Returns the pointer to the underlying xmlSecNodeSet
    pub fn nodeset_ptr(&self) -> *mut bindings::xmlSecNodeSet {
        self.ctx
    }
}

/*
XMLSEC_EXPORT xmlSecNodeSetPtr  xmlSecNodeSetGetChildren(xmlDocPtr doc,
                                                         const xmlNodePtr parent,
                                                         int withComments,
                                                         int invert);
 */

impl Drop for XmlSecNodeSet {
    fn drop(&mut self) {
        unsafe {
            bindings::xmlSecNodeSetDestroy(self.ctx);
        }
    }
}

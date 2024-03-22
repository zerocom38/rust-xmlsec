//!
//! Wrapper for XmlSec Tranformation Methods
//!
use crate::{bindings, XmlSecError, XmlSecNodeSet, XmlSecResult};

/// Supported canonical methods as specified by the XML standard.
#[allow(missing_docs)]
pub enum XmlSecCanonicalizationMethod {
    InclusiveC14N,
    InclusiveC14NWithComments,
    InclusiveC14N11,
    InclusiveC14N11WithComments,
    ExclusiveC14N,
    ExclusiveC14NWithComments,
    Sha1,
    Base64,
}

impl XmlSecCanonicalizationMethod {
    /// Returns the resource pointer for the corresponding canonicalization ressource
    pub fn to_method(&self) -> bindings::xmlSecTransformId {
        match self {
            Self::InclusiveC14N => unsafe { bindings::xmlSecTransformInclC14NGetKlass() },
            Self::InclusiveC14NWithComments => unsafe {
                bindings::xmlSecTransformInclC14NWithCommentsGetKlass()
            },
            Self::InclusiveC14N11 => unsafe { bindings::xmlSecTransformInclC14N11GetKlass() },
            Self::InclusiveC14N11WithComments => unsafe {
                bindings::xmlSecTransformInclC14N11WithCommentsGetKlass()
            },
            Self::ExclusiveC14N => unsafe { bindings::xmlSecTransformExclC14NGetKlass() },
            Self::ExclusiveC14NWithComments => unsafe {
                bindings::xmlSecTransformExclC14NWithCommentsGetKlass()
            },
            Self::Sha1 => unsafe { bindings::xmlSecOpenSSLTransformSha1GetKlass() },
            Self::Base64 => unsafe { bindings::xmlSecTransformBase64GetKlass() },
        }
    }
}

#[allow(missing_docs)]
pub enum XmlSecTransformOperation {
    None = 0,
    Encode = 1,
    Decode = 2,
    Sign = 3,
    Verify = 4,
    Encrypt = 5,
    Decrypt = 6,
}

/// context for transformations
pub struct XmlSecTransformCtx {
    ctx: *mut bindings::xmlSecTransformCtx,
}

impl XmlSecTransformCtx {
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new() -> Self {
        crate::xmlsec::guarantee_xmlsec_init();
        let ctx = unsafe { bindings::xmlSecTransformCtxCreate() };

        if ctx.is_null() {
            panic!("Failed to create dsig context");
        }
        Self { ctx }
    }

    /// Appends a transformation to the context
    pub fn append(&mut self, transform: XmlSecTransform) {
        unsafe {
            bindings::xmlSecTransformCtxAppend(self.ctx, transform.ctx);
            std::mem::forget(transform);
        }
    }

    /// Executes the transformation
    pub fn xml_execute(&mut self, node_set: &XmlSecNodeSet) -> XmlSecResult<&[u8]> {
        let node_ptr = node_set.nodeset_ptr() as *mut bindings::xmlSecNodeSet;
        let res = unsafe { bindings::xmlSecTransformCtxXmlExecute(self.ctx, node_ptr) };
        if res == 0 {
            let data = unsafe {
                let s = bindings::xmlSecBufferGetSize((*self.ctx).result);
                let p = bindings::xmlSecBufferGetData((*self.ctx).result);

                if p.is_null() || s == 0 {
                    return Err(XmlSecError::EmptyResultError);
                }

                std::slice::from_raw_parts(p, s)
            };
            Ok(data)
        } else {
            Err(XmlSecError::TransformError)
        }
    }
}

/// Transformation
pub struct XmlSecTransform {
    ctx: *mut bindings::xmlSecTransform,
}

impl XmlSecTransform {
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new(method: XmlSecCanonicalizationMethod) -> Self {
        crate::xmlsec::guarantee_xmlsec_init();
        let method = method.to_method();
        let ctx = unsafe { bindings::xmlSecTransformCreate(method) };
        if !XmlSecTransform::is_transform_valid(ctx) {
            panic!("Failed to create tranform");
        }

        Self { ctx }
    }

    /// Builds a context and sets the operation.
    pub fn with_operation(
        method: XmlSecCanonicalizationMethod,
        operation: XmlSecTransformOperation,
    ) -> Self {
        let mut trans = Self::new(method);
        trans.set_operation(operation);
        trans
    }

    /// Sets the operation.
    pub fn set_operation(&mut self, operation: XmlSecTransformOperation) -> &mut Self {
        unsafe {
            (*self.ctx).operation = operation as bindings::xmlSecTransformOperation;
        }
        self
    }

    fn is_transform_valid(transform: *mut bindings::xmlSecTransform) -> bool {
        /*
        #define xmlSecTransformIsValid(transform) \
                ((( transform ) != NULL) && \
                 (( transform )->id != NULL) && \
                 (( transform )->id->klassSize >= sizeof(xmlSecTransformKlass)) && \
                 (( transform )->id->objSize >= sizeof(xmlSecTransform)) && \
                 (( transform )->id->name != NULL))
                 */
        unsafe {
            if transform.is_null() || (*transform).id.is_null() {
                return false;
            }
            let id = *(*transform).id;
            if id.klassSize < std::mem::size_of::<bindings::xmlSecTransformKlass>()
                || id.objSize < std::mem::size_of::<bindings::xmlSecTransform>()
                || id.name.is_null()
            {
                return false;
            }
            true
        }
    }
}

impl Drop for XmlSecTransform {
    fn drop(&mut self) {
        unsafe {
            bindings::xmlSecTransformDestroy(self.ctx);
        }
    }
}

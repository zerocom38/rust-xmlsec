//!
//! Wrapper for XmlSec Signature Context
//!
use crate::XmlSecKeyFormat;
use crate::bindings;

use crate::XmlSecError;
use crate::XmlSecKey;
use crate::XmlSecResult;

use crate::XmlDocument;
use crate::XmlNode;

use std::ffi::CString;
use std::os::raw::c_uchar;
use std::ptr::null_mut;

/// Signature signing/veryfying context
pub struct XmlSecKeysMngr(*mut bindings::xmlSecKeysMngr);

impl XmlSecKeysMngr {
    /// Builds a context, ensuring xmlsec is initialized.
    pub fn new() -> Self {
        crate::xmlsec::guarantee_xmlsec_init();

        let keys_mngr = unsafe { bindings::xmlSecKeysMngrCreate() };

        if keys_mngr.is_null() {
            panic!("Failed to create keysManager");
        }

        Self(keys_mngr)
    }

    pub unsafe fn as_ptr(&self) -> *mut bindings::xmlSecKeysMngr {
        self.0
    }

    pub fn cert_load_from_memory(self: &Self, data: &[u8], format: XmlSecKeyFormat) -> XmlSecResult<()> {
        let data_size: u64= data.len() as u64;
        match unsafe{ bindings::xmlSecOpenSSLAppKeysMngrCertLoadMemory(self.0, data.as_ptr() , data_size, format as i32, bindings::xmlSecKeyDataTypeTrusted)} {
            0 => Ok(()),
            _ => Err(XmlSecError::CertLoadError)
        }
    }
}

impl Drop for XmlSecKeysMngr {
    fn drop(&mut self) {
        unsafe { bindings::xmlSecKeysMngrDestroy(self.0) };
    }
}

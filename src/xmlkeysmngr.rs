//!
//! Wrapper for XmlSec Signature Context
//!
use crate::bindings;
use crate::XmlSecKeyFormat;

use crate::XmlSecError;
use crate::XmlSecResult;

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

        unsafe {
            if bindings::xmlSecOpenSSLAppDefaultKeysMngrInit(keys_mngr) < 0 {
                panic!("Failed to init keysManager");
            }
        }

        Self(keys_mngr)
    }

    /// # Safety
    ///
    /// Returns a raw pointer to the underlying xmlsec structure.
    pub(crate) unsafe fn as_ptr(&self) -> *mut bindings::xmlSecKeysMngr {
        self.0
    }

    /// Load certificate from memory and store it in keys manager
    pub fn cert_load_from_memory(&self, data: &[u8], format: XmlSecKeyFormat) -> XmlSecResult<()> {
        let data_size = data.len();
        match unsafe {
            bindings::xmlSecOpenSSLAppKeysMngrCertLoadMemory(
                self.0,
                data.as_ptr(),
                data_size,
                format.into_raw(),
                bindings::xmlSecKeyDataTypeTrusted,
            )
        } {
            0 => Ok(()),
            _ => Err(XmlSecError::CertLoadError),
        }
    }
}

impl Drop for XmlSecKeysMngr {
    fn drop(&mut self) {
        unsafe { bindings::xmlSecKeysMngrDestroy(self.0) };
    }
}

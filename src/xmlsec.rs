//!
//! Central XmlSec1 Context
//!
use log::RecordBuilder;

use crate::bindings;

use crate::lazy_static;

use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::ptr::null;
use std::sync::Mutex;

lazy_static! {
    static ref XMLSEC: Mutex<Option<XmlSecContext>> = Mutex::new(None);
}

use std::cell::RefCell;
thread_local! {
    static LAST_ERROR_REASON: RefCell<i32> = RefCell::new(0);
}

/// XmlSec Error Reason
#[derive(Debug, Copy, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum XmlSecErrorReason {
    NoError,
    Unknown,
    XmlSecFailed,
    MallocFailed,
    StrdupFailed,
    CryptoFailed,
    XmlFailed,
    XsltFailed,
    IoFailed,
    Disabled,
    NotImplemented,
    InvalidConfig,
    InvalidSize,
    InvalidData,
    InvalidResult,
    InvalidType,
    InvalidOperation,
    InvalidStatus,
    InvalidFormat,
    DataNotMatch,
    InvalidVersion,
    InvalidNode,
    InvalidNodeContent,
    InvalidNodeAttribute,
    MissingNodeAttribute,
    NodeAlreadyPresent,
    UnexpectedNode,
    NodeNotFound,
    InvalidTransform,
    InvalidTransformKey,
    InvalidUriType,
    TransformSameDocumentRequired,
    TransformDisabled,
    InvalidAlgorithm,
    InvalidKeyData,
    KeyDataNotFound,
    KeyDataAlreadyExist,
    InvalidKeyDataSize,
    KeyNotFound,
    KeyDataDisabled,
    MaxRetrievalsLevel,
    MaxRetrievalTypeMismatch,
    MaxEncKeyLevel,
    CertVerifyFailed,
    CertNotFound,
    CertRevoked,
    CertIssuerFailed,
    CertNotYetValid,
    CertHasExpired,
    CrlVerifyFailed,
    CrlNotYetValid,
    CrlHasExpired,
    DsigNoReferences,
    DsigInvalidReference,
    Assertion,
    CastImpossible,
}

// create From<i32> for XmlSecErrorReason
impl From<i32> for XmlSecErrorReason {
    fn from(reason: i32) -> Self {
        match reason {
            0 => XmlSecErrorReason::NoError,
            1 => XmlSecErrorReason::XmlSecFailed,
            2 => XmlSecErrorReason::MallocFailed,
            3 => XmlSecErrorReason::StrdupFailed,
            4 => XmlSecErrorReason::CryptoFailed,
            5 => XmlSecErrorReason::XmlFailed,
            6 => XmlSecErrorReason::XsltFailed,
            7 => XmlSecErrorReason::IoFailed,
            8 => XmlSecErrorReason::Disabled,
            9 => XmlSecErrorReason::NotImplemented,
            10 => XmlSecErrorReason::InvalidConfig,
            11 => XmlSecErrorReason::InvalidSize,
            12 => XmlSecErrorReason::InvalidData,
            13 => XmlSecErrorReason::InvalidResult,
            14 => XmlSecErrorReason::InvalidType,
            15 => XmlSecErrorReason::InvalidOperation,
            16 => XmlSecErrorReason::InvalidStatus,
            17 => XmlSecErrorReason::InvalidFormat,
            18 => XmlSecErrorReason::DataNotMatch,
            19 => XmlSecErrorReason::InvalidVersion,
            21 => XmlSecErrorReason::InvalidNode,
            22 => XmlSecErrorReason::InvalidNodeContent,
            23 => XmlSecErrorReason::InvalidNodeAttribute,
            25 => XmlSecErrorReason::MissingNodeAttribute,
            26 => XmlSecErrorReason::NodeAlreadyPresent,
            27 => XmlSecErrorReason::UnexpectedNode,
            28 => XmlSecErrorReason::NodeNotFound,
            31 => XmlSecErrorReason::InvalidTransform,
            32 => XmlSecErrorReason::InvalidTransformKey,
            33 => XmlSecErrorReason::InvalidUriType,
            34 => XmlSecErrorReason::TransformSameDocumentRequired,
            35 => XmlSecErrorReason::TransformDisabled,
            36 => XmlSecErrorReason::InvalidAlgorithm,
            41 => XmlSecErrorReason::InvalidKeyData,
            42 => XmlSecErrorReason::KeyDataNotFound,
            43 => XmlSecErrorReason::KeyDataAlreadyExist,
            44 => XmlSecErrorReason::InvalidKeyDataSize,
            45 => XmlSecErrorReason::KeyNotFound,
            46 => XmlSecErrorReason::KeyDataDisabled,
            51 => XmlSecErrorReason::MaxRetrievalsLevel,
            52 => XmlSecErrorReason::MaxRetrievalTypeMismatch,
            61 => XmlSecErrorReason::MaxEncKeyLevel,
            71 => XmlSecErrorReason::CertVerifyFailed,
            72 => XmlSecErrorReason::CertNotFound,
            73 => XmlSecErrorReason::CertRevoked,
            74 => XmlSecErrorReason::CertIssuerFailed,
            75 => XmlSecErrorReason::CertNotYetValid,
            76 => XmlSecErrorReason::CertHasExpired,
            77 => XmlSecErrorReason::CrlVerifyFailed,
            78 => XmlSecErrorReason::CrlNotYetValid,
            79 => XmlSecErrorReason::CrlHasExpired,
            81 => XmlSecErrorReason::DsigNoReferences,
            82 => XmlSecErrorReason::DsigInvalidReference,
            100 => XmlSecErrorReason::Assertion,
            101 => XmlSecErrorReason::CastImpossible,
            _ => XmlSecErrorReason::Unknown,
        }
    }
}

/// Returns the last error that occurred in the library
pub fn last_error() -> XmlSecErrorReason {
    let mut reason = 0;
    LAST_ERROR_REASON.with(|v| reason = *v.borrow());
    reason.into()
}

/// Reset last error to no error
pub fn clear_last_error() {
    LAST_ERROR_REASON.with(|v| *v.borrow_mut() = 0);
}

unsafe extern "C" fn error_callback(
    file: *const c_char,
    line: c_int,
    func: *const c_char,
    error_object: *const c_char,
    error_subject: *const c_char,
    reason: c_int,
    msg: *const c_char,
) {
    let error_msg = {
        let mut i = 0;
        loop {
            let error_msg = bindings::xmlSecErrorsGetMsg(i);
            if error_msg.is_null() {
                break error_msg;
            }
            if bindings::xmlSecErrorsGetCode(i) == reason {
                break error_msg;
            }
            i += 1;
        }
    };

    LAST_ERROR_REASON.with_borrow_mut(|v| *v = reason);

    log::logger().log(
        &RecordBuilder::new()
            .args(format_args!(
                "func={}:obj={}:subj={}:error={}:{}:{}",
                str_or_default(func, "unknown"),
                str_or_default(error_object, "unknown"),
                str_or_default(error_subject, "unknown"),
                reason,
                str_or_default(error_msg, ""),
                str_or_default(msg, ""),
            ))
            .level(log::Level::Error)
            .module_path_static(Some("xmlsec"))
            .target("libxmlsec1")
            .file(Some(str_or_default(file, "")))
            .line(Some(line as u32))
            .build(),
    );
}

fn str_or_default<'a>(file: *const i8, default: &'static str) -> &'a str {
    if file.is_null() {
        default
    } else {
        let file_str = unsafe { CStr::from_ptr(file as *const c_char) };
        file_str.to_str().unwrap()
    }
}

pub fn guarantee_xmlsec_init() {
    let mut inner = XMLSEC
        .lock()
        .expect("Unable to lock global xmlsec initalization wrapper");

    let ver = unsafe { *openssl_sys::OpenSSL_version(0) };
    if ver < 1 {
        panic!("OpenSSL version 1.0.0 or higher is required");
    }

    if inner.is_none() {
        *inner = Some(XmlSecContext::new());
    }

    unsafe {
        bindings::xmlSecErrorsSetCallback(Some(error_callback));
    }
}

/// XmlSec Global Context
///
/// This object initializes the underlying xmlsec global state and cleans it
/// up once gone out of scope. It is checked by all objects in the library that
/// require the context to be initialized. See [`globals`][globals].
///
/// [globals]: globals
struct XmlSecContext {}

impl XmlSecContext {
    /// Runs xmlsec initialization and returns instance of itself.
    pub fn new() -> Self {
        init_xmlsec();
        init_crypto_app();
        init_crypto();

        Self {}
    }
}

impl Drop for XmlSecContext {
    fn drop(&mut self) {
        cleanup_crypto();
        cleanup_crypto_app();
        cleanup_xmlsec();
    }
}

/// Init xmlsec library
fn init_xmlsec() {
    let rc = unsafe { bindings::xmlSecInit() };

    if rc < 0 {
        panic!("XmlSec failed initialization");
    }
}

/// Load default crypto engine if we are supporting dynamic loading for
/// xmlsec-crypto libraries. Use the crypto library name ("openssl",
/// "nss", etc.) to load corresponding xmlsec-crypto library.
fn init_crypto_app() {
    // if bindings::XMLSEC_CRYPTO_DYNAMIC_LOADING
    // {
    //     let rc = unsafe { bindings::xmlSecCryptoDLLoadLibrary(0) };

    //     if rc < 0 {
    //         panic!("XmlSec failed while loading default crypto backend. \
    //                 Make sure that you have it installed and check shread libraries path");
    //     }
    // }

    let rc = unsafe { bindings::xmlSecOpenSSLAppInit(null()) };

    if rc < 0 {
        panic!("XmlSec failed to init crypto backend")
    }
}

/// Init xmlsec-crypto library
fn init_crypto() {
    let rc = unsafe { bindings::xmlSecOpenSSLInit() };

    if rc < 0 {
        panic!(
            "XmlSec failed while loading default crypto backend. \
               Make sure that you have it installed and check shread libraries path"
        );
    }
}

/// Shutdown xmlsec-crypto library
fn cleanup_crypto() {
    unsafe { bindings::xmlSecOpenSSLShutdown() };
}

/// Shutdown crypto library
fn cleanup_crypto_app() {
    unsafe { bindings::xmlSecOpenSSLAppShutdown() };
}

/// Shutdown xmlsec library
fn cleanup_xmlsec() {
    unsafe { bindings::xmlSecShutdown() };
}

//!
//! XmlSec Bindings Generation
//!
use bindgen::Builder as BindgenBuilder;

use std::env;
use std::path::PathBuf;
use std::process::Command;

const BINDINGS: &str = "bindings.rs";

fn main() {
    //   println!("cargo:rustc-link-lib=xmlsec1-openssl"); // -lxmlsec1-openssl
    //    println!("cargo:rustc-link-lib=xmlsec1"); // -lxmlsec1
    //    println!("cargo:rustc-link-lib=xml2"); // -lxml2
    //    println!("cargo:rustc-link-lib=ssl"); // -lssl
    //    println!("cargo:rustc-link-lib=crypto"); // -lcrypto

    let path_out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let path_bindings = path_out.join(BINDINGS);

    if !path_bindings.exists() {
        let mut flags: Vec<String> = Vec::new();
        let mut includes: Vec<PathBuf> = Vec::new();

        #[cfg(any(target_family = "unix", target_os = "macos"))]
        {
            if pkg_config_dep::find() {
                return;
            }
        }

        #[cfg(windows)]
        {
            vcpkg_dep::find(&mut flags, &mut includes);
        }
        let inc_strs: Vec<String> = includes
            .iter()
            .map(|inc| format!("-I{}", inc.display()))
            .collect();
        //        println!("INCS: {:?}", inc_strs);

        let bindbuild = BindgenBuilder::default()
            .header("bindings.h")
            .clang_args(flags)
            .clang_args(inc_strs)
            .layout_tests(true)
            .rustfmt_bindings(true)
            .generate_comments(true);

        let bindings = bindbuild.generate().expect("Unable to generate bindings");

        bindings
            .write_to_file(path_bindings)
            .expect("Couldn't write bindings!");
    }
}

#[cfg(any(target_family = "unix", target_os = "macos"))]
fn fetch_xmlsec_config_flags() -> Vec<String> {
    let out = Command::new("xmlsec1-config")
        .arg("--cflags")
        .output()
        .expect("Failed to get --cflags from xmlsec1-config. Is xmlsec1 installed?")
        .stdout;

    args_from_output(out)
}

#[cfg(target_family = "windows")]
fn fetch_xmlsec_config_flags() -> Vec<String> {
    Vec::new()
}

#[cfg(any(target_family = "unix", target_os = "macos"))]
fn fetch_xmlsec_config_libs() -> Vec<String> {
    let out = Command::new("xmlsec1-config")
        .arg("--libs")
        .output()
        .expect("Failed to get --libs from xmlsec1-config. Is xmlsec1 installed?")
        .stdout;

    args_from_output(out)
}

#[cfg(target_family = "windows")]
fn fetch_xmlsec_config_libs() -> Vec<String> {
    Vec::new()
}

fn args_from_output(args: Vec<u8>) -> Vec<String> {
    let decoded = String::from_utf8(args).expect("Got invalid UTF8 from xmlsec1-config");

    let args = decoded
        .split_whitespace()
        .map(|p| p.to_owned())
        .collect::<Vec<String>>();

    args
}

#[cfg(any(target_family = "unix", target_os = "macos"))]
mod pkg_config_dep {
    pub fn find() -> bool {
        if pkg_config::find_library("xmlsec1").is_ok() {
            return true;
        }
        false
    }
}

#[cfg(target_family = "windows")]
mod vcpkg_dep {
    use std::path::PathBuf;

    pub fn find(flags: &mut Vec<String>, includes: &mut Vec<PathBuf>) {
        let lib = vcpkg::find_package("xmlsec").unwrap();
        let defs: Vec<String> = vec![
            //            "-DXMLSEC_STATIC".to_string(),
            //            "-DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING".to_string(),
            "-DXMLSEC_CRYPTO_DYNAMIC_LOADING".to_string(),
            "-DXMLSEC_DEFAULT_CRYPTO=\"openssl\"".to_string(),
            "-DXMLSEC_CRYPTO_OPENSSL=1".to_string(),
            "-DOPENSSL_NO_GOST".to_string(),
            "-DXMLSEC_NO_XSLT".to_string(),
            "-DXMLSEC_DL_WIN32".to_string(),
            "-DXMLSEC_DL_LIBLTDL".to_string(),
            "-D_WIN32".to_string(),
        ];
        *includes = lib.include_paths;
        *flags = defs;
    }
}

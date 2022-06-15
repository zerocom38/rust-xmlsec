//!
//! XmlSec Bindings Generation
//!
//use bindgen::Builder as BindgenBuilder;

use bindgen::Builder as BindgenBuilder;
use std::collections::HashMap;
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

const BINDINGS: &str = "bindings.rs";

fn main() {
    if let Ok(ref s) = std::env::var("LIBXML2") {
        // println!("{:?}", std::env::vars());
        // panic!("set libxml2.");
        let p = std::path::Path::new(s);
        let fname = std::path::Path::new(p.file_name().expect("no file name in LIBXML2 env"));
        assert!(p.is_file());
        println!(
            "cargo:rustc-link-lib={}",
            fname
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .strip_prefix("lib")
                .unwrap()
        );
        println!(
            "cargo:rustc-link-search={}",
            p.parent()
                .expect("no library path in LIBXML2 env")
                .to_string_lossy()
        );
    } else {
        #[cfg(any(target_family = "unix", target_os = "macos"))]
        {
            if !libxml2_pkg_config_dep::find() {
                panic!("Could not find libxml2.");
            }
        }

        let mut libxml2_flags: Vec<String> = Vec::new();
        let mut libxml2_includes: Vec<PathBuf> = Vec::new();
        #[cfg(windows)]
        {
            libxml2_vcpkg_dep::find(&mut libxml2_flags, &mut libxml2_includes);
        }

        let mut libxml2_inc_strs: Vec<String> = libxml2_includes
            .iter()
            .map(|inc| format!("{}", inc.display()))
            .collect();

        vcpkg::find_package("openssl").unwrap();
        //        println!("INCS: {:?}", libxml2_inc_strs);
        //   println!("cargo:rustc-link-lib=xmlsec1-openssl"); // -lxmlsec1-openssl
        //    println!("cargo:rustc-link-lib=xmlsec1"); // -lxmlsec1
        //    println!("cargo:rustc-link-lib=xml2"); // -lxml2
        //    println!("cargo:rustc-link-lib=ssl"); // -lssl
        //    println!("cargo:rustc-link-lib=crypto"); // -lcrypto

        /*
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
                     let needs_bindgen = false;
                    if needs_bindgen {
                        let inc_strs: Vec<String> = includes
                            .iter()
                            .map(|inc| format!("-I{}", inc.display()))
                            .collect();
                        //        println!("INCS: {:?}", inc_strs);

                        let bindbuild = BindgenBuilder::default()
                            .header("bindings.h")
                            .clang_args(flags)
                            .clang_args(inc_strs)
                            //            .layout_tests(true)
                            .rustfmt_bindings(true)
                            .generate_comments(true);

                        let bindings = bindbuild.generate().expect("Unable to generate bindings");

                        bindings
                            .write_to_file(path_bindings)
                            .expect("Couldn't write bindings!");
                    }
                    println!("cargo:rerun-if-changed=build.rs");
                    println!("cargo:rerun-if-changed=path/to/Cargo.lock");
                    */

        //        println!("cargo:rustc-link-search=native=C:\\dev\\vcpkg\\installed\\x64-windows\\lib");
        //        println!("cargo:rustc-link-search=native=C:\\dev\\vcpkg\\installed\\x64-windows\\bin");
        //        println!("cargo:rustc-link-lib=xmlsec1-openssl");
        //        println!("cargo:rustc-link-lib=xmlsec1");

        //                    "-DXMLSEC_CRYPTO_DYNAMIC_LOADING".to_string(),
        //            "-DXMLSEC_DEFAULT_CRYPTO=\"openssl\"".to_string(),
        //            "-DXMLSEC_CRYPTO_OPENSSL=1".to_string(),
        //            "-DOPENSSL_NO_GOST".to_string(),
        //            "-DXMLSEC_NO_XSLT".to_string(),
        //            "-DXMLSEC_DL_WIN32".to_string(),
        //            "-DXMLSEC_DL_LIBLTDL".to_string(),

        let xmlsec_sources: Vec<&str> = vec![
            "xmlsec/src/app.c",
            "xmlsec/src/base64.c",
            "xmlsec/src/bn.c",
            "xmlsec/src/buffer.c",
            "xmlsec/src/c14n.c",
            "xmlsec/src/dl.c",
            "xmlsec/src/enveloped.c",
            "xmlsec/src/errors.c",
            "xmlsec/src/io.c",
            "xmlsec/src/keyinfo.c",
            "xmlsec/src/keys.c",
            "xmlsec/src/keysdata.c",
            "xmlsec/src/keysmngr.c",
            "xmlsec/src/kw_aes_des.c",
            "xmlsec/src/list.c",
            "xmlsec/src/membuf.c",
            "xmlsec/src/nodeset.c",
            "xmlsec/src/parser.c",
            "xmlsec/src/relationship.c",
            "xmlsec/src/soap.c",
            "xmlsec/src/strings.c",
            "xmlsec/src/templates.c",
            "xmlsec/src/transforms.c",
            "xmlsec/src/x509.c",
            "xmlsec/src/xmldsig.c",
            "xmlsec/src/xmlenc.c",
            "xmlsec/src/xmlsec.c",
            "xmlsec/src/xmltree.c",
            "xmlsec/src/xpath.c",
            "xmlsec/src/xslt.c",
            "xmlsec/src/openssl/app.c",
            "xmlsec/src/openssl/bn.c",
            "xmlsec/src/openssl/ciphers.c",
            "xmlsec/src/openssl/crypto.c",
            "xmlsec/src/openssl/digests.c",
            "xmlsec/src/openssl/evp.c",
            "xmlsec/src/openssl/evp_signatures.c",
            "xmlsec/src/openssl/hmac.c",
            "xmlsec/src/openssl/kt_rsa.c",
            "xmlsec/src/openssl/kw_aes.c",
            "xmlsec/src/openssl/kw_des.c",
            "xmlsec/src/openssl/signatures.c",
            "xmlsec/src/openssl/symkeys.c",
            "xmlsec/src/openssl/x509.c",
            "xmlsec/src/openssl/x509vfy.c",
        ];

        let path_out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let path_bindings = path_out.join(BINDINGS);

        create_version_header().unwrap();

        let inc_strs: Vec<String> = libxml2_inc_strs
            .clone()
            .iter()
            .map(|inc| format!("-I{}", inc))
            .collect();

        cc::Build::new()
            .files(xmlsec_sources)
            .include("xmlsec/include")
            .include(&path_out)
            .includes(libxml2_inc_strs)
            .define("XMLSEC_NO_XSLT", "1")
            .define("XMLSEC_STATIC", "1")
            .define("XMLSEC_DEFAULT_CRYPTO", "\"openssl\"")
            .define("XMLSEC_CRYPTO_OPENSSL", "1")
            .define("XMLSEC_NO_CRYPTO_DYNAMIC_LOADING", "1")
            .compile("libxmlsec1-static.a");

        let defs: Vec<String> = vec![
            //            "-DXMLSEC_STATIC".to_string(),
            //            "-DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING".to_string(),
            "-DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING".to_string(),
            "-DXMLSEC_DEFAULT_CRYPTO=\"openssl\"".to_string(),
            "-DXMLSEC_CRYPTO_OPENSSL=1".to_string(),
            "-DXMLSEC_NO_XSLT".to_string(),
            "-DXMLSEC_STATIC".to_string(),
        ];

        let inc_path = format!("-I{}", path_out.to_string_lossy().to_string());

        let bindbuild = BindgenBuilder::default()
            .header("bindings.h")
            .clang_args(defs)
            .clang_args(["-Ixmlsec/include", inc_path.as_str()])
            .clang_args(inc_strs)
            .allowlist_var(r#"(\w*xmlSec\w*)"#)
            .allowlist_type(r#"(\w*xmlSec\w*)"#)
            .allowlist_function(r#"(\w*xmlSec\w*)"#)
            //            .layout_tests(true)
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

#[cfg(any(target_family = "unix", target_os = "macos"))]
mod libxml2_pkg_config_dep {
    pub fn find() -> bool {
        if pkg_config::find_library("libxml-2.0").is_ok() {
            return true;
        }
        false
    }
}

#[cfg(target_family = "windows")]
mod libxml2_vcpkg_dep {

    use std::path::PathBuf;
    pub fn find(flags: &mut Vec<String>, includes: &mut Vec<PathBuf>) {
        let lib = vcpkg::find_package("libxml2").unwrap();
        let defs: Vec<String> = vec![
            //            "-DXMLSEC_STATIC".to_string(),
            //            "-DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING".to_string(),
        ];
        *includes = lib.include_paths;
        *flags = defs;
    }
}

fn create_version_header() -> Result<(), std::io::Error> {
    let path_out = PathBuf::from(env::var("OUT_DIR").unwrap());

    match std::fs::create_dir_all(path_out.clone().join("xmlsec")) {
        Ok(_) => {}
        Err(e) => match e {
            e if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            _ => panic!("Cannot create output directory for version.h"),
        },
    };

    let config_reader = BufReader::new(std::fs::File::open("xmlsec/configure.ac").unwrap());
    let mut xml_major_version = String::default();
    let var_names = vec![
        "XMLSEC_VERSION_MAJOR",
        "XMLSEC_VERSION_MINOR",
        "XMLSEC_VERSION_SUBMINOR",
    ];
    let mut replace_map: HashMap<String, String> = HashMap::new();

    for line in config_reader.lines() {
        if let Ok(l) = line {
            let kv: Vec<&str> = l.split("=").collect();
            if kv.len() != 2 {
                continue;
            }
            if var_names.contains(&kv[0]) {
                replace_map.insert(kv[0].to_string(), kv[1].to_string());
            }
        }
    }

    replace_map.insert(
        "XMLSEC_VERSION".to_string(),
        format!(
            "{}.{}.{}",
            replace_map.get("XMLSEC_VERSION_MAJOR").unwrap(),
            replace_map.get("XMLSEC_VERSION_MINOR").unwrap(),
            replace_map.get("XMLSEC_VERSION_SUBMINOR").unwrap()
        ),
    );

    let xml_version_major_number: i32 = replace_map
        .get("XMLSEC_VERSION_MAJOR")
        .unwrap()
        .parse()
        .unwrap();
    let xml_version_minor_number: i32 = replace_map
        .get("XMLSEC_VERSION_MINOR")
        .unwrap()
        .parse()
        .unwrap();
    replace_map.insert(
        "XMLSEC_VERSION_INFO".to_string(),
        format!(
            "{}:{}:{}",
            xml_version_major_number + xml_version_minor_number,
            replace_map.get("XMLSEC_VERSION_SUBMINOR").unwrap(),
            replace_map.get("XMLSEC_VERSION_MINOR").unwrap()
        ),
    );

    let mut version_header = std::fs::read_to_string("xmlsec/include/xmlsec/version.h.in").unwrap();

    for vars in replace_map {
        let key = format!("@{}@", vars.0);
        version_header = version_header.replace(&key, &vars.1);
    }
    std::fs::write(
        path_out.clone().join("xmlsec").join("version.h"),
        version_header,
    )
    .unwrap();
    Ok(())
}

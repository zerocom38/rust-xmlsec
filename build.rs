//!
//! XmlSec Bindings Generation
//!
//use bindgen::Builder as BindgenBuilder;

use std::env;
use std::path::PathBuf;

const BINDINGS: &str = "bindings.rs";

fn main() {
    let mut defs: Vec<String> = Vec::new();
    let mut includes: Vec<PathBuf> = Vec::new();
    deps::find_xmlsec(&mut defs, &mut includes);

    let path_out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let path_bindings = path_out.join(BINDINGS);

    let inc_strs: Vec<String> = includes
        .clone()
        .iter()
        .map(|inc| format!("-I{}", inc.to_string_lossy()))
        .collect();

    #[cfg(feature = "bindgen")]
    {
        let bindbuild = bindgen::Builder::default()
            .header("bindings.h")
            .clang_args(defs)
            .clang_args(inc_strs)
            .allowlist_var(r#"(\w*xmlSec\w*)"#)
            .allowlist_type(r#"(\w*xmlSec\w*)"#)
            .allowlist_function(r#"(\w*xmlSec\w*)"#)
            //            .layout_tests(true)
            .generate_comments(true);

        let bindings = bindbuild.generate().expect("Unable to generate bindings");

        bindings
            .write_to_file(path_bindings)
            .expect("Couldn't write bindings!");
    }
}

mod deps {

    use std::path::PathBuf;

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn find_libxml(flags: &mut Vec<String>, includes: &mut Vec<PathBuf>) {
        let lib = pkg_config::find_library("libxml-2.0").unwrap();
        let defs: Vec<String> = vec![];
        assert!(
            !lib.include_paths.is_empty(),
            "Libxml2 includes not found, not correctly installed!"
        );
        *includes = lib.include_paths;
        *flags = defs;
    }

    #[cfg(target_os = "windows")]
    pub fn find_libxml(flags: &mut Vec<String>, includes: &mut Vec<PathBuf>) {
        let lib = vcpkg::find_package("libxml2").expect("Libxml2 includes not found");

        let defs: Vec<String> = vec![];
        assert!(
            !lib.include_paths.is_empty(),
            "Libxml2 includes not found, not correctly installed!"
        );
        *includes = lib.include_paths;
        *flags = defs;
    }

    #[cfg(not(feature = "vendored"))]
    pub fn find_xmlsec(flags: &mut Vec<String>, includes: &mut Vec<PathBuf>) {
        let lib = pkg_config::find_library("xmlsec1").unwrap();
        let defs: Vec<String> = lib
            .defines
            .iter()
            .map(|d| match d.1 {
                None => format!("-D{}", d.0),
                Some(v) => format!("-D{}={}", d.0, v),
            })
            .collect();
        println!("XMLSEC LIBS: {:?} -> {:?}", lib.include_paths, defs);
        *includes = lib.include_paths;
        *flags = defs;
    }

    #[cfg(any(feature = "vendored", target_os = "windows"))]
    pub fn find_xmlsec(flags: &mut Vec<String>, includes: &mut Vec<PathBuf>) {
        crate::vendored::compile_xmlsec(flags, includes);
    }

    // #[cfg(target_os = "windows")]
    // pub fn find_openssl(flags: &mut Vec<String>, includes: &mut Vec<PathBuf>) {
    //     if let Ok(_) = vcpkg::find_package("openssl") {
    //         // Set environment variables for openssl-sys
    //         let openssl_inc_dir = "C:/vcpkg/installed/x64-windows/include".to_string();
    //         println!("cargo:rustc-link-lib=ssl");
    //         println!("cargo:rustc-link-lib=crypto");
    //         println!("cargo:include={}", openssl_inc_dir);
    //         return Some(openssl_inc_dir);
    //     }
    // }

    pub fn find_openssl(_flags: &mut Vec<String>, includes: &mut Vec<PathBuf>) {
        let openssl_inc_dir = std::env::var("DEP_OPENSSL_INCLUDE").expect("openssl-sys not found");

        includes.push(openssl_inc_dir.into());
    }
}

#[cfg(feature = "vendored")]
mod vendored {
    use std::{
        collections::HashMap,
        env,
        io::{BufRead, BufReader},
        path::PathBuf,
    };

    use crate::deps;

    pub fn compile_xmlsec(flags: &mut Vec<String>, includes: &mut Vec<PathBuf>) {
        let mut openssl_flags: Vec<String> = Vec::new();
        let mut openssl_includes: Vec<PathBuf> = Vec::new();
        deps::find_openssl(&mut openssl_flags, &mut openssl_includes);

        let mut libxml2_flags: Vec<String> = Vec::new();
        let mut libxml2_includes: Vec<PathBuf> = Vec::new();
        deps::find_libxml(&mut libxml2_flags, &mut libxml2_includes);
        //        deps::find_openssl(&mut libxml2_flags, &mut libxml2_includes);
        //        let openssl_include_path = std::env::var("DEP_OPENSSL_INCLUDE").unwrap();
        includes.extend(openssl_includes);
        includes.extend(libxml2_includes);

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
            "xmlsec/src/strings.c",
            "xmlsec/src/templates.c",
            "xmlsec/src/transforms.c",
            "xmlsec/src/xmldsig.c",
            "xmlsec/src/xmlenc.c",
            "xmlsec/src/xmlsec.c",
            "xmlsec/src/xmltree.c",
            "xmlsec/src/xpath.c",
            "xmlsec/src/xslt.c",
            "xmlsec/src/openssl/app.c",
            "xmlsec/src/openssl/ciphers.c",
            "xmlsec/src/openssl/crypto.c",
            "xmlsec/src/openssl/digests.c",
            "xmlsec/src/openssl/evp.c",
            "xmlsec/src/openssl/hmac.c",
            "xmlsec/src/openssl/kdf.c",
            "xmlsec/src/openssl/key_agrmnt.c",
            "xmlsec/src/openssl/keysstore.c",
            "xmlsec/src/openssl/kt_rsa.c",
            "xmlsec/src/openssl/kw_aes.c",
            "xmlsec/src/openssl/kw_des.c",
            "xmlsec/src/openssl/signatures.c",
            "xmlsec/src/openssl/symkeys.c",
            "xmlsec/src/openssl/x509.c",
            "xmlsec/src/openssl/x509vfy.c",
        ];

        create_version_header().unwrap();

        let path_out = PathBuf::from(env::var("OUT_DIR").unwrap());
        let mut path_xmlsec = std::env::current_dir().unwrap();
        path_xmlsec.push("xmlsec");
        path_xmlsec.push("include");

        includes.push(path_out);
        includes.push(path_xmlsec);

        let inc_strs: Vec<String> = includes
            .clone()
            .iter()
            .map(|inc| inc.to_str().unwrap().to_string())
            .collect();

        println!("XMLSEC INCLUDES: {:?}", inc_strs);

        cc::Build::new()
            .files(xmlsec_sources)
            .includes(inc_strs)
            .define("XMLSEC_NO_XSLT", "1")
            .define("XMLSEC_STATIC", "1")
            .define("XMLSEC_DEFAULT_CRYPTO", "\"openssl\"")
            .define("XMLSEC_CRYPTO_OPENSSL", "1")
            .define("XMLSEC_NO_CRYPTO_DYNAMIC_LOADING", "1")
            .flag_if_supported("-wd4130")
            .compile("libxmlsec1-static.a");

        let defs: Vec<String> = vec![
            "-DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING".to_string(),
            "-DXMLSEC_DEFAULT_CRYPTO=\"openssl\"".to_string(),
            "-DXMLSEC_CRYPTO_OPENSSL=1".to_string(),
            "-DXMLSEC_NO_XSLT".to_string(),
            "-DXMLSEC_STATIC".to_string(),
        ];
        *flags = defs;
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
        let var_names = [
            "XMLSEC_VERSION_MAJOR",
            "XMLSEC_VERSION_MINOR",
            "XMLSEC_VERSION_SUBMINOR",
        ];
        let mut replace_map: HashMap<String, String> = HashMap::new();

        for line in config_reader.lines() {
            if let Ok(l) = line {
                let kv: Vec<&str> = l.split('=').collect();
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

        let mut version_header =
            std::fs::read_to_string("xmlsec/include/xmlsec/version.h.in").unwrap();

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
}

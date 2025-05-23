use std::path::Path;
use std::{env, fs};

fn main() -> anyhow::Result<()> {
    // Compile protos
    let out_dir = Path::new(env::var("OUT_DIR")?.as_str()).join("protos");
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir)?;
    }
    fs::create_dir_all(&out_dir)?;
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut prost_config = prost_build::Config::new();
    prost_config.protoc_executable(protoc);
    prost_config.out_dir(out_dir);
    prost_config.compile_protos(&["protos/common.proto"], &[""])?;
    prost_config.extern_path(".common", "crate::protos");
    prost_config.compile_protos(&["protos/objects.proto"], &[""])?;
    prost_config.extern_path(".objects", "crate::objects::protos");
    prost_config.compile_protos(&["protos/manifest.proto"], &[""])?;
    prost_config.extern_path(".manifest", "crate::manifest::protos");
    prost_config.compile_protos(&["protos/keyring.proto"], &[""])?;
    prost_config.extern_path(".keyring", "crate::crypto::keyring::protos");
    prost_config.compile_protos(&["protos/announcement.proto"], &[""])?;
    prost_config.extern_path(".announcement", "crate::announcement::protos");
    println!("cargo:rerun-if-changed=protos");
    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}

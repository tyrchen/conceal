fn main() {
    let mut config = prost_build::Config::default();
    config.out_dir("src/protos");

    config
        .compile_protos(&["../protos/header.proto"], &["../protos"])
        .unwrap_or_else(|e| panic!("Failed to compile proto files. Error: {:?}", e));
}

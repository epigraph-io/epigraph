fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false) // Client only - Python runs the server
        .build_client(true)
        .out_dir("src/proto")
        .compile(&["../../proto/harvester.proto"], &["../../proto"])?;
    Ok(())
}

Fixture for tests/table_graph_discover_tests.rs: a directory under the sibling
checkout's crates/ that holds no Cargo.toml, so the crate scan must not list
it. (A fixture Cargo.toml is avoided on purpose: whole-tree manifest scans
would read it.)

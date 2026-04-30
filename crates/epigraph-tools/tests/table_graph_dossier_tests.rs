#[path = "../examples/table_graph/dossier.rs"]
mod dossier;
#[path = "../examples/table_graph/types.rs"]
mod types;

use dossier::collect_ddl;

#[test]
fn ddl_for_claims_includes_create_table() {
    let ddl = collect_ddl("/home/jeremy/epigraph/migrations", "claims").unwrap();
    assert!(ddl.contains("CREATE TABLE"), "missing CREATE TABLE for claims");
    assert!(ddl.contains("claims"), "DDL should mention 'claims'");
}

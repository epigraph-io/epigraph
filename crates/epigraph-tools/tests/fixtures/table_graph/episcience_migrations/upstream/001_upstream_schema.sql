-- Fixture for table_graph_discover_tests: a vendored copy of another
-- repository's schema. `claims` belongs to epigraph, so a scan that passes
-- `upstream` as a skip directory must not attribute it to this repository.
CREATE TABLE claims (
    id UUID PRIMARY KEY
);

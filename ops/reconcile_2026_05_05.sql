-- ops/reconcile_2026_05_05.sql
-- ONE-SHOT, run by hand against prod with `pg_dump -Fc` backup first.
-- Lives outside migrations/ so sqlx::migrate! does not pick it up.
-- Brings _sqlx_migrations into agreement with the public-repo numbering
-- so future `sqlx migrate run --source ./migrations` is incremental.
--
-- Checksums are sha384 of the raw migration SQL bytes (sqlx 0.7 stores
-- BYTEA, not hex text). Generated via:
--     sha384sum migrations/NNN_*.sql
-- on 2026-05-05 against the public-repo migration files at HEAD of
-- feat/api-migration-runner.
BEGIN;
TRUNCATE _sqlx_migrations;
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (1, 'initial_schema', NOW(), true, decode('f65a8e9f11671d78b1001247f66f879e88aa592db007caa581f8cb102593c1be57fd980d72e2f74800168fe958f8955b', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (2, 'behavioral_executions', NOW(), true, decode('6bdc9b8e29a2b011a885ffc1c3a1bc03a1ae6595c26610707159865ebdb2ee298339c369220f61c128aef5dfebf5dcff', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (3, 'business_function_entity_type', NOW(), true, decode('aa559da69128e6ff06ea330d8af20762f71929c22f5d59da580363c82469874b448611089b88d1305aa1ac1b7d4b7a90', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (4, 'stop_truth_value_overwrite', NOW(), true, decode('d8c567fcf3ba80ab2a2ee014c88603d1730e8a7afe3c8899444528f99908cfb6230eef25d701b840f182bd8c9ec46284', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (5, 'task_event_edge_types', NOW(), true, decode('6accd5f0c547c8c86869d7a22d3092c7178dadae21a36ff09c1128b194fca5c6187c7d328b74774d07481502bc2205dc', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (6, 'provenance_patch_payload', NOW(), true, decode('4b19c433d0a6d879f50280714e411f0c2d1c36fb8007de8b787ef0fce1f413c204875ea86942c420dd6af6b6ebd61ae4', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (7, 'papers_doi_unique_constraint', NOW(), true, decode('634c46fc496025198f429f5742bc14a14fc9e6d302fa936ac7b07bd2b9c29fd666b6f553f84b01c5183a0af999b6343a', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (8, 'claim_signature_revocations', NOW(), true, decode('603835a2a746535693e1eeb129663549385ee601ff4707162bb39fc809a91f71b34cd211d202cc04fc193a42e10d308d', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (9, 'conflict_taxonomy', NOW(), true, decode('83e0d38646d1fe06c080a9c1971a54234bbd3cca80d1c3ee7acdad28b353eeae761694876b5310e865c49e927008243a', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (10, 'divergence_cache_validity_constraints', NOW(), true, decode('c517b75efe69cddca694ca06eff922aca7dc5dc19a226d369b88afe235e6f5a590720ed21ce964213ab850c35e70c5af', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (11, 'derived_from_uppercase_factor', NOW(), true, decode('8e6bf4406c62ef6e1556e24ba49a5a71d6546fa4d423cea9f2f67a0284f69a3fb7bf5c1eb47c9de517d366b767d06646', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (12, 'cull_low_similarity_corroborates', NOW(), true, decode('2e56807a0c1a48786e60495273d8952a5f7e9a0d89323632f590e502a15fbd160979ce67692f0293a793b976e8250747', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (13, 'code_review_hardening', NOW(), true, decode('243bbfc5a5fe0b76ece7a977bd1fa687d41af2b7d91128bc47b3f7da7f013b5416a97d61093cd5d7c37542c264f3b66d', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (14, 'grant_revoke_signature_scope', NOW(), true, decode('2626ee520a83b572c5f6a03e04c9e3c4b7ffab64e5998cb8b2cad76cbf574dc210a33c5eaabfc4d12db4aa9cb2486c5c', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (15, 'graph_clusters', NOW(), true, decode('e1c1ba25eb946aabd68197f15f5a94951019a1b1e65e7e6b2df753c59374df5d58880135b6c87b8ea2980d46c7faf19c', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (16, 'add_evidence_embedding', NOW(), true, decode('0e5847bdc474fcef9d9030ca0f96cdce9fd9379e6b23e656ddac28e47ddb4cb3480b7f96d44ee1eaac9cd836dc34f947', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (17, 'authored_edges_allow_multiple', NOW(), true, decode('8f36c64e3d78cf68335edde228e1a679c994d06b2e5fb3bda51b9a2cedf64ec2d816db98e3f21b640b443fdc9474159f', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (18, 'drop_edges_triple_unique_constraint', NOW(), true, decode('21ed2f57e3d0bc988a3a42d3ffe5230f150c64a34ca9b6ea2249d93a7d277c57e8650457fbe47873cc0b3ef3491771e5', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (19, 'experiment_edge_type_fix', NOW(), true, decode('ca0e01b4c7078586f2d231d63bf92d51b54148e806fd77c53b60f7c0c609e60ddb030b7859ad5e1af4919a933894be25', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (20, 'workflows_table', NOW(), true, decode('f58224540ee8b9eeb8c2ff3d54166c0dc0052473cb9b0c72392f44f3a90091aff109ce42b643acb779088411802ffebd', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (21, 'behavioral_executions_step_claim_id', NOW(), true, decode('82562a7ff8213395ef2ec612f481d8f02801673f351d37adb34087f919503c39cfd548fcc8b1139e09ab8a01fbf316cb', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (22, 'behavioral_executions_polymorphic_workflow_id', NOW(), true, decode('05f1ccc69c2baafb814afdf50d647cb21d8e469c50823f4b4dab23a637b7fe88e1a3a3ddc139f8b6c1cfc390c5542265', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (23, 'experiments_table', NOW(), true, decode('c9af555211cac84095c7d12c651d91b35c7358fe56a481ca65947935143a5eb231948a93687fe6ec671d9c2c0ae1576b', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (24, 'cascade_delete_edges_backfill', NOW(), true, decode('d8f1d4019781aba1f734b092e9f088501dc386f689d3d8390a5f6bab6d91734df537c004cc4e7c0f6cf2da056e2561e4', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (25, 'validate_edge_reference_cleanup', NOW(), true, decode('d92b0a6bddc669a96f89fc0b0dacd52bcaad91f684c77a647ffa1c314ad1124aad6fce70da42cb3350263c7d67f5ccf5', 'hex'), 0);
INSERT INTO _sqlx_migrations (version, description, installed_on, success, checksum, execution_time) VALUES (26, 'graph_neighborhoods', NOW(), true, decode('d105dc5d938dac8f2626217b9f813dc843be195ed6f27f91f6f25ed1a04e9f58092aa4513be3cdedd4fe61769405de2b', 'hex'), 0);
COMMIT;

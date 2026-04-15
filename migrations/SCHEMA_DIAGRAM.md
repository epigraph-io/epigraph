# EpiGraph Database Schema Diagram

## Entity Relationship Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         EPIGRAPH SCHEMA                                   │
│                    Label Property Graph (LPG) Hybrid                      │
└──────────────────────────────────────────────────────────────────────────┘

                                    ┌─────────────┐
                                    │   agents    │
                                    ├─────────────┤
                                    │ id (PK)     │
                                    │ public_key  │◄─────────────┐
                                    │ display_name│              │
                                    │ labels[]    │              │
                                    │ properties  │              │
                                    └──────┬──────┘              │
                                           │                     │
                                           │ creates             │
                                           ▼                     │
┌────────────────┐              ┌─────────────────┐             │
│ evidence       │              │    claims       │             │
├────────────────┤              ├─────────────────┤             │
│ id (PK)        │              │ id (PK)         │             │
│ content_hash   │◄─┐           │ content         │             │
│ evidence_type  │  │           │ content_hash    │             │
│ source_url     │  │  supports │ truth_value     │             │
│ raw_content    │  │           │ agent_id (FK)   ├─────────────┘
│ claim_id (FK)  ├──┼───────────┤ trace_id (FK)   │
│ signature      │  │           │ embedding       │
│ signer_id (FK) ├──┘           │ labels[]        │
│ labels[]       │               │ properties      │
│ properties     │               └────────┬────────┘
└────────────────┘                        │
                                          │ generates
                                          ▼
                              ┌────────────────────────┐
                              │ reasoning_traces       │
                              ├────────────────────────┤
                              │ id (PK)                │
                              │ claim_id (FK)          │
                              │ reasoning_type         │
                              │ confidence             │
                              │ explanation            │
                              │ labels[]               │
                              │ properties             │
                              └────────┬───────────────┘
                                       │
                                       │ parent-child
                                       ▼
                              ┌────────────────────┐
                              │ trace_parents      │
                              ├────────────────────┤
                              │ trace_id (FK, PK)  │
                              │ parent_id (FK, PK) │
                              └────────────────────┘
                                    (DAG edges)


                              ┌────────────────────┐
                              │      edges         │
                              │  (Generic LPG)     │
                              ├────────────────────┤
                              │ id (PK)            │
                              │ source_id          │──┐
                              │ target_id          │  │ Any entity
                              │ source_type        │  │ to any entity
                              │ target_type        │  │
                              │ relationship       │◄─┘
                              │ labels[]           │
                              │ properties         │
                              └────────────────────┘
```

## Table Descriptions

### Core Tables

#### agents
- **Purpose**: Cryptographic identities that submit claims
- **Key Columns**:
  - `public_key` BYTEA(32) - Ed25519 public key
  - `display_name` VARCHAR(255) - Human-readable name
- **LPG Fields**: labels, properties
- **Indexes**: public_key (unique), labels (GIN), properties (GIN)

#### claims
- **Purpose**: Epistemic assertions with probabilistic truth values
- **Key Columns**:
  - `content` TEXT - Claim statement
  - `content_hash` BYTEA(32) - BLAKE3 hash
  - `truth_value` DOUBLE PRECISION [0.0, 1.0] - Probabilistic truth
  - `embedding` vector(1536) - Semantic embedding
- **LPG Fields**: labels, properties
- **Indexes**: truth_value, embedding (HNSW), agent_id, labels (GIN), properties (GIN)

#### evidence
- **Purpose**: Supporting materials for claims
- **Key Columns**:
  - `evidence_type` VARCHAR(50) - {document, observation, testimony, computation, reference}
  - `content_hash` BYTEA(32) - BLAKE3 hash
  - `signature` BYTEA(64) - Optional Ed25519 signature
- **LPG Fields**: labels, properties
- **Indexes**: claim_id, evidence_type, labels (GIN), properties (GIN)

#### reasoning_traces
- **Purpose**: Reasoning provenance and methodology
- **Key Columns**:
  - `reasoning_type` VARCHAR(50) - {deductive, inductive, abductive, analogical, statistical}
  - `confidence` DOUBLE PRECISION [0.0, 1.0] - Reasoning confidence
  - `explanation` TEXT - Human-readable justification
- **LPG Fields**: labels, properties
- **Indexes**: claim_id, reasoning_type, labels (GIN), properties (GIN)

#### trace_parents
- **Purpose**: DAG edges between reasoning traces
- **Key Columns**:
  - `trace_id` UUID - Child trace (depends on parent)
  - `parent_id` UUID - Parent trace (provides input)
- **Constraints**:
  - Composite PK (trace_id, parent_id)
  - CHECK: trace_id != parent_id (no self-references)
- **Indexes**: Both columns indexed for bidirectional traversal

#### edges
- **Purpose**: Generic LPG-style relationships between any entities
- **Key Columns**:
  - `source_id` UUID - Source entity
  - `target_id` UUID - Target entity
  - `source_type` VARCHAR(50) - Entity type
  - `target_type` VARCHAR(50) - Entity type
  - `relationship` VARCHAR(100) - Edge label
- **LPG Fields**: labels, properties
- **Examples**:
  - Claim "supports" Claim
  - Claim "contradicts" Claim
  - Agent "endorses" Claim
  - Evidence "cites" Evidence

## Data Flow

```
1. Agent Registration
   ┌─────────┐
   │ Agent   │ → INSERT INTO agents (public_key, ...)
   └─────────┘

2. Claim Submission
   ┌─────────────┐
   │ Evidence    │ → INSERT INTO evidence
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │ Reasoning   │ → INSERT INTO reasoning_traces
   │ Trace       │ → INSERT INTO trace_parents (DAG)
   └──────┬──────┘
          │
          ▼
   ┌─────────────┐
   │ Claim       │ → INSERT INTO claims
   └─────────────┘ → UPDATE claims.trace_id (via migration 006 FK)

3. Truth Propagation
   Evidence added → Trigger truth recalculation
                 → UPDATE claims SET truth_value = ...
                 → Ripple to dependent claims (via trace_parents DAG)

4. Semantic Search
   Query text → Generate embedding
             → SELECT * FROM claims
                ORDER BY embedding <=> $query_embedding
                LIMIT 10

5. Lineage Query
   Claim ID → Recursive CTE on trace_parents
           → Traverse DAG to find all evidence sources
```

## Index Strategy Summary

| Index Type | Purpose | Example |
|------------|---------|---------|
| B-tree | Primary keys, foreign keys, ordering | `agents(id)`, `claims(truth_value)` |
| GIN | Array and JSONB queries | `claims(labels)`, `agents(properties)` |
| HNSW | Vector similarity search | `claims(embedding)` |
| Unique | Prevent duplicates | `agents(public_key)` |
| Composite | Multi-column queries | `claims(agent_id, truth_value)` |
| Partial | Filtered index (smaller, faster) | `claims WHERE truth_value >= 0.7` |

## Query Examples

### 1. Find High-Truth Claims by Agent
```sql
SELECT c.id, c.content, c.truth_value
FROM claims c
WHERE c.agent_id = $1
  AND c.truth_value >= 0.7
ORDER BY c.truth_value DESC;
-- Uses index: idx_claims_agent_truth
```

### 2. Semantic Search
```sql
SELECT c.id, c.content, c.truth_value,
       1 - (c.embedding <=> $query_embedding::vector) AS similarity
FROM claims c
WHERE c.embedding IS NOT NULL
  AND c.truth_value >= 0.7
ORDER BY c.embedding <=> $query_embedding::vector
LIMIT 10;
-- Uses index: idx_claims_embedding_hnsw
```

### 3. Claim Lineage (Recursive)
```sql
WITH RECURSIVE lineage AS (
  -- Base: Start with the target claim
  SELECT rt.id, rt.claim_id, 0 AS depth
  FROM reasoning_traces rt
  WHERE rt.claim_id = $target_claim_id

  UNION ALL

  -- Recursive: Find parent traces
  SELECT rt.id, rt.claim_id, l.depth + 1
  FROM lineage l
  JOIN trace_parents tp ON tp.trace_id = l.id
  JOIN reasoning_traces rt ON rt.id = tp.parent_id
  WHERE l.depth < 10  -- Prevent infinite loops
)
SELECT * FROM lineage;
-- Uses index: idx_trace_parents_trace_id
```

### 4. Find Contradictory Claims
```sql
SELECT
  c1.id AS claim_a,
  c2.id AS claim_b,
  c1.content AS statement_a,
  c2.content AS statement_b
FROM edges e
JOIN claims c1 ON c1.id = e.source_id
JOIN claims c2 ON c2.id = e.target_id
WHERE e.relationship = 'contradicts'
  AND e.source_type = 'claim'
  AND e.target_type = 'claim';
-- Uses index: idx_edges_typed_relationship
```

### 5. Agent Reputation (Domain-Specific)
```sql
SELECT
  a.id,
  a.display_name,
  COUNT(*) FILTER (WHERE c.truth_value >= 0.8) AS verified_true,
  COUNT(*) FILTER (WHERE c.truth_value <= 0.2) AS verified_false,
  COUNT(*) AS total_claims,
  AVG(c.truth_value) AS avg_truth
FROM agents a
JOIN claims c ON c.agent_id = a.id
WHERE c.properties->>'domain' = 'physics'
GROUP BY a.id, a.display_name;
-- Uses index: idx_claims_agent_id, idx_claims_properties (GIN)
```

## Schema Evolution Notes

### Adding New Evidence Type
```sql
-- Easy: Just update CHECK constraint
ALTER TABLE evidence
DROP CONSTRAINT evidence_type_valid;

ALTER TABLE evidence
ADD CONSTRAINT evidence_type_valid CHECK (
  evidence_type IN ('document', 'observation', 'testimony',
                    'computation', 'reference', 'new_type')
);
```

### Adding New Relationship Type
```sql
-- No schema change needed! Just insert with new relationship value
INSERT INTO edges (source_id, target_id, source_type, target_type, relationship)
VALUES ($1, $2, 'claim', 'claim', 'elaborates');
```

### Partitioning Claims Table (Future)
```sql
-- For > 100M claims, partition by created_at
CREATE TABLE claims_2024 PARTITION OF claims
FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
```

---

**Note**: This schema is designed to match the Rust types in `/home/user/EpiGraphV2/crates/epigraph-core/src/`. All database constraints enforce the same invariants as the Rust type system.

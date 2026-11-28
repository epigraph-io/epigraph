# Ontology-aligned triples pilot: closed predicate whitelist

Status: draft whitelist, first task of the opt-in pilot (backlog d2b1de93,
split 7ea4d7ce). Nothing in this directory runs, and nothing writes to the
`triples` table. The triple layer stays dormant
(`crates/epigraph-engine/src/triple_extractor.rs`) until the pilot passes its
acceptance gates on a fixed test corpus.

Earlier extraction used free-text predicates, and they varied across
rewordings of the same fact (`exhibits` / `exhibited` / `shows`), so two
claims sharing a subject rarely shared a `(subject, predicate)` pair
(`experiments/rdf-triple-matching/PHASE0_FINDINGS.md`). The pilot fixes the
vocabulary BEFORE it picks an extractor: a triple whose predicate is not
listed here, or whose subject or object type is not one this list allows for
that predicate, is never written.

## Entity types

Every subject and object type below is one of the 14 values of the
`entities_type_top_valid` CHECK constraint on `entities.type_top`
(`migrations/001_initial_schema.sql`, re-created with `BusinessFunction` in
`migrations/003_business_function_entity_type.sql`):

`Material`, `Molecule`, `Method`, `Instrument`, `Property`, `Measurement`,
`Condition`, `Organism`, `Software`, `Person`, `Organization`, `Location`,
`Concept`, `BusinessFunction`.

The spelling is the constraint's: `Organization`, with a z. A type the CHECK
does not list cannot be stored, so it cannot appear here.

## Rejection rule

The list is CLOSED. At parse time, before entity resolution and before any
write, the extractor drops:

1. a triple whose predicate is not one of the names below (exact match after
   the canonicalizer maps surface variants, e.g. "works for" -> `employed_by`;
   the canonicalizer may only map ONTO this list, never add to it);
2. a triple whose subject `type_top` or object `type_top` is not one of the
   types this list allows for its predicate;
3. a triple whose object is a literal: every predicate below takes an entity
   object.

A dropped triple is not stored, not repaired and not stored under a fallback
predicate such as `related_to`. It is counted per reason in the run report.
This is how OntoGPT/SPIRES treats a value outside the schema's enum: it drops
it at parse. Adding a predicate means changing this file, with its types,
mapping and examples, in a reviewed commit.

## Predicates: person and organisation ties

Direction is always subject -> object, and the name reads in that direction
("A employed_by B"). Where schema.org's property points the other way, the
mapping says so.

The mappings were checked against the published schema.org domain and range
of each property and against the RO term's own definition. "None" means no
term matches closely enough to emit as an equivalence.

### `employed_by`

- Subject: `Person`
- Object: `Organization`
- schema.org: `worksFor` (domain `Person`, range `Organization`), same
  direction.
- RO/BFO: none.
- Examples (synthetic):
  - "Mira Kestrel joined Halvren Optics as a staff engineer in 2019."
    -> (Mira Kestrel: Person) `employed_by` (Halvren Optics: Organization)
  - "Tobin Arlo is a research scientist at the Quellmark Institute."
    -> (Tobin Arlo: Person) `employed_by` (Quellmark Institute: Organization)

### `member_of`

- Subject: `Person` or `Organization`
- Object: `Organization`
- schema.org: `memberOf` (domain `Person` or `Organization`; range includes
  `Organization`), same direction. Its inverse there is `member`.
- RO/BFO: `RO:0002350` "member of" is the general item-to-collection relation
  (its example is an organism in a population). It is broader than a social
  membership, so it is not emitted as an equivalence.
- Examples (synthetic):
  - "Dr. Selka Varn sits on the steering committee of the Brivane
    Photonics Consortium."
    -> (Selka Varn: Person) `member_of` (Brivane Photonics Consortium: Organization)
  - "Nordeval Labs is one of twelve member companies of the Fenmarrow Battery
    Alliance."
    -> (Nordeval Labs: Organization) `member_of` (Fenmarrow Battery Alliance: Organization)

### `founded`

- Subject: `Person` or `Organization`
- Object: `Organization`
- schema.org: inverse of `founder`. `founder` has domain `Organization` and
  range `Organization` or `Person`, so "B founder A" is "A `founded` B".
- RO/BFO: none.
- Examples (synthetic):
  - "Pell Orrin started Corvane Materials in a rented garage in 2011."
    -> (Pell Orrin: Person) `founded` (Corvane Materials: Organization)
  - "The Ashvane Foundation established the Ashvane Coastal Field Station."
    -> (Ashvane Foundation: Organization) `founded` (Ashvane Coastal Field Station: Organization)

### `collaborates_with`

- Subject: `Person` or `Organization`
- Object: the SAME type as the subject (`Person` with `Person`,
  `Organization` with `Organization`). A person-to-organisation tie is
  `affiliated_with` or `employed_by`, not this.
- Symmetric. The extractor writes ONE triple per pair, with the two entities
  in entity-id order, so a restatement with the names swapped resolves to the
  same triple. `entity_neighborhood` reads an entity as subject or object, so
  either end finds it.
- schema.org: none. `colleague` (domain `Person`, range `Person` or `URL`) is
  "a colleague of the person", a workplace tie, not a collaboration on a
  piece of work, and it does not cover organisations.
- RO/BFO: none.
- Examples (synthetic):
  - "Ilsa Morrow and Dev Tanaka-Reyes co-led the 2024 electrolyte
    stability study."
    -> (Ilsa Morrow: Person) `collaborates_with` (Dev Tanaka-Reyes: Person)
  - "Ombrel Bioworks and Larchvale University run a joint enzyme screening
    programme."
    -> (Ombrel Bioworks: Organization) `collaborates_with` (Larchvale University: Organization)

### `advises`

- Subject: `Person`
- Object: `Person` or `Organization`
- schema.org: none found (schema.org has no `advisor` or `adviser` term page).
- RO/BFO: none.
- Examples (synthetic):
  - "Prof. Hana Oduya supervised Rell Castine's doctoral thesis."
    -> (Hana Oduya: Person) `advises` (Rell Castine: Person)
  - "Marten Sjoberg serves on the scientific advisory board of Tidvarre
    Genomics."
    -> (Marten Sjoberg: Person) `advises` (Tidvarre Genomics: Organization)

### `funded_by`

- Subject: `Person` or `Organization`
- Object: `Organization` or `Person`
- schema.org: `funder` (domain includes `Person` and `Organization`; range
  `Organization` or `Person`), same direction: "A funder B" is
  "A `funded_by` B".
- RO/BFO: none.
- Scope: funding of a person or an organisation. Funding of a study or a
  project is a claim about that work, not an entity tie, and is out of scope
  for this list until a work type exists in `type_top`.
- Examples (synthetic):
  - "Orla Vence's fellowship is paid for by the Pemvarrow Science Trust."
    -> (Orla Vence: Person) `funded_by` (Pemvarrow Science Trust: Organization)
  - "Vantrell Robotics closed a seed round led by Quillmere Ventures."
    -> (Vantrell Robotics: Organization) `funded_by` (Quillmere Ventures: Organization)

### `affiliated_with`

- Subject: `Person`
- Object: `Organization`
- schema.org: `affiliation` (domain `Person`, range `Organization`; "an
  organization that this person is affiliated with"), same direction.
- RO/BFO: none.
- Use it when the text states a tie weaker than, or other than, employment
  (a visiting or honorary post, an alumni tie, a listed affiliation on a
  paper). When the text states employment, use `employed_by`.
- Examples (synthetic):
  - "Dr. Yusra Belling holds an honorary chair at Wexmoor Polytechnic."
    -> (Yusra Belling: Person) `affiliated_with` (Wexmoor Polytechnic: Organization)
  - "Affiliations: Cato Linde (Marrow Bay Research Centre)."
    -> (Cato Linde: Person) `affiliated_with` (Marrow Bay Research Centre: Organization)

## Not yet on the list

Every other relation, including ties between the scientific types
(`Material`, `Method`, `Property`, ...), is off-list and dropped by the rule
above until it is added here with its types, mapping and examples. The names,
people, organisations and sentences in this file are invented.

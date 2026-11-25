//! A throwaway belief graph with no database (`scratch` feature).
//!
//! The scratch graph holds one chat's belief graph in memory: atoms, edges
//! and the turns written into it. It is built for the EpiClaw agent-runner,
//! acting on operator ruling 9854c563 ("Epigraph API without DB" for
//! temporary throwaway belief graphs). Nothing here uses `feature = "db"`
//! code, reads the environment or opens a connection.

pub mod bm25;
pub mod snapshot;
pub mod store;

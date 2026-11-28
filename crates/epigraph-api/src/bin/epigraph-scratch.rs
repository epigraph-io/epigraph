//! `epigraph-scratch`: a throwaway, database-free belief graph served over
//! stdio JSON lines. See `epigraph_api::scratch` for the protocol, the
//! snapshot format and why this binary needs no database.

fn main() {
    std::process::exit(epigraph_api::scratch::run(std::env::args().skip(1)));
}

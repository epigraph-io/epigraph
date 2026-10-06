//! `delete-frames`: remove an explicit list of `frames` rows (test or probe
//! frames left in a production graph, backlog 34b3175c / drain U048), refusing
//! every frame whose removal would change anything a real claim depends on.
//!
//! STUB: the argument surface only; the plan, the refusals and the write land
//! in the next commit.

use sqlx::PgConnection;
use std::collections::BTreeSet;
use uuid::Uuid;

/// Everything `delete-frames` was told.
#[derive(Clone, Debug)]
pub struct Options {
    /// The frames to remove, in the ids file's order.
    pub frames: Vec<Uuid>,
    /// Claims whose frame-keyed rows may be removed with the frames.
    pub companions: BTreeSet<Uuid>,
    pub apply: bool,
    pub confirm_delete: Option<usize>,
    pub reason: String,
    pub lock_timeout: String,
}

/// What a run decided and did.
#[derive(Debug, Default)]
pub struct Report {
    /// Frames removed (zero on a dry run).
    pub deleted: usize,
    /// Listed frames refused, with every reason.
    pub refused: Vec<(Uuid, Vec<String>)>,
    /// Listed ids that are not a frame.
    pub missing: Vec<Uuid>,
}

/// # Errors
/// Never, in the stub.
pub async fn run(
    _conn: &mut PgConnection,
    _opts: &Options,
    _out: &mut dyn std::io::Write,
) -> anyhow::Result<Report> {
    Ok(Report::default())
}

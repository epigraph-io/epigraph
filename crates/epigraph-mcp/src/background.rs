//! Work a tool call hands off to run after its response: the detached
//! `ingest_document` / `ingest_document_inline` walks and the post-commit
//! embedding loops of both document walks.
//!
//! Those tasks used to be bare `tokio::spawn`s that nothing owned. On stdio the
//! process returns from `main` as soon as the client closes the transport, and
//! the runtime then drops every task still running: a walk the caller was told
//! was `queued` is cancelled (its one transaction rolls back), and an embedding
//! loop stops partway, leaving committed claims with no vector. The operator
//! `ingest-document` CLI lost its embedding loop the same way, because it exits
//! as soon as the walk returns.
//!
//! [`BackgroundTasks`] is the owner. Every clone of a server shares one, so a
//! task a detached walk spawns (its embedding loop) is tracked by the same
//! tracker as the walk itself. A process that is about to exit calls
//! [`BackgroundTasks::drain`], which waits for what is still running, up to a
//! limit.

use std::future::Future;
use std::time::Duration;

use tokio_util::task::TaskTracker;

/// How long a stdio server, after its client has gone, and the operator
/// `ingest-document` CLI wait for the tasks still running before they exit.
///
/// Sized for the slowest tracked task: an embedding loop makes one provider
/// call per created claim, serially, at about 0.8 s each, so a 500-claim
/// document needs about 400 s.
pub const EXIT_DRAIN_LIMIT: Duration = Duration::from_secs(600);

/// The tasks a server's tool calls left running. Cloning shares the tracker.
#[derive(Clone, Default)]
pub struct BackgroundTasks {
    tracker: TaskTracker,
}

impl std::fmt::Debug for BackgroundTasks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackgroundTasks")
            .field("running", &self.tracker.len())
            .field("closed", &self.tracker.is_closed())
            .finish()
    }
}

impl BackgroundTasks {
    /// Run `task` on the runtime, tracked, so [`Self::drain`] waits for it.
    pub fn spawn<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        // The JoinHandle is not kept: a tracked task's failure is its own to
        // log, as it was when these were bare `tokio::spawn`s.
        drop(self.tracker.spawn(task));
    }

    /// How many tracked tasks have not finished yet.
    #[must_use]
    pub fn running(&self) -> usize {
        self.tracker.len()
    }

    /// Wait up to `limit` for every tracked task to finish, and return how
    /// many were still running when the wait ended (0 when all finished).
    ///
    /// A task spawned while the drain waits, such as the embedding loop of a
    /// walk that is finishing, is waited for too: the tracker is empty only
    /// when the last of them is done. Tasks left at the limit are named in a
    /// WARN; they are cancelled when the process exits.
    pub async fn drain(&self, limit: Duration) -> usize {
        self.tracker.close();
        let running = self.tracker.len();
        if running == 0 {
            return 0;
        }
        tracing::info!(
            running,
            limit_secs = limit.as_secs(),
            "waiting for background tasks (detached ingests, embedding loops) to finish \
             before exiting"
        );
        if tokio::time::timeout(limit, self.tracker.wait())
            .await
            .is_ok()
        {
            return 0;
        }
        let left = self.tracker.len();
        tracing::warn!(
            left,
            limit_secs = limit.as_secs(),
            "background tasks still running at the drain limit are cancelled on exit: a \
             detached ingest that had not committed wrote nothing, and claims whose embedding \
             had not been stored carry no vector until the maintenance backfill reaches them"
        );
        left
    }
}

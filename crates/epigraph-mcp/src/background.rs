//! Tracking for the tasks a tool detaches and answers ahead of.
//!
//! `ingest_document` and `ingest_document_inline` answer `queued` and run the
//! walk in a detached task; both document walkers embed their new claims in
//! another. On the HTTP transport the process outlives the request, so those
//! tasks finish. On stdio it did not: `main` awaited `service.waiting()` and
//! returned, and a runtime that is dropped cancels every task still on it. A
//! client that called `ingest_document`, read `queued` and closed the session
//! ended the process mid-walk (nothing written, the `papers` row left behind)
//! or mid-embedding (claims committed with no vector) (backlog b928ccc1).
//!
//! [`BackgroundTasks`] counts such tasks so the stdio entry point can wait for
//! them, with a bound, before it returns. It is a counter and a `Notify`
//! rather than a `JoinSet`: the tasks are spawned from `&self` tool handlers on
//! clones of the server, and nothing needs their results, only to know when
//! there are none left.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// A shared count of detached tasks still running. Clones share the count, so
/// a per-session clone of the server spawns into the same set.
#[derive(Clone, Default)]
pub struct BackgroundTasks {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    active: AtomicUsize,
    idle: tokio::sync::Notify,
}

/// Held by a tracked task for its whole life. Decrements on drop, so a task
/// that panics or is cancelled is still counted out.
struct Guard(Arc<Inner>);

impl Drop for Guard {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

impl BackgroundTasks {
    /// `tokio::spawn` a task that [`wait_idle`](Self::wait_idle) waits for.
    pub fn spawn<F>(&self, future: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        // Counted BEFORE the spawn, not inside the task: a waiter that checks
        // between the spawn and the task's first poll must already see it.
        self.inner.active.fetch_add(1, Ordering::SeqCst);
        let guard = Guard(Arc::clone(&self.inner));
        tokio::spawn(async move {
            let _guard = guard;
            future.await
        })
    }

    /// How many tracked tasks are running now.
    #[must_use]
    pub fn active(&self) -> usize {
        self.inner.active.load(Ordering::SeqCst)
    }

    /// Wait until no tracked task is running, or until `timeout` has passed.
    /// Returns `true` when the set went idle, `false` on the timeout.
    ///
    /// A task spawned while this waits is waited for too.
    pub async fn wait_idle(&self, timeout: Duration) -> bool {
        let idle = async {
            loop {
                // Registered before the count is read, so a task that finishes
                // between the read and the await still wakes this waiter.
                let notified = self.inner.idle.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.active() == 0 {
                    return;
                }
                notified.await;
            }
        };
        tokio::time::timeout(timeout, idle).await.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::BackgroundTasks;
    use std::time::Duration;

    #[tokio::test]
    async fn an_idle_set_does_not_wait() {
        let tasks = BackgroundTasks::default();
        assert!(tasks.wait_idle(Duration::from_millis(10)).await);
    }

    #[tokio::test]
    async fn wait_idle_returns_once_every_task_has_finished() {
        let tasks = BackgroundTasks::default();
        let (release, gate) = tokio::sync::oneshot::channel::<()>();
        let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = done.clone();
        tasks.spawn(async move {
            let _ = gate.await;
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        // A clone shares the set: this is the server clone a detached walk runs on.
        let clone = tasks.clone();
        clone.spawn(async {});
        assert!(
            tasks.active() >= 1,
            "the gated task is counted from the spawn"
        );

        assert!(
            !tasks.wait_idle(Duration::from_millis(50)).await,
            "a task that has not finished keeps the set busy"
        );
        release.send(()).unwrap();
        assert!(tasks.wait_idle(Duration::from_secs(5)).await);
        assert!(
            done.load(std::sync::atomic::Ordering::SeqCst),
            "idle means the task ran to completion, not that it was dropped"
        );
        assert_eq!(tasks.active(), 0);
    }

    /// A task that panics must not hold the process open until the timeout.
    #[tokio::test]
    async fn a_panicking_task_is_counted_out() {
        let tasks = BackgroundTasks::default();
        let handle = tasks.spawn(async { panic!("boom") });
        assert!(handle.await.is_err());
        assert!(tasks.wait_idle(Duration::from_secs(5)).await);
    }
}

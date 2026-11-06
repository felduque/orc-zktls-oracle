use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::task::{JoinError, JoinHandle};

/// A spawned task that is aborted when dropped, so a failed or timed-out
/// session attempt leaves nothing running before the retry.
pub(crate) struct AbortOnDrop<T>(JoinHandle<T>);

impl<T: Send + 'static> AbortOnDrop<T> {
    pub(crate) fn spawn(fut: impl Future<Output = T> + Send + 'static) -> Self {
        Self(tokio::spawn(fut))
    }
}

impl<T> Future for AbortOnDrop<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

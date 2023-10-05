use std::{future::Future, sync::Arc};

pub(crate) fn unwrap_or_clone_arc<T: Clone>(arc: Arc<T>) -> T {
    Arc::try_unwrap(arc).unwrap_or_else(|x| (*x).clone())
}

pub(crate) async fn run_in_tokio_task<F: Future + Send + 'static>(f: F) -> F::Output
where
    F::Output: Send,
{
    crate::RUNTIME.spawn(f).await.unwrap()
}

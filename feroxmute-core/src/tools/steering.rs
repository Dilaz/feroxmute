use std::sync::Arc;
use tokio::sync::Mutex;

/// Operator-supplied guidance queued for the orchestrator (human-in-the-loop steering).
#[derive(Clone, Default)]
pub struct OperatorGuidance {
    inbox: Arc<Mutex<Vec<String>>>,
}

impl OperatorGuidance {
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a guidance message from the operator.
    pub async fn push(&self, text: String) {
        self.inbox.lock().await.push(text);
    }

    /// Drain all pending guidance, emptying the queue.
    pub async fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.inbox.lock().await)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn push_then_take_drains() {
        let g = OperatorGuidance::new();
        g.push("a".into()).await;
        g.push("b".into()).await;
        assert_eq!(g.take().await, vec!["a", "b"]);
        assert!(g.take().await.is_empty());
    }
}

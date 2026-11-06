use std::time::Duration;

pub(crate) type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Prover failure. Messages never contain the GitHub token.
#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("invalid input: {0}")]
    Invalid(String),

    #[error("{phase} timed out after {after:?}")]
    Timeout { phase: &'static str, after: Duration },

    #[error("{stage}: {source}")]
    Stage {
        stage: &'static str,
        #[source]
        source: BoxError,
    },

    #[error("preflight failed: {0}")]
    Preflight(String),

    #[error("the presentation contains the GitHub token; refusing to use it")]
    TokenLeak,
}

impl ProverError {
    /// Hangs and transport/protocol failures are worth one fresh session;
    /// bad input and leaks are not.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Timeout { .. } | Self::Stage { .. })
    }
}

pub(crate) trait StageExt<T> {
    fn stage(self, stage: &'static str) -> Result<T, ProverError>;
}

impl<T, E: Into<BoxError>> StageExt<T> for Result<T, E> {
    fn stage(self, stage: &'static str) -> Result<T, ProverError> {
        self.map_err(|e| ProverError::Stage {
            stage,
            source: e.into(),
        })
    }
}

/// Runs `fut` with a deadline, mapping expiry to [`ProverError::Timeout`].
pub(crate) async fn with_timeout<T>(
    phase: &'static str,
    after: Duration,
    fut: impl std::future::Future<Output = Result<T, ProverError>>,
) -> Result<T, ProverError> {
    tokio::time::timeout(after, fut)
        .await
        .map_err(|_| ProverError::Timeout { phase, after })?
}

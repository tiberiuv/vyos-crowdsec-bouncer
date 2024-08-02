use super::types::DecisionsResponse;

#[allow(async_fn_in_trait)]
pub trait CrowdsecLAPI {
    async fn stream_decisions(
        &self,
        pull_history: bool,
    ) -> Result<DecisionsResponse, anyhow::Error>;
}

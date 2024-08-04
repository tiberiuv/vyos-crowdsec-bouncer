use super::http::DecisionsOptions;
use super::types::DecisionsResponse;

#[allow(async_fn_in_trait)]
pub trait CrowdsecLAPI {
    async fn stream_decisions(
        &self,
        decision_options: &DecisionsOptions,
    ) -> Result<DecisionsResponse, anyhow::Error>;
}

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

use futures_util::Future;
use rand::random;

pub fn read_file(path: &Path) -> Result<Vec<u8>, io::Error> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(buf)
}

fn exponential_backoff(retries: u64, cap: u64) -> Duration {
    let jitter = random::<u64>() * 5;
    Duration::from_millis(u64::min(cap, ((2 ^ retries) * 25) + jitter))
}

pub async fn retry_op<Fut, T, E, F>(retries: u64, f: F) -> Result<T, E>
where
    E: std::fmt::Debug,
    Fut: Future<Output = Result<T, E>>,
    F: Fn() -> Fut,
{
    let mut current_retries = 0;
    loop {
        let result = f().await;
        match result {
            Ok(t) => return Ok(t),
            Err(err) if current_retries < retries => {
                current_retries += 1;
                tracing::error!(msg = "Failed iteration", ?err, retry = current_retries);
                tokio::time::sleep(exponential_backoff(current_retries, 1000)).await;
            }
            Err(err) => {
                tracing::error!(msg = "Ran out of retries", ?err);
                return Err(err);
            }
        }
    }
}

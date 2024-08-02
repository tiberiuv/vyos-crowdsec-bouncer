use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

pub fn inspect_err(msg: &str, err: anyhow::Error) -> anyhow::Error {
    tracing::error!(msg = msg, ?err);
    err
}

pub fn read_file(path: &Path) -> Result<Vec<u8>, io::Error> {
    let mut file = File::open(path)?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;

    Ok(buf)
}

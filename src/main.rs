use std::io::stdin;
use std::str::{FromStr, SplitWhitespace};

use clap::{Args, Parser};

use crate::crowdsec_lapi::Decision;

/* mod codegen {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/mod.rs"));
} */
mod cli;
mod crowdsec_lapi;


/* fn deserialize_from_iter<'a, T: Deserialize<'a>>(
    s: &mut impl Iterator<Item = &'a str>,
    arg: &'static str,
) -> Result<T, anyhow::Error> {
    s.next()
        .ok_or(anyhow::anyhow!("{arg} not provided"))
        .and_then(|x| serde_json::from_str(x))
} */
/* impl FromStr for CrowdsecInput {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut s = s.split_whitespace().take(5);
        let operation: Operation = if let Some(operation) = s.next() {
            serde_json::from_str(operation)?
        } else {
            return Err(anyhow::anyhow!("operation not provided"));
        };

        Ok(dbg!(s
            .split_whitespace()
            .take(5)
            .last()
            .map(serde_json::from_str::<Self>))
        .ok_or_else(|| anyhow::anyhow!("Invalid input"))??)
    }
} */


fn main() {
    let stdin_handle = stdin();

    let args = crate::cli::Bin::parse();
    dbg!(args);

    for line in stdin_handle.lines() {
        match line {
            Ok(line) => {
                let decision = Decision::from_crowdsec_input(&line);
                dbg!(&decision);
            }
            Err(io_err) => {}
        }
    }
}

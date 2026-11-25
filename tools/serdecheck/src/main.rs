//! Reads one JSON document per line and writes, per line, what the Private AI
//! Gateway writes after parsing it: `serde_json::to_vec(&from_slice(line))`,
//! or `ERR <message>` when serde_json rejects it.

use std::io::{self, BufRead, Write};

fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(v) => writeln!(out, "{}", serde_json::to_string(&v).expect("serialize"))?,
            Err(e) => writeln!(out, "ERR {e}")?,
        }
    }
    out.flush()
}

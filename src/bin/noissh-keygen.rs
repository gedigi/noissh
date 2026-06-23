#![forbid(unsafe_code)]
//! noissh-keygen — ensure a static keypair exists and print its public key.
//!
//! Usage:
//!   noissh-keygen [--key PATH]
//!       Ensure a static keypair exists at PATH (default <config>/id),
//!       creating it if missing, and print the public key line
//!       `noissh-x25519 <base64>` to stdout. Paste that line into a server's
//!       authorized_keys to authorize this identity. If the file already
//!       exists, its public key is printed without regenerating.
//!   noissh-keygen --help
//!       Print this usage.

use std::path::PathBuf;
use std::process::exit;

use auth::PublicKey;
use noissh::RuntimeError;
use noissh::config::{config_dir, load_or_generate_keypair};

const USAGE: &str = "\
noissh-keygen — ensure a noissh static keypair exists and print its public key

Usage:
  noissh-keygen [--key PATH]   ensure a keypair at PATH (default <config>/id),
                               creating it if missing, then print the public
                               key line `noissh-x25519 <base64>`
  noissh-keygen --help         print this help

Paste the printed line into a server's authorized_keys to authorize this key.";

fn main() {
    if let Err(e) = run() {
        eprintln!("noissh-keygen: {e}");
        exit(1);
    }
}

fn run() -> Result<(), RuntimeError> {
    let mut key_path: Option<PathBuf> = None;
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("{USAGE}");
                return Ok(());
            }
            "--version" | "-V" => {
                println!("noissh-keygen {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "--key" => match it.next() {
                Some(p) => key_path = Some(PathBuf::from(p)),
                None => {
                    eprintln!("noissh-keygen: --key requires a PATH argument");
                    exit(2);
                }
            },
            other => {
                eprintln!("noissh-keygen: unexpected argument {other:?}");
                eprintln!("{USAGE}");
                exit(2);
            }
        }
    }

    let path = key_path.unwrap_or_else(|| config_dir().join("id"));
    let keypair = load_or_generate_keypair(&path)?;
    let public = PublicKey::from_bytes(&keypair.public)?;
    println!("{}", public.to_text());
    Ok(())
}

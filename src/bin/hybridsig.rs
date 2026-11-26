//! Command line: `hybridsig keygen|sign|verify`. Exit status: 0 success, 1 the signature does not verify,
//! 2 usage or file error. Unix only: it relies on Unix file permissions for the secret key.

#[cfg(not(unix))]
compile_error!("the hybridsig command line needs Unix file permissions; the library does not");

use hybridsig::{
    Error, PublicKey, SecretKey, MAX_CONTEXT, PUBLIC_KEY_LEN, SECRET_KEY_LEN, SIGNATURE_LEN,
};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::process::ExitCode;
use zeroize::Zeroizing;

/// The longest message the command line signs or verifies; it is held in memory.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

const USAGE: &str = "usage:
  hybridsig keygen --secret FILE --public FILE
  hybridsig sign   --secret FILE --context TEXT --in FILE --out FILE
  hybridsig verify --public FILE --context TEXT --in FILE --signature FILE";

enum Failure {
    NotValid(String),
    Other(String),
}

fn other(what: impl std::fmt::Display) -> Failure {
    Failure::Other(what.to_string())
}

/// Parses `--name value` pairs and insists on exactly the expected names.
fn options(args: &[String], names: &[&str]) -> Result<HashMap<String, String>, Failure> {
    let mut found = HashMap::new();
    for pair in args.chunks(2) {
        let [name, value] = pair else {
            return Err(other(USAGE));
        };
        let name = name.strip_prefix("--").filter(|n| names.contains(n));
        let name = name.ok_or_else(|| other(USAGE))?;
        if found.insert(name.to_string(), value.clone()).is_some() {
            return Err(other(USAGE));
        }
    }
    if found.len() != names.len() {
        return Err(other(USAGE));
    }
    Ok(found)
}

/// Reads an open file, refusing anything longer than `limit` without reading it all. The buffer is sized
/// once, so a secret is not left behind in a smaller one.
fn read_open(file: File, path: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let size = file
        .metadata()
        .map_err(|e| other(format!("cannot read {path}: {e}")))?
        .len();
    let expected = usize::try_from(size).unwrap_or(usize::MAX).min(limit);
    let mut bytes = Zeroizing::new(Vec::with_capacity(expected + 1));
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| other(format!("cannot read {path}: {e}")))?;
    if bytes.len() > limit {
        return Err(other(format!("{path} is longer than {limit} bytes")));
    }
    Ok(bytes)
}

fn open(path: &str) -> Result<File, Failure> {
    File::open(path).map_err(|e| other(format!("cannot read {path}: {e}")))
}

fn read(path: &str, limit: usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
    read_open(open(path)?, path, limit)
}

/// Writes a new file; never replaces one. `private` files are readable by their owner only. A file that could
/// not be written completely is removed.
fn create(path: &str, bytes: &[u8], private: bool) -> Result<(), Failure> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(if private { 0o600 } else { 0o644 })
        .open(path)
        .map_err(|e| other(format!("cannot create {path}: {e}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| {
            let _ = fs::remove_file(path);
            other(format!("cannot write {path}: {e}"))
        })
}

fn load_secret(path: &str) -> Result<SecretKey, Failure> {
    // Check the permissions of the file that is then read, not of whatever the name points to a moment later.
    let file = open(path)?;
    let mode = file
        .metadata()
        .map_err(|e| other(format!("cannot read {path}: {e}")))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(other(format!(
            "{path} can be read by others (mode {:o}); run chmod 600 on it",
            mode & 0o777
        )));
    }
    SecretKey::from_bytes(&read_open(file, path, SECRET_KEY_LEN)?).map_err(other)
}

fn context(value: &str) -> Result<&[u8], Failure> {
    if value.len() > MAX_CONTEXT {
        return Err(other(Error::ContextTooLong(value.len())));
    }
    Ok(value.as_bytes())
}

fn run(args: &[String]) -> Result<String, Failure> {
    let (command, rest) = args.split_first().ok_or_else(|| other(USAGE))?;
    match command.as_str() {
        "keygen" => {
            let o = options(rest, &["secret", "public"])?;
            let key = SecretKey::generate().map_err(other)?;
            // The public key first: if either cannot be written, no secret key is left behind. (Two files
            // cannot be created as one atomic step.)
            create(&o["public"], key.public_key().as_bytes(), false)?;
            if let Err(failure) = create(&o["secret"], &key.to_bytes(), true) {
                let _ = fs::remove_file(&o["public"]);
                return Err(failure);
            }
            Ok(format!("key id {}", hex(key.public_key().key_id())))
        }
        "sign" => {
            let o = options(rest, &["secret", "context", "in", "out"])?;
            let context = context(&o["context"])?;
            let key = load_secret(&o["secret"])?;
            let signature = key
                .sign(context, &read(&o["in"], MAX_MESSAGE)?)
                .map_err(other)?;
            create(&o["out"], &signature, false)?;
            Ok(format!("signed: {} bytes", signature.len()))
        }
        "verify" => {
            let o = options(rest, &["public", "context", "in", "signature"])?;
            let context = context(&o["context"])?;
            let key = PublicKey::from_bytes(&read(&o["public"], PUBLIC_KEY_LEN)?).map_err(other)?;
            let message = read(&o["in"], MAX_MESSAGE)?;
            let signature = read(&o["signature"], SIGNATURE_LEN)?;
            key.verify(context, &message, &signature)
                .map_err(|e| Failure::NotValid(e.to_string()))?;
            Ok(format!(
                "OK: both signatures verify, key id {}",
                hex(key.key_id())
            ))
        }
        _ => Err(other(USAGE)),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(message) => {
            println!("{message}");
            ExitCode::SUCCESS
        }
        Err(Failure::NotValid(reason)) => {
            println!("FAILED: {reason}");
            ExitCode::from(1)
        }
        Err(Failure::Other(reason)) => {
            eprintln!("{reason}");
            ExitCode::from(2)
        }
    }
}

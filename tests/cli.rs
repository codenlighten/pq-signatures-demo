//! The command line, run as a user would run it. Unix only, like the command line itself.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> Self {
        // Cargo's scratch directory, not the shared system one, which other things may empty while we run.
        let path = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("hybridsig-{}-{name}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        std::fs::write(path.join("message"), b"release 1.0").unwrap();
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_hybridsig"))
            .args(args)
            .current_dir(&self.0)
            .output()
            .unwrap()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn status(output: &Output) -> i32 {
    output.status.code().unwrap()
}

const KEYGEN: &[&str] = &["keygen", "--secret", "k.key", "--public", "k.pub"];
const SIGN: &[&str] = &[
    "sign",
    "--secret",
    "k.key",
    "--context",
    "release",
    "--in",
    "message",
    "--out",
    "sig",
];

fn check(context: &str) -> [&str; 9] {
    [
        "verify",
        "--public",
        "k.pub",
        "--context",
        context,
        "--in",
        "message",
        "--signature",
        "sig",
    ]
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn keygen_sign_and_verify() {
    let dir = Dir::new("round-trip");
    assert_eq!(status(&dir.run(KEYGEN)), 0);
    assert_eq!(status(&dir.run(SIGN)), 0);
    let ok = dir.run(&check("release"));
    assert_eq!(status(&ok), 0);
    assert!(String::from_utf8_lossy(&ok.stdout).starts_with("OK: both signatures verify"));
}

#[test]
fn a_signature_that_does_not_verify_exits_1() {
    let dir = Dir::new("wrong");
    dir.run(KEYGEN);
    dir.run(SIGN);
    let wrong = dir.run(&check("invoice"));
    assert_eq!(status(&wrong), 1);
    assert!(String::from_utf8_lossy(&wrong.stdout).starts_with("FAILED"));
    std::fs::write(dir.path("message"), b"release 2.0").unwrap();
    assert_eq!(status(&dir.run(&check("release"))), 1);
}

#[test]
fn the_secret_key_is_private_and_a_readable_one_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = Dir::new("permissions");
    dir.run(KEYGEN);
    assert_eq!(mode(&dir.path("k.key")), 0o600);
    std::fs::set_permissions(dir.path("k.key"), std::fs::Permissions::from_mode(0o640)).unwrap();
    let refused = dir.run(SIGN);
    assert_eq!(status(&refused), 2);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("can be read by others"));
    assert!(!dir.path("sig").exists());
}

#[test]
fn nothing_is_overwritten() {
    let dir = Dir::new("overwrite");
    dir.run(KEYGEN);
    let before = std::fs::read(dir.path("k.key")).unwrap();
    assert_eq!(status(&dir.run(KEYGEN)), 2);
    assert_eq!(std::fs::read(dir.path("k.key")).unwrap(), before);
    dir.run(SIGN);
    assert_eq!(status(&dir.run(SIGN)), 2);
}

#[test]
fn bad_usage_and_missing_files_exit_2() {
    let dir = Dir::new("usage");
    for args in [
        &[][..],
        &["frobnicate"],
        &["keygen", "--secret", "a"],
        &["keygen", "--secret", "a", "--public", "b", "--extra", "c"],
        &["keygen", "--secret", "a", "--secret", "b"],
        &[
            "verify",
            "--public",
            "none",
            "--context",
            "",
            "--in",
            "message",
            "--signature",
            "sig",
        ],
    ] {
        assert_eq!(status(&dir.run(args)), 2, "{args:?}");
    }
    assert!(!dir.path("a").exists());
}

#[test]
fn keygen_leaves_nothing_behind_when_either_file_cannot_be_created() {
    let dir = Dir::new("half-keygen");
    std::fs::write(dir.path("taken"), b"old").unwrap();
    for (secret, public) in [
        ("k.key", "taken"),
        ("taken", "k.pub"),
        ("no-such-dir/k.key", "k.pub"),
        ("k.key", "no-such-dir/k.pub"),
    ] {
        let out = dir.run(&["keygen", "--secret", secret, "--public", public]);
        assert_eq!(status(&out), 2, "{secret} {public}");
        assert!(!dir.path("k.key").exists(), "{secret} {public}");
        assert!(!dir.path("k.pub").exists(), "{secret} {public}");
    }
    assert_eq!(std::fs::read(dir.path("taken")).unwrap(), b"old");
}

#[test]
fn a_context_over_255_bytes_is_a_usage_error_not_a_failed_signature() {
    let dir = Dir::new("long-context");
    dir.run(KEYGEN);
    dir.run(SIGN);
    let long = "x".repeat(256);
    let out = dir.run(&check(&long));
    assert_eq!(status(&out), 2);
    assert!(String::from_utf8_lossy(&out.stderr).contains("the limit is 255"));
}

fn set_length(path: &Path, length: u64) {
    let file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.set_len(length).unwrap();
}

#[test]
fn oversized_files_are_refused() {
    let dir = Dir::new("oversized");
    dir.run(KEYGEN);
    dir.run(SIGN);
    for (name, limit) in [
        ("sig", 3377),
        ("k.pub", 1988),
        ("message", 64 * 1024 * 1024),
    ] {
        let original = std::fs::read(dir.path(name)).unwrap();
        set_length(&dir.path(name), limit + 1);
        let out = dir.run(&check("release"));
        assert_eq!(status(&out), 2, "{name}");
        let error = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(error.contains("is longer than"), "{name}: {error}");
        std::fs::write(dir.path(name), original).unwrap();
    }
    set_length(&dir.path("k.key"), 69);
    std::fs::remove_file(dir.path("sig")).unwrap();
    let out = dir.run(SIGN);
    assert_eq!(status(&out), 2);
    assert!(String::from_utf8_lossy(&out.stderr).contains("is longer than 68 bytes"));
}

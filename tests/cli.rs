use assert_cmd::Command;
use predicates::prelude::*;

fn etcat() -> Command {
    Command::new(assert_cmd::cargo::cargo_bin!("etcat"))
}

#[test]
fn help_lists_the_rootless_user_workflows() {
    etcat().arg("--help").assert().success().stdout(
        predicate::str::contains("Netcat-like, rootless")
            .and(predicate::str::contains("no-auth-ssh"))
            .and(predicate::str::contains("exit-node")),
    );
}

#[test]
fn invalid_connection_token_fails_before_network_startup() {
    etcat()
        .arg("not-a-token")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "neither an etc2 connection token nor a DNS name",
        ));
}

#[test]
fn invalid_compact_token_fails_before_network_startup() {
    Command::cargo_bin("etcat")
        .unwrap()
        .arg("etc2invalid")
        .assert()
        .failure()
        .stderr(predicate::str::contains("connection token"));
}

#[test]
fn built_in_relay_registry_lists_the_community_relay() {
    etcat()
        .arg("relays")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "community-1\tCommunity\tencrypted-unpinned",
        ));
}

#[test]
fn readme_flag_prints_embedded_documentation() {
    etcat()
        .arg("--readme")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("# etcat"));
}

#[test]
fn serve_rejects_positional_client_arguments() {
    etcat()
        .args(["--serve=8080", "etc2invalid"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no positional arguments are valid along with --serve",
        ));

    etcat()
        .args(["--serve=8080", "ping", "etc2invalid"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "no positional arguments are valid along with --serve",
        ));
}

#[test]
fn client_key_creation_refuses_an_accidental_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let configure = |command: &mut Command| {
        command
            .env("XDG_CONFIG_HOME", directory.path())
            .env("APPDATA", directory.path())
            .env("HOME", directory.path());
    };

    let mut first = etcat();
    configure(&mut first);
    first
        .args(["genkey", "--client", "--key", "cli-test"])
        .assert()
        .success()
        .stdout(predicate::str::starts_with("etcp1"));

    let mut second = etcat();
    configure(&mut second);
    second
        .args(["genkey", "--client", "--key", "cli-test"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"));
}

#[test]
fn genkey_accepts_an_explicit_private_key_path() {
    let directory = tempfile::tempdir().unwrap();
    let key_path = directory.path().join("explicit.private.json");

    etcat()
        .args(["genkey", "--client", "--key"])
        .arg(&key_path)
        .assert()
        .success()
        .stdout(predicate::str::starts_with("etcp1"));
    assert!(key_path.exists());
}

#[test]
fn genkey_delete_requires_an_explicit_key_name() {
    etcat()
        .args(["genkey", "--delete"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "genkey --delete requires --key=<name>",
        ));
}

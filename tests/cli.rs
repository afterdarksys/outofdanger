use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temp_dir(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "outofdanger-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn check_uses_documented_exit_codes() {
    let binary = env!("CARGO_BIN_EXE_outofdanger");
    let denied = Command::new(binary)
        .args([
            "check",
            "--config",
            "examples/outofdanger.conf",
            "--command",
            "rm",
            "--",
            "-rf",
            "/",
        ])
        .output()
        .unwrap();
    assert_eq!(denied.status.code(), Some(10));
    assert!(String::from_utf8(denied.stdout)
        .unwrap()
        .starts_with("deny: rm"));

    let allowed = Command::new(binary)
        .args([
            "check",
            "--config",
            "examples/outofdanger.conf",
            "--command",
            "rm",
            "--",
            "-f",
            "/tmp/harmless",
        ])
        .output()
        .unwrap();
    assert!(allowed.status.success());
}

#[test]
fn wrapper_symlink_dispatches_to_real_command() {
    let root = temp_dir("dispatch");
    let config = root.join("policy.conf");
    let wrapper = root.join("echo");
    fs::write(&config, "command echo /bin/echo\ndefault echo allow\n").unwrap();
    symlink(env!("CARGO_BIN_EXE_outofdanger"), &wrapper).unwrap();

    let output = Command::new(&wrapper)
        .env("OUT_OF_DANGER_CONFIG", &config)
        .arg("hello")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "hello\n");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn wrapper_symlink_denies_with_documented_exit_code() {
    let root = temp_dir("deny");
    let config = root.join("policy.conf");
    let wrapper = root.join("echo");
    fs::write(&config, "command echo /bin/echo\ndefault echo deny\n").unwrap();
    symlink(env!("CARGO_BIN_EXE_outofdanger"), &wrapper).unwrap();

    let output = Command::new(&wrapper)
        .env("OUT_OF_DANGER_CONFIG", &config)
        .arg("hello")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(10));
    assert_eq!(output.stdout, b"", "real command must not have run");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn wrapper_with_missing_config_fails_closed() {
    let root = temp_dir("noconfig");
    let wrapper = root.join("echo");
    symlink(env!("CARGO_BIN_EXE_outofdanger"), &wrapper).unwrap();

    let output = Command::new(&wrapper)
        .env("OUT_OF_DANGER_CONFIG", root.join("does-not-exist.conf"))
        .arg("hello")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"", "real command must not have run");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn non_utf8_arguments_reach_policy_instead_of_panicking() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let binary = env!("CARGO_BIN_EXE_outofdanger");
    let root = temp_dir("nonutf8");
    let config = root.join("policy.conf");
    fs::write(
        &config,
        "command rm /bin/rm\ndefault rm allow\ndeny rm ** /etc/** **\n",
    )
    .unwrap();

    let denied = Command::new(binary)
        .args(["check", "--config"])
        .arg(&config)
        .args(["--command", "rm", "--", "-f"])
        .arg(OsString::from_vec(b"/etc/bad\xff\xfename".to_vec()))
        .output()
        .unwrap();
    assert_eq!(
        denied.status.code(),
        Some(10),
        "stderr: {}",
        String::from_utf8_lossy(&denied.stderr)
    );

    let allowed = Command::new(binary)
        .args(["check", "--config"])
        .arg(&config)
        .args(["--command", "rm", "--", "-f"])
        .arg(OsString::from_vec(b"/tmp/bad\xff\xfename".to_vec()))
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn link_creates_working_command_symlinks() {
    let binary = env!("CARGO_BIN_EXE_outofdanger");
    let root = temp_dir("link-success");
    let config = root.join("policy.conf");
    let links = root.join("links");
    fs::write(&config, "command echo /bin/echo\ndefault echo allow\n").unwrap();

    let linked = Command::new(binary)
        .args(["link", "--config"])
        .arg(&config)
        .arg("--dir")
        .arg(&links)
        .output()
        .unwrap();
    assert!(linked.status.success());

    let dispatched = Command::new(links.join("echo"))
        .env("OUT_OF_DANGER_CONFIG", &config)
        .arg("linked")
        .output()
        .unwrap();
    assert!(dispatched.status.success());
    assert_eq!(String::from_utf8(dispatched.stdout).unwrap(), "linked\n");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn link_preflight_prevents_partial_install() {
    let binary = env!("CARGO_BIN_EXE_outofdanger");
    let root = temp_dir("link");
    let config = root.join("policy.conf");
    let links = root.join("links");
    fs::create_dir(&links).unwrap();
    fs::write(
        &config,
        "command alpha /bin/echo\ndefault alpha allow\ncommand omega /bin/echo\ndefault omega allow\n",
    )
    .unwrap();
    fs::write(links.join("omega"), "occupied").unwrap();

    let output = Command::new(binary)
        .args(["link", "--config"])
        .arg(&config)
        .arg("--dir")
        .arg(&links)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!links.join("alpha").exists());
    fs::remove_dir_all(root).unwrap();
}

fn check_at(
    root: &std::path::Path,
    config: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_outofdanger"))
        .current_dir(root)
        .args(["check", "--config"])
        .arg(config)
        .args(["--command", "rm", "--"])
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn relative_root_and_symlink_parent_cannot_bypass_guard() {
    let root = temp_dir("root-guard");
    let config = root.join("policy.conf");
    fs::write(&config, "command rm /bin/rm\ndefault rm allow\n").unwrap();
    assert_eq!(
        check_at(std::path::Path::new("/"), &config, &["-rf", "."])
            .status
            .code(),
        Some(10)
    );
    symlink("/", root.join("root-alias")).unwrap();
    assert_eq!(
        check_at(&root, &config, &["-rf", "root-alias/."])
            .status
            .code(),
        Some(10)
    );
    assert_eq!(
        check_at(&root, &config, &["-rf", "root-alias/.."])
            .status
            .code(),
        Some(10)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn protected_trees_cover_relative_symlink_missing_and_ancestor_operands() {
    let root = temp_dir("protect");
    let protected = root.join("state");
    fs::create_dir(&protected).unwrap();
    symlink(&protected, root.join("alias")).unwrap();
    let config = root.join("policy.conf");
    fs::write(
        &config,
        format!(
            "command rm /bin/rm\ndefault rm allow\nprotect rm {}\n",
            protected.display()
        ),
    )
    .unwrap();
    for args in [
        vec!["-rf", "state"],
        vec!["-f", "state/missing"],
        vec!["-rf", "alias/"],
        vec!["-rf", "."],
        vec!["-rf", "scratch", "state", "other"],
        vec!["-rf", "--", "state"],
    ] {
        assert_eq!(
            check_at(&root, &config, &args).status.code(),
            Some(10),
            "{args:?}"
        );
    }
    assert!(check_at(&root, &config, &["-rf", "state-backup"])
        .status
        .success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bulk_limit_counts_operands_and_respects_option_separator() {
    let root = temp_dir("bulk");
    let config = root.join("policy.conf");
    fs::write(
        &config,
        "command rm /bin/rm\ndefault rm allow\nmax-operands rm 2\n",
    )
    .unwrap();
    assert!(check_at(&root, &config, &["-r", "-f", "a", "b"])
        .status
        .success());
    assert_eq!(
        check_at(&root, &config, &["-rf", "a", "b", "c"])
            .status
            .code(),
        Some(10)
    );
    assert_eq!(
        check_at(&root, &config, &["--", "-a", "-b", "-c"])
            .status
            .code(),
        Some(10)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn recursive_cwd_guard_blocks_current_directory_and_ancestors() {
    let root = temp_dir("cwd");
    let config = root.join("policy.conf");
    fs::write(
        &config,
        "command rm /bin/rm\ndefault rm allow\nguard rm recursive-cwd\n",
    )
    .unwrap();
    for operand in [".", ".."] {
        assert_eq!(
            check_at(&root, &config, &["-rf", operand]).status.code(),
            Some(10)
        );
    }
    assert!(check_at(&root, &config, &["-rf", "child"]).status.success());
    assert!(check_at(&root, &config, &["-f", "."]).status.success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn emergency_lock_denies_execution_even_for_dangling_symlinks() {
    let root = temp_dir("lock");
    let config = root.join("policy.conf");
    let lock = root.join("STOP");
    fs::write(
        &config,
        format!(
            "command echo /bin/echo\ndefault echo allow\nlock-file echo {}\n",
            lock.display()
        ),
    )
    .unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_outofdanger"))
            .args(["run", "--config"])
            .arg(&config)
            .args(["--command", "echo", "--", "hello"])
            .output()
            .unwrap()
    };
    assert!(run().status.success());
    symlink(root.join("missing"), &lock).unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(10));
    assert!(output.stdout.is_empty());
    fs::remove_file(lock).unwrap();
    assert!(run().status.success());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn validation_rejects_missing_nonexecutable_and_hardlinked_wrapper_targets() {
    let root = temp_dir("validate");
    let config = root.join("policy.conf");
    let real = root.join("real");
    let validate = || {
        Command::new(env!("CARGO_BIN_EXE_outofdanger"))
            .args(["validate", "--config"])
            .arg(&config)
            .output()
            .unwrap()
    };
    fs::write(
        &config,
        format!("command echo {}\ndefault echo allow\n", real.display()),
    )
    .unwrap();
    assert_eq!(validate().status.code(), Some(2));
    fs::write(&real, "not executable").unwrap();
    assert_eq!(validate().status.code(), Some(2));
    fs::remove_file(&real).unwrap();
    fs::hard_link(env!("CARGO_BIN_EXE_outofdanger"), &real).unwrap();
    assert_eq!(validate().status.code(), Some(2));
    let run = Command::new(env!("CARGO_BIN_EXE_outofdanger"))
        .args(["run", "--config"])
        .arg(&config)
        .args(["--command", "echo", "--", "hello"])
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(2));
    assert!(run.stdout.is_empty());
    fs::write(&config, "command echo /bin/echo\ndefault echo allow\n").unwrap();
    assert!(validate().status.success());
    fs::remove_dir_all(root).unwrap();
}

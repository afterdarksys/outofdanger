use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::{env, fs};

use crate::config::{Action, CommandPolicy, Config};

#[derive(Debug, Eq, PartialEq)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
}

// Arguments are OsString end to end: Unix filenames are bytes, not UTF-8,
// and the wrapper used to panic (exit 101) on any non-Unicode argument —
// which meant the wrapped rm could not delete exactly the mojibake-named
// files rm exists to clean up.
pub fn evaluate(config: &Config, command: &str, args: &[OsString]) -> Result<Decision, String> {
    let policy = config
        .commands
        .get(command)
        .ok_or_else(|| format!("command {command:?} is not configured"))?;

    if let Some(lock) = &policy.lock_file {
        match fs::symlink_metadata(lock) {
            Ok(_) => return Ok(deny("emergency lock-file exists")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "cannot inspect lock-file {}: {error}",
                    lock.display()
                ))
            }
        }
    }
    if command == "rm" {
        let (recursive, operands) = removal_args(args);
        if policy
            .max_operands
            .is_some_and(|limit| operands.len() > limit)
        {
            return Ok(deny("operand count exceeds max-operands"));
        }
        let cwd = env::current_dir()
            .map_err(|error| format!("cannot resolve working directory: {error}"))?;
        for operand in operands {
            let path = resolved_path(Path::new(operand), &cwd)?;
            if recursive
                && (path == Path::new("/")
                    || lexical_path(Path::new(operand), &cwd) == Path::new("/"))
                && !policy.permits.contains("recursive-root")
            {
                return Ok(deny(
                    "built-in guard recursive-root (use `permit rm recursive-root` to override)",
                ));
            }
            if recursive && policy.guard_cwd && cwd.starts_with(&path) {
                return Ok(deny("guard recursive-cwd: working directory or ancestor"));
            }
            for protected in &policy.protected {
                let protected = resolved_path(protected, &cwd)?;
                if path.starts_with(&protected) || (recursive && protected.starts_with(&path)) {
                    return Ok(deny(&format!("protected tree {}", protected.display())));
                }
            }
        }
    }

    let arg_bytes: Vec<&[u8]> = args.iter().map(|arg| arg.as_os_str().as_bytes()).collect();
    for rule in &policy.rules {
        if rule.pattern.matches(&arg_bytes) {
            return Ok(Decision {
                action: rule.action,
                reason: format!("rule on config line {}", rule.line),
            });
        }
    }

    Ok(Decision {
        action: policy.default,
        reason: "command default".into(),
    })
}

pub fn command_policy<'a>(config: &'a Config, command: &str) -> Result<&'a CommandPolicy, String> {
    config
        .commands
        .get(command)
        .ok_or_else(|| format!("command {command:?} is not configured"))
}

fn deny(reason: &str) -> Decision {
    Decision {
        action: Action::Deny,
        reason: reason.into(),
    }
}

fn removal_args(args: &[OsString]) -> (bool, Vec<&OsString>) {
    let mut recursive = false;
    let mut operands = Vec::new();
    let mut options = true;
    for arg in args {
        let bytes = arg.as_os_str().as_bytes();
        if options && bytes == b"--" {
            options = false;
        } else if options && bytes.starts_with(b"--") {
            recursive |= is_recursive_long_option(&bytes[2..]);
        } else if options && bytes.starts_with(b"-") && bytes != b"-" {
            recursive |= bytes[1..].iter().any(|&flag| flag == b'r' || flag == b'R');
        } else {
            operands.push(arg);
        }
    }
    (recursive, operands)
}

fn lexical_path(path: &Path, cwd: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let mut result = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(part) => result.push(part),
            _ => {}
        }
    }
    result
}

// Resolve existing prefixes before normalizing: a symlink followed by `..`
// must use the filesystem's parent, not the symlink's lexical parent.
fn resolved_path(path: &Path, cwd: &Path) -> Result<PathBuf, String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let mut prefix = absolute.as_path();
    let mut suffix = Vec::new();
    let base = loop {
        match fs::canonicalize(prefix) {
            Ok(base) => break base,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let component = prefix
                    .components()
                    .next_back()
                    .ok_or_else(|| format!("cannot resolve {}", absolute.display()))?;
                suffix.push(component.as_os_str().to_os_string());
                prefix = prefix
                    .parent()
                    .ok_or_else(|| format!("cannot resolve {}", absolute.display()))?;
            }
            Err(error) => return Err(format!("cannot resolve {}: {error}", absolute.display())),
        }
    };
    let mut result = base;
    for part in suffix.iter().rev() {
        match Path::new(part).components().next() {
            Some(Component::ParentDir) => {
                result.pop();
            }
            Some(Component::Normal(_)) => result.push(part),
            _ => {}
        }
    }
    Ok(result)
}

/// GNU getopt_long accepts any unambiguous abbreviation of a long option, so
/// `rm --recu -f /` is a real recursive root removal on coreutils 8.30 (verified
/// on the Debian 10 fleet). Matching only the fully spelled `--recursive` left
/// every prefix of it as a way past this guard.
///
/// `--recursive` is rm's only long option beginning with `r`, so every non-empty
/// prefix of it is unambiguous and none of the other long options can collide.
/// Over-matching here would only ever deny more, which is the safe direction.
fn is_recursive_long_option(name: &[u8]) -> bool {
    let name = name.split(|&byte| byte == b'=').next().unwrap_or(name);
    !name.is_empty() && b"recursive".starts_with(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn config(extra: &str) -> Config {
        Config::parse(&format!(
            "command rm /bin/rm.real\ndefault rm allow\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn built_in_guard_catches_root_spellings_and_flag_forms() {
        for args in [
            strings(&["-rf", "/"]),
            strings(&["-R", "//"]),
            strings(&["--recursive", "/./"]),
            strings(&["-r", "--", "/"]),
            strings(&["-rf", "/tmp/.."]),
            strings(&["-rf", "/.."]),
        ] {
            assert_eq!(
                evaluate(&config(""), "rm", &args).unwrap().action,
                Action::Deny
            );
        }
    }

    #[test]
    fn built_in_guard_catches_abbreviated_long_recursive() {
        // GNU getopt_long takes any unambiguous prefix, so these are all real
        // recursive root removals on coreutils 8.30.
        for args in [
            strings(&["--recu", "-f", "/"]),
            strings(&["--recurs", "-f", "/"]),
            strings(&["--rec", "/"]),
            strings(&["--r", "/"]),
            strings(&["--recursive", "/"]),
        ] {
            assert_eq!(
                evaluate(&config(""), "rm", &args).unwrap().action,
                Action::Deny,
                "expected deny for {args:?}"
            );
        }
    }

    #[test]
    fn abbreviation_guard_does_not_swallow_other_long_options() {
        // Nothing else in rm's long-option set is a prefix of "recursive",
        // so these must stay allowed.
        for args in [
            strings(&["--verbose", "/"]),
            strings(&["--force", "/"]),
            strings(&["--interactive=never", "/"]),
            strings(&["--one-file-system", "/"]),
            strings(&["--preserve-root", "/"]),
        ] {
            assert_eq!(
                evaluate(&config(""), "rm", &args).unwrap().action,
                Action::Allow,
                "expected allow for {args:?}"
            );
        }
    }

    #[test]
    fn built_in_guard_does_not_block_non_recursive_or_non_root() {
        assert_eq!(
            evaluate(&config(""), "rm", &strings(&["-f", "/"]))
                .unwrap()
                .action,
            Action::Allow
        );
        assert_eq!(
            evaluate(&config(""), "rm", &strings(&["-rf", "/tmp"]))
                .unwrap()
                .action,
            Action::Allow
        );
    }

    #[test]
    fn permit_is_explicit_escape_hatch() {
        let decision = evaluate(
            &config("permit rm recursive-root\n"),
            "rm",
            &strings(&["-rf", "/"]),
        )
        .unwrap();
        assert_eq!(decision.action, Action::Allow);
    }

    #[test]
    fn non_utf8_arguments_evaluate_instead_of_panicking() {
        use std::os::unix::ffi::OsStringExt;
        let arg = OsString::from_vec(b"/etc/bad\xff\xfename".to_vec());
        let denied = evaluate(
            &config("deny rm ** /etc/** **\n"),
            "rm",
            &[OsString::from("-f"), arg],
        )
        .unwrap();
        assert_eq!(denied.action, Action::Deny);

        let harmless = OsString::from_vec(b"/tmp/bad\xff\xfename".to_vec());
        let allowed = evaluate(
            &config("deny rm ** /etc/** **\n"),
            "rm",
            &[OsString::from("-f"), harmless],
        )
        .unwrap();
        assert_eq!(allowed.action, Action::Allow);
    }

    #[test]
    fn protected_path_rules_need_a_trailing_double_star() {
        // A pattern must match the WHOLE argument list. Without the trailing
        // `**` a protected-path rule only fires when that path happens to be
        // the last operand, which is a footgun for a command that takes many
        // operands. Both spellings are pinned here so the difference stays
        // visible to whoever edits a policy next.
        let last_only = config("deny rm ** /etc/**\n");
        assert_eq!(
            evaluate(&last_only, "rm", &strings(&["-rf", "/etc/passwd"]))
                .unwrap()
                .action,
            Action::Deny
        );
        assert_eq!(
            evaluate(
                &last_only,
                "rm",
                &strings(&["-rf", "/etc/passwd", "/tmp/scratch"])
            )
            .unwrap()
            .action,
            Action::Allow,
            "documents the footgun: protected path is not the last operand"
        );

        let anywhere = config("deny rm ** /etc/** **\n");
        for args in [
            strings(&["-rf", "/etc/passwd"]),
            strings(&["-rf", "/etc/passwd", "/tmp/scratch"]),
            strings(&["-rf", "/tmp/scratch", "/etc/passwd"]),
            strings(&["-rf", "/tmp/a", "/etc/b", "/tmp/c"]),
        ] {
            assert_eq!(
                evaluate(&anywhere, "rm", &args).unwrap().action,
                Action::Deny,
                "expected deny for {args:?}"
            );
        }
        assert_eq!(
            evaluate(&anywhere, "rm", &strings(&["-rf", "/tmp/scratch"]))
                .unwrap()
                .action,
            Action::Allow,
            "must not over-deny unprotected paths"
        );
    }

    #[test]
    fn first_matching_rule_wins() {
        let config = config("allow rm -rf /tmp/*\ndeny rm **\n");
        assert_eq!(
            evaluate(&config, "rm", &strings(&["-rf", "/tmp/build"]))
                .unwrap()
                .action,
            Action::Allow
        );
        assert_eq!(
            evaluate(&config, "rm", &strings(&["-rf", "/var/data"]))
                .unwrap()
                .action,
            Action::Deny
        );
    }
}

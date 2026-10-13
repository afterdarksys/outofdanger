mod config;
mod matcher;
mod policy;

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use config::{Action, Config};
use policy::{command_policy, evaluate};

const DEFAULT_CONFIG: &str = "/etc/outofdanger.conf";
const DENIED_EXIT: i32 = 10;

fn main() {
    if let Err(error) = entrypoint() {
        eprintln!("outofdanger: {error}");
        process::exit(2);
    }
}

fn entrypoint() -> Result<(), String> {
    // args_os, not args: Unix arguments are bytes, and env::args() panics on
    // anything non-Unicode. Filenames with broken encodings are exactly what
    // a wrapped rm gets pointed at, so they must reach policy evaluation.
    let argv: Vec<OsString> = env::args_os().collect();
    let invoked_as = basename(argv.first().map(OsString::as_os_str));

    if invoked_as != "outofdanger" && invoked_as != "ood" {
        return run_wrapped(&invoked_as, &argv[1..], config_from_env()?);
    }

    let Some(subcommand) = argv.get(1) else {
        print_help();
        return Ok(());
    };

    match subcommand.to_str() {
        Some("check") | Some("run") => check_or_run(subcommand.to_str().unwrap(), &argv[2..]),
        Some("validate") => validate_config(&argv[2..]),
        Some("commands") => list_commands(&argv[2..]),
        Some("link") => link_commands(&argv[2..]),
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some("version") | Some("--version") | Some("-V") => {
            println!("outofdanger {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => Err(format!(
            "unknown subcommand {:?}; try `outofdanger help`",
            subcommand.to_string_lossy()
        )),
    }
}

fn check_or_run(mode: &str, args: &[OsString]) -> Result<(), String> {
    let parsed = CommonArgs::parse(args)?;
    let command = parsed
        .command
        .ok_or_else(|| "missing --command NAME".to_string())?;
    let config = Config::load(&parsed.config)?;
    if mode == "check" {
        check(&config, &command, &parsed.trailing)
    } else {
        execute(&config, &command, &parsed.trailing)
    }
}

fn run_wrapped(command: &str, args: &[OsString], config_path: PathBuf) -> Result<(), String> {
    let config = Config::load(&config_path)?;
    execute(&config, command, args)
}

fn check(config: &Config, command: &str, args: &[OsString]) -> Result<(), String> {
    let decision = evaluate(config, command, args)?;
    println!(
        "{}: {} ({})",
        decision.action.as_str(),
        command,
        decision.reason
    );
    if decision.action == Action::Deny {
        process::exit(DENIED_EXIT);
    }
    Ok(())
}

fn execute(config: &Config, command: &str, args: &[OsString]) -> Result<(), String> {
    let decision = evaluate(config, command, args)?;
    if decision.action == Action::Deny {
        eprintln!("outofdanger: denied {command}: {}", decision.reason);
        process::exit(DENIED_EXIT);
    }

    let real = &command_policy(config, command)?.real;
    validate_executable(real)?;
    // arg0 is the invoked name, not the real path: multiplexer binaries
    // (busybox, toybox) pick their applet from argv[0], and
    // `command rm /bin/busybox` should run rm, not busybox's help.
    let error = Command::new(real).arg0(command).args(args).exec();
    Err(format!("cannot execute {}: {error}", real.display()))
}

fn validate_executable(real: &Path) -> Result<(), String> {
    let metadata = fs::metadata(real)
        .map_err(|error| format!("cannot inspect real executable {}: {error}", real.display()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "real executable {} is not an executable file",
            real.display()
        ));
    }
    let current = env::current_exe()
        .and_then(fs::metadata)
        .map_err(|error| format!("cannot inspect current executable: {error}"))?;
    if current.dev() == metadata.dev() && current.ino() == metadata.ino() {
        return Err(format!(
            "real executable {} resolves back to the outofdanger wrapper",
            real.display()
        ));
    }
    Ok(())
}

fn validate_config(args: &[OsString]) -> Result<(), String> {
    let parsed = ConfigOnlyArgs::parse(args)?;
    let config = Config::load(&parsed.config)?;
    let mut names: Vec<_> = config.commands.keys().collect();
    names.sort();
    for name in names {
        validate_executable(&config.commands[name].real)?;
    }
    println!("valid: {} commands", config.commands.len());
    Ok(())
}

fn list_commands(args: &[OsString]) -> Result<(), String> {
    let parsed = ConfigOnlyArgs::parse(args)?;
    let config = Config::load(&parsed.config)?;
    let mut names: Vec<_> = config.commands.keys().collect();
    names.sort();
    for name in names {
        let policy = &config.commands[name];
        println!(
            "{name}\t{}\tdefault={}",
            policy.real.display(),
            policy.default.as_str()
        );
    }
    Ok(())
}

fn link_commands(args: &[OsString]) -> Result<(), String> {
    let parsed = LinkArgs::parse(args)?;
    let config = Config::load(&parsed.config)?;
    let executable =
        env::current_exe().map_err(|error| format!("cannot locate current executable: {error}"))?;
    fs::create_dir_all(&parsed.dir)
        .map_err(|error| format!("cannot create {}: {error}", parsed.dir.display()))?;

    let mut names: Vec<_> = config.commands.keys().collect();
    names.sort();
    for name in &names {
        let link = parsed.dir.join(name);
        match fs::symlink_metadata(&link) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("cannot inspect {}: {error}", link.display())),
            Ok(_) => {
                return Err(format!(
                    "refusing to replace existing path {}; no links were created",
                    link.display()
                ));
            }
        }
    }
    for name in names {
        let link = parsed.dir.join(name);
        symlink(&executable, &link).map_err(|error| {
            format!(
                "cannot link {} to {}: {error}",
                link.display(),
                executable.display()
            )
        })?;
        println!("linked {} -> {}", link.display(), executable.display());
    }
    Ok(())
}

fn config_from_env() -> Result<PathBuf, String> {
    match env::var_os("OUT_OF_DANGER_CONFIG") {
        Some(value) if value.is_empty() => Err("OUT_OF_DANGER_CONFIG is empty".into()),
        Some(value) => Ok(PathBuf::from(value)),
        None => Ok(PathBuf::from(DEFAULT_CONFIG)),
    }
}

fn basename(value: Option<&OsStr>) -> String {
    let value = value.unwrap_or_else(|| OsStr::new("outofdanger"));
    Path::new(value)
        .file_name()
        .unwrap_or(value)
        .to_string_lossy()
        .into_owned()
}

struct CommonArgs {
    config: PathBuf,
    command: Option<String>,
    trailing: Vec<OsString>,
}

impl CommonArgs {
    fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut config = config_from_env()?;
        let mut command = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].to_str() {
                Some("--") => {
                    return Ok(Self {
                        config,
                        command,
                        trailing: args[index + 1..].to_vec(),
                    });
                }
                Some("--config") => {
                    index += 1;
                    config = PathBuf::from(require_value(args, index, "--config")?);
                }
                Some("--command") => {
                    index += 1;
                    let value = require_value(args, index, "--command")?;
                    command = Some(
                        value
                            .to_str()
                            .ok_or_else(|| "--command name must be valid UTF-8".to_string())?
                            .to_string(),
                    );
                }
                _ => {
                    return Err(format!(
                        "unexpected option {:?}; command arguments follow --",
                        args[index].to_string_lossy()
                    ))
                }
            }
            index += 1;
        }
        Ok(Self {
            config,
            command,
            trailing: Vec::new(),
        })
    }
}

struct ConfigOnlyArgs {
    config: PathBuf,
}

impl ConfigOnlyArgs {
    fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut config = config_from_env()?;
        let mut index = 0;
        while index < args.len() {
            match args[index].to_str() {
                Some("--config") => {
                    index += 1;
                    config = PathBuf::from(require_value(args, index, "--config")?);
                }
                _ => {
                    return Err(format!(
                        "unexpected option {:?}",
                        args[index].to_string_lossy()
                    ))
                }
            }
            index += 1;
        }
        Ok(Self { config })
    }
}

struct LinkArgs {
    config: PathBuf,
    dir: PathBuf,
}

impl LinkArgs {
    fn parse(args: &[OsString]) -> Result<Self, String> {
        let mut config = config_from_env()?;
        let mut dir = None;
        let mut index = 0;
        while index < args.len() {
            match args[index].to_str() {
                Some("--config") => {
                    index += 1;
                    config = PathBuf::from(require_value(args, index, "--config")?);
                }
                Some("--dir") => {
                    index += 1;
                    dir = Some(PathBuf::from(require_value(args, index, "--dir")?));
                }
                _ => {
                    return Err(format!(
                        "unexpected option {:?}",
                        args[index].to_string_lossy()
                    ))
                }
            }
            index += 1;
        }
        Ok(Self {
            config,
            dir: dir.ok_or_else(|| "missing --dir PATH".to_string())?,
        })
    }
}

fn require_value<'a>(
    args: &'a [OsString],
    index: usize,
    option: &str,
) -> Result<&'a OsString, String> {
    args.get(index)
        .ok_or_else(|| format!("{option} requires a value"))
}

fn print_help() {
    println!(
        "outofdanger {version}\n\
         Policy wrapper for dangerous commands.\n\n\
         USAGE:\n\
           outofdanger check [--config PATH] --command NAME -- ARGS...\n\
           outofdanger run [--config PATH] --command NAME -- ARGS...\n\
           outofdanger validate [--config PATH]\n\
           outofdanger commands [--config PATH]\n\
           outofdanger link [--config PATH] --dir PATH\n\n\
         A symlink named after a configured command evaluates policy and then execs\n\
         that command's real executable. The default config is {DEFAULT_CONFIG};\n\
         override it with OUT_OF_DANGER_CONFIG or --config.\n\n\
         Denied operations exit {DENIED_EXIT}; configuration errors exit 2.",
        version = env!("CARGO_PKG_VERSION")
    );
}

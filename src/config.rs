use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::matcher::Pattern;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Allow,
    Deny,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Rule {
    pub action: Action,
    pub pattern: Pattern,
    pub line: usize,
}

#[derive(Clone, Debug)]
pub struct CommandPolicy {
    pub real: PathBuf,
    pub default: Action,
    pub rules: Vec<Rule>,
    pub permits: HashSet<String>,
    pub protected: Vec<PathBuf>,
    pub max_operands: Option<usize>,
    pub guard_cwd: bool,
    pub lock_file: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct Config {
    pub commands: HashMap<String, CommandPolicy>,
}

#[derive(Default)]
struct CommandBuilder {
    real: Option<PathBuf>,
    default: Option<Action>,
    rules: Vec<Rule>,
    permits: HashSet<String>,
    protected: Vec<PathBuf>,
    max_operands: Option<usize>,
    guard_cwd: bool,
    lock_file: Option<PathBuf>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let input = fs::read_to_string(path)
            .map_err(|error| format!("cannot read config {}: {error}", path.display()))?;
        Self::parse(&input).map_err(|error| format!("{}: {error}", path.display()))
    }

    pub fn parse(input: &str) -> Result<Self, String> {
        if input.contains('\0') {
            return Err("configuration contains a NUL byte".into());
        }
        let mut builders: HashMap<String, CommandBuilder> = HashMap::new();

        for (index, raw_line) in input.lines().enumerate() {
            let line_number = index + 1;
            let words =
                split_words(raw_line).map_err(|error| format!("line {line_number}: {error}"))?;
            if words.is_empty() {
                continue;
            }

            match words[0].as_str() {
                "command" => {
                    require_len(&words, 3, line_number, "command NAME ABSOLUTE_PATH")?;
                    validate_name(&words[1], line_number)?;
                    let real = PathBuf::from(&words[2]);
                    if !real.is_absolute() {
                        return Err(format!(
                            "line {line_number}: real command path must be absolute"
                        ));
                    }
                    let builder = builders.entry(words[1].clone()).or_default();
                    if builder.real.replace(real).is_some() {
                        return Err(format!(
                            "line {line_number}: duplicate command declaration for {}",
                            words[1]
                        ));
                    }
                }
                "default" => {
                    require_len(&words, 3, line_number, "default NAME allow|deny")?;
                    validate_name(&words[1], line_number)?;
                    let action = parse_action(&words[2], line_number)?;
                    let builder = builders.entry(words[1].clone()).or_default();
                    if builder.default.replace(action).is_some() {
                        return Err(format!(
                            "line {line_number}: duplicate default for {}",
                            words[1]
                        ));
                    }
                }
                "allow" | "deny" => {
                    if words.len() < 3 {
                        return Err(format!(
                            "line {line_number}: expected {} NAME ARG_PATTERN...",
                            words[0]
                        ));
                    }
                    validate_name(&words[1], line_number)?;
                    let action = parse_action(&words[0], line_number)?;
                    builders
                        .entry(words[1].clone())
                        .or_default()
                        .rules
                        .push(Rule {
                            action,
                            pattern: Pattern::new(words[2..].to_vec()),
                            line: line_number,
                        });
                }
                "protect" | "lock-file" => {
                    require_len(
                        &words,
                        3,
                        line_number,
                        "protect|lock-file NAME ABSOLUTE_PATH",
                    )?;
                    validate_name(&words[1], line_number)?;
                    let path = PathBuf::from(&words[2]);
                    if !path.is_absolute() {
                        return Err(format!(
                            "line {line_number}: protection path must be absolute"
                        ));
                    }
                    let builder = builders.entry(words[1].clone()).or_default();
                    if words[0] == "protect" {
                        if words[1] != "rm" {
                            return Err(format!("line {line_number}: protect supports only rm"));
                        }
                        builder.protected.push(path);
                    } else if builder.lock_file.replace(path).is_some() {
                        return Err(format!("line {line_number}: duplicate lock-file"));
                    }
                }
                "max-operands" => {
                    require_len(&words, 3, line_number, "max-operands rm POSITIVE_INTEGER")?;
                    if words[1] != "rm" {
                        return Err(format!("line {line_number}: max-operands supports only rm"));
                    }
                    let limit = words[2]
                        .parse::<usize>()
                        .ok()
                        .filter(|n| *n > 0)
                        .ok_or_else(|| {
                            format!("line {line_number}: operand limit must be positive")
                        })?;
                    if builders
                        .entry(words[1].clone())
                        .or_default()
                        .max_operands
                        .replace(limit)
                        .is_some()
                    {
                        return Err(format!("line {line_number}: duplicate max-operands"));
                    }
                }
                "guard" => {
                    require_len(&words, 3, line_number, "guard rm recursive-cwd")?;
                    if words[1] != "rm" || words[2] != "recursive-cwd" {
                        return Err(format!(
                            "line {line_number}: supported guard is rm recursive-cwd"
                        ));
                    }
                    builders.entry(words[1].clone()).or_default().guard_cwd = true;
                }
                "permit" => {
                    require_len(&words, 3, line_number, "permit NAME OPERATION")?;
                    validate_name(&words[1], line_number)?;
                    if words[2] != "recursive-root" || words[1] != "rm" {
                        return Err(format!(
                            "line {line_number}: unknown operation {}; supported: recursive-root",
                            words[2]
                        ));
                    }
                    builders
                        .entry(words[1].clone())
                        .or_default()
                        .permits
                        .insert(words[2].clone());
                }
                directive => {
                    return Err(format!("line {line_number}: unknown directive {directive}"));
                }
            }
        }

        let mut commands = HashMap::new();
        for (name, builder) in builders {
            let real = builder
                .real
                .ok_or_else(|| format!("command {name} has policy but no command declaration"))?;
            let default = builder
                .default
                .ok_or_else(|| format!("command {name} has no explicit default"))?;
            commands.insert(
                name,
                CommandPolicy {
                    real,
                    default,
                    rules: builder.rules,
                    permits: builder.permits,
                    protected: builder.protected,
                    max_operands: builder.max_operands,
                    guard_cwd: builder.guard_cwd,
                    lock_file: builder.lock_file,
                },
            );
        }

        if commands.is_empty() {
            return Err("configuration defines no commands".into());
        }
        Ok(Self { commands })
    }
}

fn require_len(words: &[String], expected: usize, line: usize, usage: &str) -> Result<(), String> {
    if words.len() == expected {
        Ok(())
    } else {
        Err(format!("line {line}: expected {usage}"))
    }
}

fn parse_action(word: &str, line: usize) -> Result<Action, String> {
    match word {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        _ => Err(format!("line {line}: action must be allow or deny")),
    }
}

fn validate_name(name: &str, line: usize) -> Result<(), String> {
    // "." and ".." would make `link` create paths outside --dir, and a
    // leading "-" makes the name look like an option everywhere it is used.
    if name.is_empty()
        || name == "outofdanger"
        || name == "ood"
        || name == "."
        || name == ".."
        || name.starts_with('-')
        || name.contains('/')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
    {
        Err(format!("line {line}: invalid command name {name:?}"))
    } else {
        Ok(())
    }
}

fn split_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut chars = line.chars().peekable();
    let mut quote = None;
    let mut started = false;

    while let Some(character) = chars.next() {
        if character != '#' && (!character.is_whitespace() || quote.is_some()) {
            started = true;
        }
        match (quote, character) {
            (None, '#') => break,
            (None, '\'' | '"') => quote = Some(character),
            (Some(expected), found) if expected == found => quote = None,
            (_, '\\') => {
                let escaped = chars.next().ok_or_else(|| "trailing escape".to_string())?;
                current.push(escaped);
            }
            (None, found) if found.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (_, found) => current.push(found),
        }
    }
    if quote.is_some() {
        return Err("unterminated quote".into());
    }
    if started {
        words.push(current);
    }
    Ok(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_empty_arguments_and_rejects_invalid_protections() {
        assert_eq!(
            split_words("allow rm '' \"\" x").unwrap(),
            ["allow", "rm", "", "", "x"]
        );
        for directive in [
            "protect rm relative",
            "max-operands rm 0",
            "max-operands echo 2",
            "guard rm typo",
            "lock-file rm relative",
            "permit echo recursive-root",
        ] {
            assert!(Config::parse(&format!(
                "command rm /bin/rm\ndefault rm allow\n{directive}\n"
            ))
            .is_err());
        }
        for name in ["ood", "outofdanger"] {
            assert!(
                Config::parse(&format!("command {name} /bin/echo\ndefault {name} allow\n"))
                    .is_err()
            );
        }
        assert!(Config::parse("command rm /bin/rm\0\ndefault rm allow").is_err());
    }

    #[test]
    fn parses_a_complete_policy() {
        let config = Config::parse(
            "command rm /bin/rm.real\n\
             default rm deny\n\
             allow rm -f /tmp/*\n\
             permit rm recursive-root\n",
        )
        .unwrap();
        let rm = &config.commands["rm"];
        assert_eq!(rm.default, Action::Deny);
        assert_eq!(rm.rules.len(), 1);
        assert!(rm.permits.contains("recursive-root"));
    }

    #[test]
    fn rejects_implicit_defaults() {
        let error = Config::parse("command rm /bin/rm.real\n").unwrap_err();
        assert!(error.contains("no explicit default"));
    }

    #[test]
    fn rejects_pathological_command_names() {
        for name in [".", "..", "-rf", "--force", "a/b", ""] {
            let error = Config::parse(&format!("command {name} /bin/echo\ndefault {name} allow\n"))
                .unwrap_err();
            assert!(
                error.contains("invalid command name") || error.contains("expected"),
                "name {name:?} must be rejected, got: {error}"
            );
        }
    }

    #[test]
    fn supports_quotes_and_comments() {
        let words = split_words("allow rm 'hello world' \"a#b\" # comment").unwrap();
        assert_eq!(words, ["allow", "rm", "hello world", "a#b"]);
    }
}

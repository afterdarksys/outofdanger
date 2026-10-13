#[derive(Clone, Debug)]
pub struct Pattern {
    tokens: Vec<String>,
}

impl Pattern {
    pub fn new(tokens: Vec<String>) -> Self {
        Self { tokens }
    }

    pub fn matches(&self, args: &[&[u8]]) -> bool {
        match_tokens(&self.tokens, args)
    }
}

// Both matchers are iterative with a single backtrack point (the classic
// two-pointer wildcard algorithm). The obvious recursive version is
// exponential: against a pattern like `/data/*a*a*a*a*b`, a 35-byte argument
// already took 8+ seconds, and arguments are caller-controlled — a policy
// wrapper that can be hung by a weird filename takes the wrapped command
// down with it. Tracking only the most recent star is sufficient because a
// later star supersedes any earlier backtrack opportunity.

/// `**` matches zero or more complete arguments; every other token must
/// glob-match exactly one argument.
fn match_tokens(pattern: &[String], values: &[&[u8]]) -> bool {
    let (mut p, mut v) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while v < values.len() {
        if p < pattern.len() && pattern[p] == "**" {
            star = Some((p + 1, v));
            p += 1;
        } else if p < pattern.len() && glob(pattern[p].as_bytes(), values[v]) {
            p += 1;
            v += 1;
        } else if let Some((after_star, consumed)) = star {
            p = after_star;
            v = consumed + 1;
            star = Some((after_star, consumed + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|token| token == "**")
}

/// `*` matches any run of bytes, `?` exactly one byte, inside one argument.
fn glob(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while v < value.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some((p + 1, v));
            p += 1;
        } else if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if let Some((after_star, consumed)) = star {
            p = after_star;
            v = consumed + 1;
            star = Some((after_star, consumed + 1));
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(tokens: &[&str]) -> Pattern {
        Pattern::new(tokens.iter().map(|token| token.to_string()).collect())
    }

    fn matches(p: &Pattern, values: &[&str]) -> bool {
        let bytes: Vec<&[u8]> = values.iter().map(|value| value.as_bytes()).collect();
        p.matches(&bytes)
    }

    #[test]
    fn wildcard_handles_literal_stars_in_filenames() {
        assert!(matches(&pattern(&["*a"]), &["*ba"]));
        assert!(matches(&pattern(&["*?"]), &["**"]));
        assert!(!matches(&pattern(&["*a"]), &["*b"]));
    }

    #[test]
    fn token_globs_match_one_argument() {
        let p = pattern(&["-?f", "/tmp/*"]);
        assert!(matches(&p, &["-rf", "/tmp/build"]));
        assert!(!matches(&p, &["-rf", "/var/build"]));
    }

    #[test]
    fn double_star_matches_multiple_arguments() {
        let p = pattern(&["**", "/protected"]);
        assert!(matches(&p, &["-r", "-f", "/protected"]));
        assert!(matches(&p, &["/protected"]));
        assert!(!matches(&p, &["/protected", "extra"]));
    }

    #[test]
    fn double_star_matches_zero_arguments_anywhere() {
        assert!(matches(&pattern(&["**"]), &[]));
        assert!(matches(&pattern(&["**", "**"]), &[]));
        assert!(matches(&pattern(&["a", "**"]), &["a"]));
        assert!(matches(&pattern(&["**", "a", "**"]), &["a"]));
        assert!(!matches(&pattern(&["**", "a", "**"]), &["b"]));
    }

    #[test]
    fn multiple_double_stars_backtrack_correctly() {
        let p = pattern(&["**", "a", "**", "b", "**"]);
        assert!(matches(&p, &["x", "a", "y", "b", "z"]));
        assert!(matches(&p, &["a", "b"]));
        assert!(matches(&p, &["a", "a", "b", "b"]));
        assert!(!matches(&p, &["b", "a"]));
    }

    #[test]
    fn glob_star_edges() {
        assert!(matches(&pattern(&["*"]), &[""]));
        assert!(matches(&pattern(&["a*"]), &["a"]));
        assert!(matches(&pattern(&["*a"]), &["aaa"]));
        assert!(matches(&pattern(&["a**b"]), &["ab"]));
        assert!(!matches(&pattern(&["?"]), &[""]));
    }

    #[test]
    fn adversarial_backtracking_finishes_instantly() {
        // The recursive matcher needed >8s at 35 bytes and effectively forever
        // at 60; the iterative one must stay O(pattern * value).
        let p = pattern(&["**", "/data/*a*a*a*a*a*a*a*a*a*a*a*b", "**"]);
        let long = format!("/data/{}", "a".repeat(4096));
        let start = std::time::Instant::now();
        assert!(!matches(&p, &["-f", &long]));
        assert!(
            start.elapsed() < std::time::Duration::from_millis(200),
            "matcher backtracking is super-linear again"
        );
    }

    #[test]
    fn matches_arbitrary_bytes_not_just_utf8() {
        let p = pattern(&["/tmp/*"]);
        assert!(p.matches(&[b"/tmp/bad\xff\xfename".as_slice()]));
        assert!(!p.matches(&[b"/var/bad\xff\xfename".as_slice()]));
    }
}

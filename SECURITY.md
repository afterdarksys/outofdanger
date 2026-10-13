# Security policy

Out of Danger is a fail-closed safety rail in front of commands such as `rm`.
Its whole value is that it refuses, so a way past a refusal is the most serious
kind of bug it can have. Please report it privately first.

## How to report

Use GitHub's **private vulnerability reporting** on this repository: the
**Security** tab, then **Report a vulnerability**. The report is visible only
to the maintainers until an advisory is published.

Please do not open a public issue or pull request for a bypass, and do not
post a working bypass anywhere public until a fix is released.

A useful report includes:

- the commit or release you tested;
- the policy file and the exact command line that gets past the wrapper, made
  minimal if you can (`outofdanger check --config ... --command ... -- ...` is
  ideal);
- what the wrapper should have done (deny, exit 2) and what it did instead;
- ideally, a failing test in the style of `tests/` or the unit tests in `src/`.

Please test in a scratch directory or a throwaway machine, never on data you
cannot afford to lose.

## What counts as a bypass

Anything that lets an invocation through the wrapper do what its policy says it
must not. In particular:

- **Reaching a denied operation**: any spelling, flag form, quoting, relative
  path, symlink, `..` sequence or non-UTF-8 argument that gets a `deny` rule, a
  `protect` tree, `max-operands`, `guard rm recursive-cwd` or the built-in
  recursive-root guard to allow what it should deny.
- **Failing open**: a malformed policy, an unreadable lock file, a metadata
  error or an invalid real path that results in the real command running
  instead of a refusal.
- **Choosing the wrong executable**: the wrapper executing anything other than
  the configured real path for the invoked name, or recursing into itself
  through a symlink or hard link that `validate` accepts.
- **Link installation clobbering**: `link` replacing or following an existing
  path it should have refused.

## What is not a bypass

- Running the real executable directly (for example `/bin/rm`), or any command
  path that does not resolve to the wrapper. The README documents this: the
  wrapper is a safety rail, not a security boundary.
- Filesystem changes that race evaluation and execution, and the documented
  lexical limits of argument globs. A way around a limit that the README claims
  is covered is in scope.
- Anything that requires already being able to edit the policy file or the
  installed binary.

## Supported versions

Only the latest release and the latest commit on the default branch are
supported. Fixes are made there.

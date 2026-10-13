# Out of Danger

Out of Danger is a small, fail-closed policy wrapper for commands such as `rm`.
One binary can be symlinked under several command names. It reads the invoked
name, evaluates that command's policy, and replaces itself with the configured
real executable only when the operation is allowed.

It does not make the real executable inaccessible. Its purpose is to make the
normal command path safer and auditable, not to be a security boundary against
a user who can invoke the real executable directly.

## Build

```sh
cargo build --release
```

The resulting binary is `target/release/outofdanger` and has no third-party
runtime or build dependencies.

## Policy file

See [`examples/outofdanger.conf`](examples/outofdanger.conf):

```text
command rm /bin/rm
default rm allow
protect rm /etc
protect rm /var/lib
```

Each configured command requires:

- `command NAME ABSOLUTE_REAL_PATH`
- `default NAME allow|deny`

Ordered `allow` and `deny` rules follow the form `ACTION NAME ARG_PATTERN...`.
The first matching rule wins. `*` and `?` match characters inside one argument;
the token `**` matches zero or more complete arguments. Values may use single or
double quotes and `#` begins a comment outside quotes.

Recursive removal of `/`, `//`, relative paths resolving to root, and equivalent root spellings has an additional
built-in guard. Deliberately disabling it requires `permit rm recursive-root`.

## Additional safety controls

```text
protect rm /etc
protect rm /var/lib
max-operands rm 20
guard rm recursive-cwd
lock-file rm /etc/outofdanger.STOP
```

- `protect rm PATH` denies removal of the directory itself or its descendants,
  and recursive removal of its ancestors. It resolves relative operands and
  existing symlink prefixes, including missing leaf paths. Paths must be absolute.
- `max-operands rm N` denies removal of more than N operands, regardless of
  whether recursion is enabled. N must be positive; flags do not count, and
  arguments after `--` count as operands.
- `guard rm recursive-cwd` denies recursive removal of the current directory
  or any ancestor, preventing accidents such as `rm -rf .`.
- `lock-file NAME PATH` denies every invocation of NAME while PATH exists,
  including a dangling symlink. Inspection errors fail closed. Remove the file
  to resume operations. Use a dedicated path in a directory you control.
- `outofdanger validate --config PATH` checks policy syntax and all real command
  targets without executing them. Missing targets, non-executable files,
  directories, and links back to this wrapper (including hard links) fail.

These controls run before ordered argument rules; an `allow` rule cannot
bypass them. Only the recursive-root guard has a `permit` override. Tree,
operand-count, and working-directory controls support `rm` only. Command names
`outofdanger` and `ood` are reserved for the wrapper's management interface.

## Try it without installing

```sh
target/release/outofdanger check \
  --config examples/outofdanger.conf --command rm -- -rf /
```

An allowed check exits 0. A denied check exits 10, while configuration and usage
errors exit 2. To evaluate and execute a command explicitly, replace `check`
with `run`.

## Install safely

Do not replace operating-system binaries. Put wrapper symlinks in a dedicated
directory earlier in `PATH`:

```sh
install -d "$HOME/.local/lib/outofdanger" "$HOME/.local/bin/outofdanger-wrappers"
install -m 0755 target/release/outofdanger "$HOME/.local/lib/outofdanger/outofdanger"
"$HOME/.local/lib/outofdanger/outofdanger" link \
  --config "$PWD/examples/outofdanger.conf" \
  --dir "$HOME/.local/bin/outofdanger-wrappers"
```

Set `OUT_OF_DANGER_CONFIG` to the deployed policy path and prepend the wrapper
directory to `PATH`. The `link` command creates only missing links and refuses
to replace any existing path.

For system deployment, use the same layout under `/usr/local`, keep the real
paths pointed at the operating-system executables, and deploy the policy as
`/etc/outofdanger.conf`. Avoid renaming package-managed binaries: upgrades often
replace them and can silently bypass or break the wrapper.

## Limitations

- The built-in root guard and optional path/count guards understand `rm`;
  other commands use argument rules and optional emergency locks.
- Argument globs are lexical. They do not resolve symlinks, shell expansions,
  working-directory-relative paths, or command-specific semantics. Use `protect`
  for filesystem tree protection.
- The wrapper controls only invocations that resolve to its symlink in `PATH`.
  Direct invocation of the real path remains possible by design.


Filesystem resolution is conservative: symlink operands can be denied even
when `rm` would only unlink the symlink. Paths can change between evaluation
and execution; these controls do not provide atomic filesystem enforcement.
Validation checks executable mode bits, not ACLs or mount execution restrictions.

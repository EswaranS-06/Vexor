# tests

## split_equivalence.sh

Proof that `vexor` + `lib/*.sh` (the working tree) is the former single-file `vexor` cut into
modules and nothing else. Run it from anywhere, as an ordinary user (no root, no Docker, no `.env`):

```bash
tests/split_equivalence.sh          # compare against main:vexor
tests/split_equivalence.sh 017a04f  # or any ref that still has the single file
```

It checks (a) the text: `vexor` with each `. "$ROOT/lib/X.sh"` line replaced by that module
(minus its 3-line header) reproduces the old file line for line, except the loader lines and the
edits listed in `ALLOWED_EDITS` inside the script; (b) the same 505 functions with identical
bodies (`declare -f`) and the same globals (`declare -p`) after sourcing both without the final
`main` call; (c) `bash -n`, LF endings, modes (vexor 755, modules 644, no shebang); (d) identical
output and exit codes of `help`, `version`, `completion` (also through a symlink on `PATH`), the
console Python tests; (e) the CI step "Generated compose files match the committed ones".
Exit 0 and `RESULT: equivalent` when everything holds. Commands that need root, `.env` or Docker
(`plan`, `status`, `doctor`, ...) are not run.

The REF must be a single-file commit: once the split is merged into main, pass the commit
before the merge. Later refactoring phases change function bodies on purpose, so the proof
applies to the split itself.

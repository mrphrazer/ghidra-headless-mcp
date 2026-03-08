# Releasing `ghidra-headless-mcp`

This repository is prepared for GitHub source releases. It does not publish to PyPI.

## Blocking prerequisite

Do not create a public release tag until the repository license is chosen and committed.

## Release checklist

1. Confirm the worktree is clean.
2. Update `ghidra_headless_mcp/_version.py` (which feeds `ghidra_headless_mcp.__version__`).
3. Move the pending release notes from `CHANGELOG.md` into a dated version section.
4. Run the required gates locally:

```bash
python3 -m ruff check .
python3 -m ruff format --check .
python3 -m pytest -m "not live"
GHIDRA_INSTALL_DIR=/usr/share/ghidra python3 -m pytest -m live
tmpdir="$(mktemp -d)"
git archive --format=tar HEAD | tar -xf - -C "$tmpdir"
python3 -m pip wheel "$tmpdir" --no-deps --no-build-isolation --no-cache-dir -w "$tmpdir/dist"
python3 -m pip install "$tmpdir"/dist/*.whl --no-deps --target "$tmpdir/install"
test -x "$tmpdir/install/bin/ghidra-headless-mcp"
test -x "$tmpdir/install/bin/ghidra_headless_mcp"
```

5. Commit the version and changelog update.
6. Create and push a signed tag named `vX.Y.Z`.
7. Wait for the required GitHub Actions jobs to pass on the tag:
   - `lint-format`
   - `package-build`
   - `fake-backend-tests`
   - `live-ghidra-tests`
8. Download the wheel artifact produced by `package-build` on the tag if you want to attach it to the GitHub Release.
9. Create the GitHub Release from the tag and paste the matching changelog notes.

## Notes

- The `package-build` job builds from a clean `git archive` copy so tracked source state, not local build residue, defines the release artifact.
- The live test gate expects Ghidra at `/usr/share/ghidra`.

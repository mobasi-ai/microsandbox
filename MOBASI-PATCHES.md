# Mobasi patches

This branch is upstream `superradcompany/microsandbox` tag `v0.7.13`
(`44c1e63176259e048f42893a5779de8b08fe0ec6`) plus the patches below.
Version numbers do not change: `msb --version` prints `0.7.13`.

The workflow `.github/workflows/mobasi-runtime.yml` builds the Windows
runtime archive `microsandbox-windows-x86_64.zip` from this branch and
publishes it as a release asset with its SHA-256 and `provenance.json`.

## Carried patches

### 1. libkrun: look up the WHP vCPU state functions at run time

- Upstream PR: https://github.com/superradcompany/libkrun/pull/177
- Source: `mobasi-ai/libkrun` branch `fix/whp-state-runtime-lookup`,
  rev `7291cb9f5be6b45305e4c725d6c778f3d9c87f29`. It sits on upstream
  libkrun `cd518196`, which is `msb_krun` 0.1.42 plus one CI-only commit.
- How: `[patch.crates-io]` in `Cargo.toml` replaces all 11 `msb_krun*`
  crates with that git rev. In `Cargo.lock`, only the source of the
  `msb_krun*` crates changes.
- Why: `msb.exe` from upstream imports `WHvGetVirtualProcessorState` and
  `WHvSetVirtualProcessorState` from `winhvplatform.dll`. Windows 10 does
  not export them, so `msb.exe` does not load there. The patch finds them
  at run time. A vCPU state capture or restore (snapshot) fails with a
  clear error when they are missing; other features work on Windows 10.
- Targets: Windows x86_64 (`x86_64-pc-windows-msvc`). Other targets build
  the same code as before.
- Drop when: an upstream microsandbox release pins an `msb_krun` version
  that contains libkrun#177. Then rebase on that release and delete the
  `[patch.crates-io]` section.

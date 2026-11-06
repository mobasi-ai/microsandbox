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
  rev `7291cb9f5be6b45305e4c725d6c778f3d9c87f29` (now carried inside rev `8c94998f`, see patch 2). It sits on upstream
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

### 2. libkrun: give unplugged virtio-mem memory back on macOS and Windows (spike)

- Upstream PR: none yet (spike, 2026-11-06).
- Source: `mobasi-ai/libkrun` branch `mobasi/dynamic-memory`, rev
  `8c94998f94410e99685b740ff7d09fd93baba101`, on top of patch 1.
- How: the `[patch.crates-io]` table points all 11 `msb_krun*` crates and
  `msb-vm-memory` at that rev. The libkrun branch vendors `msb-vm-memory`
  0.18.0-msb.2 under `third_party/` with one added constructor,
  `MmapRegion::new_reserved` (Windows).
- Why: `msb run --memory 1G --max-memory 6G` committed 6 GiB on Windows at
  boot (error 1455 when the commit limit is short), and an unplug on macOS or
  Windows wrote zeros into the block instead of releasing it, so a shrink
  made the host use more memory. Linux was already correct.
- What: Windows reserves the hotplug region, commits and maps each block on
  plug (a refused commit answers NACK), and unmaps and decommits it on unplug.
  macOS unmaps an unplugged block, replaces its pages, and maps it again;
  its free page reporting uses `MADV_FREE_REUSABLE`.
- Targets: Windows x86_64 and macOS aarch64. Linux builds the same code as
  before.
- Not done: snapshot capture and dirty tracking of blocks that Windows maps
  after boot.

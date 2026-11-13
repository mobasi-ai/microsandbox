# Mobasi patches

This branch is upstream `superradcompany/microsandbox` tag `v0.7.15`
(`6ab7ba993ee0e85074036ade7a9833390a6cea2d`) plus the patch below.
Version numbers do not change: `msb --version` prints `0.7.15`.

The workflow `.github/workflows/mobasi-runtime.yml` builds the Windows
runtime archive `microsandbox-windows-x86_64.zip` from this branch and
publishes it as a release asset with its SHA-256 and `provenance.json`.
It does not build the macOS and Linux archives yet.

## Carried patch

### libkrun: give unplugged virtio-mem memory back on macOS and Windows

- Upstream PR: none.
- Source: `mobasi-ai/libkrun` branch `mobasi/dynamic-memory-v2`, rev
  `be121d0ac64af93b9526f893a2fb1601ec3f9ce6`. It sits on upstream libkrun
  `344cb248`, which is `msb_krun` 0.1.45, the version that v0.7.15 pins.
- How: `[patch.crates-io]` in `Cargo.toml` replaces all 11 `msb_krun*`
  crates and `msb-vm-memory` with that git rev. In `Cargo.lock`, only the
  source of those crates changes. The libkrun branch has a copy of
  `msb-vm-memory` 0.18.0-msb.2 under `third_party/` with one added
  function, `MmapRegion::new_reserved` (Windows).
- Why: `msb run --memory 1G --max-memory 6G` committed 6 GiB on Windows at
  boot (error 1455 when the commit limit is short), and an unplug on macOS
  or Windows wrote zeros into the block and did not release it. Linux was
  already correct.
- What: Windows reserves the hotplug region, commits and maps a range when
  the guest plugs it, and unmaps and decommits it when the guest unplugs
  it. macOS unmaps an unplugged range, puts new zero pages in its place,
  and maps it again. The design, the rules against a hostile guest, the
  limits, and the tests are in `MOBASI-VIRTIO-MEM.md` of the libkrun
  branch.
- Targets: Windows x86_64 and macOS aarch64. Linux builds the same
  behavior as upstream.
- Not supported on Windows for a VM with `--max-memory` above
  `--memory`: memory capture, restore, and dirty tracking. The calls
  return an error.
- Tests: `scripts/mobasi-dynamic-memory` (end to end), and the unit,
  model, fuzz, and real-partition tests of the libkrun branch.
- Drop when: upstream gives unplugged memory back on macOS and Windows.

## Patches that are not carried now

- libkrun: look up the WHP vCPU state functions at run time (Windows 10).
  Upstream merged it as libkrun#177. It is in `msb_krun` 0.1.43 and later,
  so v0.7.14 and later have it.

## Move to a new upstream release

1. Rebase the libkrun branch on the upstream commit of the `msb_krun`
   version that the release pins. If `msb-vm-memory` has a new version,
   copy it to `third_party/msb-vm-memory` and add `new_reserved` again.
2. Run the libkrun tests on macOS, Linux, and Windows.
3. Make this branch again from the release tag: the patch table in
   `Cargo.toml`, `Cargo.lock`, this file, the workflow, and the scripts.
4. Build on each target and run the scripts in
   `scripts/mobasi-dynamic-memory`.

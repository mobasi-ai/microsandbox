# Dynamic memory spike tests

These scripts are the manual tests of the dynamic memory patch (patch 2 in
`MOBASI-PATCHES.md`). They are not part of an automatic test suite. Each script
takes the path of an `msb` program and an empty `MSB_HOME` folder, so you can
run the same test on the upstream runtime and on the patched runtime.

| Script | Platform | What it does |
| --- | --- | --- |
| `dm-test.sh` | macOS, Linux | Starts a VM at 1 GiB with a 6 GiB limit. Grows it to 4 GiB, fills 2.5 GiB in the guest, frees it, and shrinks to 1 GiB. Prints host and guest memory at each step. |
| `dm-test.ps1` | Windows | The same steps. Prints the commit and the RAM of the VM process. |
| `dm-auto.sh` | macOS, Linux | A prototype of automatic sizing. Grows the VM when the guest has little free memory and shrinks it when the guest is calm. |
| `dm-auto.ps1` | Windows | The same prototype. |
| `dm-nack.ps1` | Windows | Puts only the VM process in a job object with a memory limit, then asks for more memory than the limit permits. The VM must stay alive at its current size. |

Usage:

```sh
scripts/mobasi-dynamic-memory/dm-test.sh <msb> <msb-home> <label>
```

```powershell
scripts\mobasi-dynamic-memory\dm-test.ps1 -Msb <msb.exe> -MsbHome <folder> -Label <label>
```

Do not put the full `msb` command in the job object of `dm-nack.ps1`. A limit
on the command makes `msb modify` start the sandbox again.

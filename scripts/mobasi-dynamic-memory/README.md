# Dynamic memory tests

These scripts are the manual end-to-end tests of the dynamic memory patch (see
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
| `dm-storm.sh`, `dm-storm.ps1` | all | Resize storm with a data check. The guest (`guest-storm.sh`) holds 1.2 GiB of checksummed data in memory and works on memory and disk, while the host sets a random size between 2 GiB and 6 GiB again and again. The data must stay correct, the VM process must live, and the host memory must go back after a shrink. |
| `dm-hostile.sh`, `dm-hostile.ps1` | all | Hostile guest. A root program in the guest (`hostile.c`, built in the guest) takes the virtio-mem device from the kernel (`guest-hostile-prepare.sh`) and drives it through `/dev/mem` on the real hypervisor: random and hostile requests against a model with data checks, a race of memory access against plug and unplug, and access to memory that is not plugged. On macOS and Linux the VM must live. On Windows the VM must live through the requests, and must stop without a crash of the VMM when the guest reads memory that is not plugged. |

Usage:

```sh
scripts/mobasi-dynamic-memory/dm-test.sh <msb> <msb-home> <label>
```

```powershell
scripts\mobasi-dynamic-memory\dm-test.ps1 -Msb <msb.exe> -MsbHome <folder> -Label <label>
```

Do not put the full `msb` command in the job object of `dm-nack.ps1`. A limit
on the command makes `msb modify` start the sandbox again.

The storm and hostile tests take the same arguments as `dm-test`. The hostile test needs
network access in the guest, to install a compiler. Do not change a script while it runs.

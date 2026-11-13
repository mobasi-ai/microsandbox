# Refused-commit test for the patched msb.exe. ASCII only.
# After boot, the VM process alone joins a job object whose per-process memory
# limit is its commit plus $LimitGB, so a commit above it fails inside the VM
# process only, as a full commit limit would.
param([string]$Msb, [string]$MsbHome, [double]$LimitGB = 2.5, [string]$Ask = "5G")
$ErrorActionPreference = "Continue"
$env:MSB_HOME = $MsbHome
New-Item -ItemType Directory -Force -Path $MsbHome | Out-Null
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Job {
  [StructLayout(LayoutKind.Sequential)] struct BASIC { public long a; public long b; public uint LimitFlags; public UIntPtr c; public UIntPtr d; public uint e; public UIntPtr f; public uint g; public uint h; }
  [StructLayout(LayoutKind.Sequential)] struct IO { public ulong a,b,c,d,e,f; }
  [StructLayout(LayoutKind.Sequential)] struct EXT { public BASIC Basic; public IO Io; public UIntPtr ProcessMemoryLimit; public UIntPtr JobMemoryLimit; public UIntPtr PeakProcess; public UIntPtr PeakJob; }
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr CreateJobObject(IntPtr a, string n);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr j, int c, ref EXT i, uint l);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr j, IntPtr p);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
  public static string LimitPid(int pid, ulong bytes) {
    IntPtr j = CreateJobObject(IntPtr.Zero, null);
    if (j == IntPtr.Zero) return "CreateJobObject " + Marshal.GetLastWin32Error();
    EXT e = new EXT(); e.Basic.LimitFlags = 0x100; e.ProcessMemoryLimit = new UIntPtr(bytes);
    if (!SetInformationJobObject(j, 9, ref e, (uint)Marshal.SizeOf(typeof(EXT)))) return "SetInformationJobObject " + Marshal.GetLastWin32Error();
    IntPtr p = OpenProcess(0x0101, false, pid);
    if (p == IntPtr.Zero) return "OpenProcess " + Marshal.GetLastWin32Error();
    if (!AssignProcessToJobObject(j, p)) return "AssignProcessToJobObject " + Marshal.GetLastWin32Error();
    return "ok";
  }
  public static string LimitSelf(ulong bytes) {
    IntPtr j = CreateJobObject(IntPtr.Zero, null);
    if (j == IntPtr.Zero) return "CreateJobObject " + Marshal.GetLastWin32Error();
    EXT e = new EXT(); e.Basic.LimitFlags = 0x100; e.ProcessMemoryLimit = new UIntPtr(bytes);
    if (!SetInformationJobObject(j, 9, ref e, (uint)Marshal.SizeOf(typeof(EXT)))) return "SetInformationJobObject " + Marshal.GetLastWin32Error();
    if (!AssignProcessToJobObject(j, GetCurrentProcess())) return "AssignProcessToJobObject " + Marshal.GetLastWin32Error();
    return "ok";
  }
}
"@
function Step($t) { Write-Output ("== {0} {1}" -f (Get-Date).ToUniversalTime().ToString("HH:mm:ss"), $t) }
function Show {
  $m = (& $Msb exec dm-nack -- head -1 /proc/meminfo 2>&1 | ForEach-Object { ($_ -replace "\s+", " ").Trim() }) -join " "
  Write-Output "  guest $m"
  $vp = Get-CimInstance Win32_Process -Filter "Name='msb.exe'" | Where-Object { $_.CommandLine -match "machine --name dm-nack" } | Select-Object -First 1
  if ($vp) { $v = Get-Process -Id $vp.ProcessId; Write-Output ("  VM pid {0} commit {1:N2} GB, RAM {2:N2} GB, started {3}" -f $v.Id, ($v.PagedMemorySize64/1GB), ($v.WorkingSet64/1GB), $v.StartTime) } else { Write-Output "  no VM process" }
}
& $Msb remove -f dm-nack 2>&1 | Out-Null
Step "boot --memory 1G --max-memory 6G"
& $Msb run -d -n dm-nack --memory 1G --max-memory 6G alpine -- sleep 100000 2>$null | Select-Object -Last 2
Start-Sleep 3; Show
$vmp = Get-CimInstance Win32_Process -Filter "Name='msb.exe'" | Where-Object { $_.CommandLine -match "machine --name dm-nack" } | Select-Object -First 1
$vm = Get-Process -Id $vmp.ProcessId
$limit = [uint64]($vm.PagedMemorySize64 + $LimitGB * 1GB)
Step ("VM pid {0} commit {1:N2} GB; job limit {2:N2} GB: {3}" -f $vm.Id, ($vm.PagedMemorySize64/1GB), ($limit/1GB), [Job]::LimitPid($vm.Id, $limit))
Step "modify --memory $Ask (more than the limit allows)"
& $Msb modify dm-nack --memory $Ask 2>$null | Select-Object -Last 3
Start-Sleep 20
Step "logs of the first VM, before anything restarts it"
Get-Content "$MsbHome\sandboxes\dm-nack\logs\runtime.log" -Tail 25 -ErrorAction SilentlyContinue
Write-Output "-- kernel.log:"
Get-Content "$MsbHome\sandboxes\dm-nack\logs\kernel.log" -Tail 25 -ErrorAction SilentlyContinue
& $Msb ps 2>&1 | Select-String dm-nack
Show
Step "runtime log (system, last lines)"
& $Msb logs --source system dm-nack --tail 40 2>&1 | Select-String -Pattern "virtio-mem|NACK|plug|panic|alloc|memory|exit|error|1455" | Select-Object -Last 25
Step "processes"
Get-Process msb -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ("  msb pid {0} commit {1:N2} GB start {2}" -f $_.Id, ($_.PagedMemorySize64/1GB), $_.StartTime) }
Step "is the VM still alive?"
& $Msb exec dm-nack -- sh -c 'echo alive; uptime' 2>&1
& $Msb ps 2>&1 | Select-String dm-nack
Step "stop"
& $Msb stop dm-nack 2>&1 | Out-Null
Write-Output "done"

# Dynamic memory spike test for one msb runtime on Windows. ASCII only.
# Usage: dm-test.ps1 -Msb <msb.exe> -MsbHome <dir> -Label <label>
param([string]$Msb, [string]$MsbHome, [string]$Label, [string]$Max = "6G")
$ErrorActionPreference = "Continue"
$env:MSB_HOME = $MsbHome
New-Item -ItemType Directory -Force -Path $MsbHome | Out-Null
$name = "dm-$Label"
function Step($t) { Write-Output ("== {0} {1}" -f (Get-Date).ToUniversalTime().ToString("HH:mm:ss"), $t) }
function HostMem {
  $os = Get-CimInstance Win32_OperatingSystem
  Write-Output ("  host commit in use {0:N2} GB, free commit {1:N2} GB, free RAM {2:N2} GB" -f (($os.TotalVirtualMemorySize - $os.FreeVirtualMemory)/1MB), ($os.FreeVirtualMemory/1MB), ($os.FreePhysicalMemory/1MB))
  Get-Process msb -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Output ("  host msb pid {0} commit {1:N2} GB, RAM {2:N2} GB" -f $_.Id, ($_.PagedMemorySize64/1GB), ($_.WorkingSet64/1GB))
  }
}
function GuestMem {
  $m = (& $Msb exec $name -- head -3 /proc/meminfo 2>&1 | ForEach-Object { ($_ -replace "\s+", " ").Trim() }) -join " | "
  Write-Output "  guest $m"
}
& $Msb remove -f $name 2>&1 | Out-Null
Step "boot --memory 1G --max-memory $Max"
& $Msb run -d -n $name --memory 1G --max-memory $Max alpine -- sleep 100000 2>$null | Select-Object -Last 3
Start-Sleep 3; GuestMem; HostMem
Step "modify --memory 4G (grow)"
& $Msb modify $name --memory 4G 2>$null | Select-Object -Last 3
Start-Sleep 5; GuestMem; HostMem
Step "fill 2500 MiB in guest tmpfs"
& $Msb exec $name -- sh -c 'mount -t tmpfs -o size=3500m tmpfs /mnt 2>/dev/null; dd if=/dev/zero of=/mnt/fill bs=1M count=2500 2>&1 | tail -1' 2>&1
Start-Sleep 2; GuestMem; HostMem
Step "free the fill"
& $Msb exec $name -- sh -c 'rm -f /mnt/fill; sync; echo 3 > /proc/sys/vm/drop_caches' 2>&1
Start-Sleep 3; GuestMem; HostMem
Step "modify --memory 1G (shrink)"
& $Msb modify $name --memory 1G 2>$null | Select-Object -Last 3
Start-Sleep 10; GuestMem; HostMem
Step "stop"
& $Msb stop $name 2>&1 | Out-Null; & $Msb remove -f $name 2>&1 | Out-Null
Write-Output "done"

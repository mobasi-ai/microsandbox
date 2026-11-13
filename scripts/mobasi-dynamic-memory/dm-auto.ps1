# Autoscaler prototype on Windows: grow and shrink a VM with the guest's need.
# Boot 2 GiB (cap 6 GiB). Every second: when MemAvailable < 45% of MemTotal and
# the target < cap, grow by 1 GiB (then wait 3 checks); when MemAvailable > 70%
# for 4 checks in a row and the target > 2 GiB, shrink by 1 GiB. The guest
# fills tmpfs with 400 MiB every 3 s to 3.2 GiB, holds it 15 s, frees it.
# ASCII only.
param([string]$Msb, [string]$MsbHome, [string]$Label = "win")
$ErrorActionPreference = "Continue"
$env:MSB_HOME = $MsbHome
$name = "auto-$Label"; $floor = 2048; $cap = 6144; $step = 1024
& $Msb remove -f $name 2>&1 | Out-Null
& $Msb run -d -n $name --memory 2G --max-memory 6G alpine -- sleep 100000 2>&1 | Out-Null
Start-Sleep 3
$work = Start-Job -ScriptBlock { param($m, $n, $h)
  $env:MSB_HOME = $h
  & $m exec $n -- sh -c 'mount -t tmpfs -o size=5000m tmpfs /mnt; i=0; while [ $i -lt 8 ]; do i=$((i+1)); dd if=/dev/zero of=/mnt/f$i bs=1M count=400 2>/dev/null || echo dd-failed-$i; sleep 3; done; sleep 15; rm -f /mnt/f*; echo 3 > /proc/sys/vm/drop_caches' 2>&1
} -ArgumentList $Msb, $name, $MsbHome
$target = $floor; $calm = 0; $cool = 0
for ($t = 1; $t -le 90; $t++) {
  $lines = & $Msb exec $name -- head -3 /proc/meminfo 2>$null
  $total = $null; $avail = $null
  foreach ($l in $lines) {
    if ($l -match "^MemTotal:\s+(\d+)") { $total = [int]($matches[1] / 1024) }
    if ($l -match "^MemAvailable:\s+(\d+)") { $avail = [int]($matches[1] / 1024) }
  }
  $action = "-"
  if ($cool -gt 0) { $cool-- }
  elseif ($total) {
    if ($avail * 100 -lt $total * 45 -and $target -lt $cap) {
      $target += $step; $calm = 0; $cool = 3; $action = "grow->${target}M"
      Start-Process -NoNewWindow -FilePath $Msb -ArgumentList @("modify", $name, "--memory", "${target}M") -RedirectStandardOutput "$env:TEMP\auto-mod.out" -RedirectStandardError "$env:TEMP\auto-mod.err"
    } elseif ($avail * 100 -gt $total * 70 -and $target -gt $floor) {
      $calm++
      if ($calm -ge 4) { $target -= $step; $calm = 0; $action = "shrink->${target}M"
        Start-Process -NoNewWindow -FilePath $Msb -ArgumentList @("modify", $name, "--memory", "${target}M") -RedirectStandardOutput "$env:TEMP\auto-mod.out" -RedirectStandardError "$env:TEMP\auto-mod.err" }
    } else { $calm = 0 }
  }
  $p = Get-CimInstance Win32_Process -Filter "Name='msb.exe'" | Where-Object { $_.CommandLine -match "machine --name $name" } | Select-Object -First 1
  $vm = if ($p) { Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue } else { $null }
  $os = Get-CimInstance Win32_OperatingSystem
  $vmText = if ($vm) { "vm_commit={0:N2}GB vm_ram={1:N2}GB" -f ($vm.PagedMemorySize64/1GB), ($vm.WorkingSet64/1GB) } else { "vm=?" }
  Write-Output ("{0} t={1:D2} guest_total={2}M avail={3}M {4} sys_commit={5:N2}GB {6}" -f (Get-Date).ToUniversalTime().ToString("HH:mm:ss"), $t, $total, $avail, $vmText, (($os.TotalVirtualMemorySize - $os.FreeVirtualMemory)/1MB), $action)
  Start-Sleep 1
}
Write-Output ("workload: " + ((Receive-Job $work -Wait) -join " "))
& $Msb stop $name 2>&1 | Out-Null; & $Msb remove -f $name 2>&1 | Out-Null
Write-Output "done"

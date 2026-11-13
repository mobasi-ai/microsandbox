# Resize storm with a data check, for Windows. ASCII only.
# Usage: dm-storm.ps1 -Msb <msb.exe> -MsbHome <folder> -Label <label> [-Rounds 150]
# The guest holds 1.2 GiB of checksummed data in memory and works on memory and disk. The host
# sets a random memory size between 2 GiB and 6 GiB again and again. At the end the data must be
# correct, the kernel log must show no fault, and the commit of the VM must go back after a shrink.
param([string]$Msb, [string]$MsbHome, [string]$Label = "win", [int]$Rounds = 150)
$ErrorActionPreference = "Continue"
$env:MSB_HOME = $MsbHome
New-Item -ItemType Directory -Force -Path $MsbHome | Out-Null
$name = "storm-$Label"
function Step($t) { Write-Output ("== {0} {1}" -f (Get-Date).ToUniversalTime().ToString("HH:mm:ss"), $t) }
function VmProc {
  $p = Get-CimInstance Win32_Process -Filter "Name='msb.exe'" | Where-Object { $_.CommandLine -match "machine --name $name" } | Select-Object -First 1
  if ($p) { Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue } else { $null }
}
function HostText {
  $v = VmProc
  if ($v) { "vm_commit={0:N2}GB vm_ram={1:N2}GB" -f ($v.PagedMemorySize64/1GB), ($v.WorkingSet64/1GB) } else { "no-vm" }
}
function GuestTotal {
  $l = & $Msb exec $name -- head -1 /proc/meminfo 2>$null
  if ("$l" -match "MemTotal:\s+(\d+)") { [int]($matches[1] / 1024) } else { "?" }
}
& $Msb remove -f $name 2>&1 | Out-Null
Step "boot --memory 1G --max-memory 6G, then grow to 4G"
& $Msb run -d -n $name --memory 1G --max-memory 6G alpine -- sleep 100000 2>$null | Select-Object -Last 1
Start-Sleep 3
& $Msb modify $name --memory 4G 2>&1 | Out-Null
Start-Sleep 4
$vm0 = VmProc
Step ("start the guest workload (VM pid {0}, {1})" -f $vm0.Id, (HostText))
$script = [IO.File]::ReadAllText((Join-Path $PSScriptRoot "guest-storm.sh")) -replace "`r", ""
$b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script))
$work = Start-Job -ScriptBlock { param($m, $n, $h, $b)
  $env:MSB_HOME = $h
  & $m exec $n -- sh -c "echo $b | base64 -d | sh" 2>&1
} -ArgumentList $Msb, $name, $MsbHome, $b64
for ($i = 0; $i -lt 180; $i++) {
  & $Msb exec $name -- test -e /mnt/sums 2>$null | Out-Null
  if ($LASTEXITCODE -eq 0) { break }
  Start-Sleep 1
}
Step "storm: $Rounds random sizes"
$rng = New-Object System.Random 4242
for ($i = 1; $i -le $Rounds; $i++) {
  $target = 2048 + $rng.Next(17) * 256
  & $Msb modify $name --memory "${target}M" 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { Write-Output "  modify failed at round $i" }
  if ($i % 15 -eq 0) { Write-Output ("  round {0} target={1}M guest_total={2}M {3}" -f $i, $target, (GuestTotal), (HostText)) }
  Start-Sleep -Milliseconds (200 + $rng.Next(800))
}
Step "stop the workload"
& $Msb exec $name -- touch /mnt/stop 2>&1 | Out-Null
$out = Receive-Job $work -Wait
Write-Output ("  guest: " + (($out | Select-Object -Last 3) -join " "))
Write-Output ("  BAD lines: " + @($out | Where-Object { "$_" -cmatch "BAD" }).Count)
Step "kernel log"
& $Msb exec $name -- sh -c "dmesg | grep -iE 'virtio_mem|BUG|Oops|corrupt|Bad page|broken|unable to handle' | tail -8; echo kernel lines: `$(dmesg | wc -l)" 2>&1 | ForEach-Object { "  $_" }
Step "free the data and shrink to 1G"
& $Msb exec $name -- sh -c "rm -f /mnt/keep* /root/disk; sync; echo 3 > /proc/sys/vm/drop_caches" 2>&1 | Out-Null
& $Msb modify $name --memory 1G 2>&1 | Out-Null
Start-Sleep 20
$vm1 = VmProc
Write-Output ("  guest_total={0}M {1} vm_pid_before={2} vm_pid_now={3}" -f (GuestTotal), (HostText), $vm0.Id, $vm1.Id)
if ($vm1 -and $vm0.Id -eq $vm1.Id -and $vm0.StartTime -eq $vm1.StartTime) { Write-Output "  RESULT: the VM process lived through the storm" } else { Write-Output "  RESULT: FAIL, the VM process changed or died" }
& $Msb stop $name 2>&1 | Out-Null; & $Msb remove -f $name 2>&1 | Out-Null
Write-Output "done"

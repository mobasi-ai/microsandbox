# Hostile guest test, for Windows. ASCII only.
# Usage: dm-hostile.ps1 -Msb <msb.exe> -MsbHome <folder> -Label <label> [-Steps 20000]
# A root program in the guest takes the virtio-mem device from the kernel and drives it through
# /dev/mem on the real hypervisor: random and hostile requests against a model, and a race of
# memory access against plug and unplug. The VM process must live through these.
# Then the program reads memory that is not plugged. Windows has no host memory there, so the VM
# must stop: with an error of the VMM, and never with an access violation of the VMM process.
param([string]$Msb, [string]$MsbHome, [string]$Label = "win", [int]$Steps = 20000)
$ErrorActionPreference = "Continue"
$env:MSB_HOME = $MsbHome
New-Item -ItemType Directory -Force -Path $MsbHome | Out-Null
$name = "hostile-$Label"
function Step($t) { Write-Output ("== {0} {1}" -f (Get-Date).ToUniversalTime().ToString("HH:mm:ss"), $t) }
function VmProc {
  $p = Get-CimInstance Win32_Process -Filter "Name='msb.exe'" | Where-Object { $_.CommandLine -match "machine --name $name" } | Select-Object -First 1
  if ($p) { Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue } else { $null }
}
function HostText {
  $v = VmProc
  if ($v) { "vm_commit={0:N2}GB vm_ram={1:N2}GB" -f ($v.PagedMemorySize64/1GB), ($v.WorkingSet64/1GB) } else { "no-vm" }
}
function B64($file) { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(([IO.File]::ReadAllText((Join-Path $PSScriptRoot $file)) -replace "`r", ""))) }
function Hostile($mode) {
  Step ("hostile {0} ({1})" -f $mode, (HostText))
  & $Msb exec $name -- sh -c "/root/hostile `$(cat /root/mmio) $mode; echo exit=`$?" 2>&1 | ForEach-Object { "  $_" }
}
$started = Get-Date
& $Msb remove -f $name 2>&1 | Out-Null
Step "boot --memory 1G --max-memory 3G --cpus 2"
& $Msb run -d -n $name --memory 1G --max-memory 3G --cpus 2 alpine -- sleep 100000 2>$null | Select-Object -Last 1
Start-Sleep 3
$vm0 = VmProc
Step "put the hostile driver in the guest and take the device from the kernel"
$source = B64 "hostile.c"
& $Msb exec $name -- sh -c "echo $source | base64 -d > /root/hostile.c" 2>&1 | Out-Null
$prepare = B64 "guest-hostile-prepare.sh"
& $Msb exec $name -- sh -c "echo $prepare | base64 -d | sh" 2>&1 | ForEach-Object { "  $_" }
Step "the host asks for the full size; only the hostile driver can plug now"
& $Msb modify $name --memory 3G 2>&1 | Out-Null
Start-Sleep 2
Hostile "info"
Hostile "model $Steps 1"
Hostile "model $Steps 77"
Hostile "racesafe 15"
Hostile "model $Steps 5"
$vm1 = VmProc
if ($vm1 -and $vm0.Id -eq $vm1.Id) { Write-Output ("  RESULT: the VM process lived through the requests ({0})" -f (HostText)) } else { Write-Output "  RESULT: FAIL, the VM process changed or died" }
Step "kernel log"
& $Msb exec $name -- sh -c "dmesg | grep -iE 'BUG:|Oops|corrupt|Bad page|unable to handle|nobody cared' | tail -5; echo kernel lines: `$(dmesg | wc -l)" 2>&1 | ForEach-Object { "  $_" }
Step "now read memory that is not plugged: the VM must stop, and the VMM must not crash"
& $Msb exec $name -- sh -c "/root/hostile `$(cat /root/mmio) touch; echo exit=`$?" 2>&1 | Select-Object -First 12 | ForEach-Object { "  $_" }
Start-Sleep 4
$vm2 = VmProc
if ($vm2 -and $vm0.Id -eq $vm2.Id) { Write-Output "  the VM process still runs" } else { Write-Output "  the VM process stopped" }
Write-Output "  runtime log:"
Get-Content "$MsbHome\sandboxes\$name\logs\runtime.log" -Tail 400 -ErrorAction SilentlyContinue | Select-String -Pattern "not plugged|unhandled WHP|panic|abort|the VM stops|vcpu.*exit|exit code|ERROR" | Select-Object -Last 8 | ForEach-Object { "    $_" }
$crashes = @(Get-WinEvent -FilterHashtable @{ LogName = "Application"; Id = 1000; StartTime = $started } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match "msb.exe" })
Write-Output ("  Windows application crash events for msb.exe since the start: {0}" -f $crashes.Count)
$crashes | Select-Object -First 2 | ForEach-Object { "    " + (($_.Message -split "`n" | Select-Object -First 8) -join " | ") }
& $Msb ps 2>&1 | Select-String $name | ForEach-Object { "  $_" }
& $Msb stop $name 2>&1 | Out-Null; & $Msb remove -f $name 2>&1 | Out-Null

# A queue in a block that the guest then unplugs: the VMM process must end with an access
# violation, which ends this VM only. This part starts a new VM.
Step "second VM: put the queue of the device in a block and unplug that block"
$started2 = Get-Date
& $Msb run -d -n $name --memory 1G --max-memory 3G --cpus 2 alpine -- sleep 100000 2>$null | Select-Object -Last 1
Start-Sleep 3
& $Msb exec $name -- sh -c "echo $source | base64 -d > /root/hostile.c" 2>&1 | Out-Null
& $Msb exec $name -- sh -c "echo $prepare | base64 -d | sh" 2>&1 | ForEach-Object { "  $_" }
& $Msb modify $name --memory 3G 2>&1 | Out-Null
Start-Sleep 2
$vm3 = VmProc
& $Msb exec $name -- sh -c "/root/hostile `$(cat /root/mmio) ringmove; echo exit=`$?" 2>&1 | Select-Object -First 8 | ForEach-Object { "  $_" }
Start-Sleep 5
$vm4 = VmProc
if ($vm4 -and $vm3.Id -eq $vm4.Id) { Write-Output "  the VM process still runs" } else { Write-Output "  the VM process stopped" }
$crashes2 = @(Get-WinEvent -FilterHashtable @{ LogName = "Application"; Id = 1000; StartTime = $started2 } -ErrorAction SilentlyContinue | Where-Object { $_.Message -match "msb.exe" })
Write-Output ("  Windows application crash events for msb.exe in this part: {0}" -f $crashes2.Count)
$crashes2 | Select-Object -First 1 | ForEach-Object { "    " + ((($_.Message -split "`n") | Where-Object { $_ -match "Exception code|Faulting module name|Fault offset" }) -join " | ") }
$os = Get-CimInstance Win32_OperatingSystem
Write-Output ("  host after it: commit in use {0:N2} GB, free RAM {1:N2} GB, msb processes {2}" -f (($os.TotalVirtualMemorySize - $os.FreeVirtualMemory)/1MB), ($os.FreePhysicalMemory/1MB), @(Get-Process msb -ErrorAction SilentlyContinue).Count)
& $Msb stop $name 2>&1 | Out-Null; & $Msb remove -f $name 2>&1 | Out-Null
Write-Output "done"

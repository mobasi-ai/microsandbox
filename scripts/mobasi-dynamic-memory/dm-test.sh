#!/usr/bin/env bash
# Dynamic memory spike test for one msb runtime on macOS or Linux.
# Usage: dm-test.sh <msb-binary> <msb-home> <label>
# Boot at 1 GiB with a 6 GiB hotplug cap, grow to 4 GiB, fill 2.5 GiB in the
# guest, free it, shrink to 1 GiB. Print host and guest memory at each step.
set -u
MSB="$1"; export MSB_HOME="$2"; LABEL="$3"; NAME="dm-$LABEL"
mkdir -p "$MSB_HOME"

host_mem() {
  local pids; pids=$(pgrep -f "$NAME" | tr '\n' ' ')
  if [ "$(uname)" = Darwin ]; then
    for p in $pids; do
      local fp; fp=$(footprint -p "$p" 2>/dev/null | awk '/phys_footprint:/ {print $2, $3; exit}')
      echo "  host pid $p rss=$(( $(ps -o rss= -p "$p" 2>/dev/null || echo 0) / 1024 ))MiB footprint=${fp:-?}"
    done
  else
    for p in $pids; do
      local rss; rss=$(awk '/^VmRSS/ {print int($2/1024)}' /proc/$p/status 2>/dev/null)
      echo "  host pid $p rss=${rss:-?}MiB"
    done
    echo "  host Committed_AS=$(awk '/Committed_AS/ {print int($2/1024)}' /proc/meminfo)MiB MemAvailable=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)MiB"
  fi
}
guest_mem() { "$MSB" exec "$NAME" -- sh -c 'grep -E "^(MemTotal|MemFree|MemAvailable)" /proc/meminfo | tr -s " " | tr "\n" " "' 2>&1 | sed 's/^/  guest /'; echo; }
step() { echo "== $(date -u +%T) $*"; }

"$MSB" remove -f "$NAME" >/dev/null 2>&1
step "boot --memory 1G --max-memory 6G"
"$MSB" run -d -n "$NAME" --memory 1G --max-memory 6G alpine -- sleep 100000 2>&1 | tail -2
sleep 3; guest_mem; host_mem
step "modify --memory 4G (grow)"
"$MSB" modify "$NAME" --memory 4G 2>&1 | tail -3
sleep 5; guest_mem; host_mem
step "fill 2500 MiB in guest tmpfs"
"$MSB" exec "$NAME" -- sh -c 'mkdir -p /dev/shm && mount -t tmpfs -o size=3500m tmpfs /mnt 2>/dev/null; dd if=/dev/zero of=/mnt/fill bs=1M count=2500 2>&1 | tail -1'
sleep 2; guest_mem; host_mem
step "free the fill"
"$MSB" exec "$NAME" -- sh -c 'rm -f /mnt/fill; sync; echo 3 > /proc/sys/vm/drop_caches'
sleep 3; guest_mem; host_mem
step "modify --memory 1G (shrink)"
"$MSB" modify "$NAME" --memory 1G 2>&1 | tail -3
sleep 10; guest_mem; host_mem
step "stop"
"$MSB" stop "$NAME" >/dev/null 2>&1; "$MSB" remove -f "$NAME" >/dev/null 2>&1
echo "done"

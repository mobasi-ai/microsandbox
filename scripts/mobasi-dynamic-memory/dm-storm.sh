#!/usr/bin/env bash
# Resize storm with a data check, for macOS and Linux.
# Usage: dm-storm.sh <msb-binary> <msb-home> <label> [rounds]
# The guest holds 1.2 GiB of checksummed data in memory and works on memory and disk. The host
# sets a random memory size between 2 GiB and 6 GiB again and again. At the end the data must be
# correct, the kernel log must show no fault, and the host memory must go back after a shrink.
set -u
MSB="$1"; export MSB_HOME="$2"; LABEL="$3"; ROUNDS="${4:-150}"; NAME="storm-$LABEL"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$MSB_HOME"
host_mib() {
  local p; p=$(pgrep -f "machine --name $NAME" | head -1)
  [ -z "$p" ] && { echo "no-vm"; return; }
  if [ "$(uname)" = Darwin ]; then footprint -p "$p" 2>/dev/null | awk '/phys_footprint:/ {print $2 $3; exit}'
  else awk '/^VmRSS/ {print int($2/1024) "MiB"}' /proc/$p/status 2>/dev/null; fi
}
step() { echo "== $(date -u +%T) $*"; }
"$MSB" remove -f "$NAME" >/dev/null 2>&1
step "boot --memory 1G --max-memory 6G, then grow to 4G"
"$MSB" run -d -n "$NAME" --memory 1G --max-memory 6G alpine -- sleep 100000 2>&1 | tail -1
sleep 3
"$MSB" modify "$NAME" --memory 4G >/dev/null 2>&1
sleep 4
VMPID=$(pgrep -f "machine --name $NAME" | head -1)
step "start the guest workload (VM pid $VMPID, host $(host_mib))"
"$MSB" exec "$NAME" -- sh -c "$(cat "$HERE/guest-storm.sh")" > "/tmp/storm-$LABEL-guest.log" 2>&1 &
for _ in $(seq 1 180); do "$MSB" exec "$NAME" -- test -e /mnt/sums >/dev/null 2>&1 && break; sleep 1; done
"$MSB" exec "$NAME" -- test -e /mnt/sums >/dev/null 2>&1 || echo "FAIL: the guest workload did not start"
step "storm: $ROUNDS random sizes"
RANDOM=4242
for i in $(seq 1 "$ROUNDS"); do
  target=$((2048 + (RANDOM % 17) * 256))
  "$MSB" modify "$NAME" --memory "${target}M" >/dev/null 2>&1 || echo "  modify failed at round $i"
  if [ $((i % 15)) = 0 ]; then
    total=$("$MSB" exec "$NAME" -- awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)
    echo "  round $i target=${target}M guest_total=${total:-?}M host=$(host_mib)"
  fi
  sleep "0.$((2 + RANDOM % 8))"
done
step "stop the workload"
"$MSB" exec "$NAME" -- touch /mnt/stop >/dev/null 2>&1
wait
echo "  guest: $(tail -3 "/tmp/storm-$LABEL-guest.log" | tr '\n' ' ')"
grep -c BAD "/tmp/storm-$LABEL-guest.log" | sed 's/^/  BAD lines: /'
step "kernel log"
"$MSB" exec "$NAME" -- sh -c 'dmesg | grep -iE "virtio_mem|BUG:|Oops|corrupt|Bad page|broken|unable to handle" | grep -vE "plugged size|requested size" | tail -8; echo "kernel lines: $(dmesg | wc -l)"' 2>&1 | sed 's/^/  /'
step "free the data and shrink to 1G"
"$MSB" exec "$NAME" -- sh -c 'rm -f /mnt/keep* /root/disk; sync; echo 3 > /proc/sys/vm/drop_caches' >/dev/null 2>&1
"$MSB" modify "$NAME" --memory 1G >/dev/null 2>&1
sleep 20
total=$("$MSB" exec "$NAME" -- awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null)
NOW=$(pgrep -f "machine --name $NAME" | head -1)
echo "  guest_total=${total:-?}M host=$(host_mib) vm_pid_before=$VMPID vm_pid_now=${NOW:-none}"
[ "$VMPID" = "${NOW:-none}" ] && echo "  RESULT: the VM process lived through the storm" || echo "  RESULT: FAIL, the VM process changed or died"
"$MSB" stop "$NAME" >/dev/null 2>&1; "$MSB" remove -f "$NAME" >/dev/null 2>&1
echo done

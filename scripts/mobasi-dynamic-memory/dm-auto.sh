#!/usr/bin/env bash
# Autoscaler prototype: grow and shrink a VM with the guest's need.
# Usage: dm-auto.sh <msb-binary> <msb-home> <label>
# Boot 2 GiB (cap 6 GiB). Every second: when MemAvailable < 45% of MemTotal
# and the target < cap, grow by 1 GiB; when MemAvailable > 70% for 4 checks in
# a row and the target > 2 GiB, shrink by 1 GiB. The guest fills tmpfs with
# 400 MiB every 3 s to 3.2 GiB, holds it 15 s, and frees it.
set -u
MSB="$1"; export MSB_HOME="$2"; LABEL="$3"; NAME="auto-$LABEL"
FLOOR=2048; CAP=6144; STEP=1024
mkdir -p "$MSB_HOME"
host_mib() {
  local p; p=$(pgrep -f "machine --name $NAME" | head -1)
  if [ "$(uname)" = Darwin ]; then footprint -p "$p" 2>/dev/null | awk '/phys_footprint:/ {print $2 $3; exit}'
  else awk '/^VmRSS/ {print int($2/1024) "MiB"}' /proc/$p/status 2>/dev/null; fi
}
"$MSB" remove -f "$NAME" >/dev/null 2>&1
"$MSB" run -d -n "$NAME" --memory 2G --max-memory 6G alpine -- sleep 100000 >/dev/null 2>&1
sleep 3
# Workload: +400 MiB every 3 s up to 3200 MiB, hold 15 s, free all.
"$MSB" exec "$NAME" -- sh -c 'mount -t tmpfs -o size=5000m tmpfs /mnt; i=0; while [ $i -lt 8 ]; do i=$((i+1)); dd if=/dev/zero of=/mnt/f$i bs=1M count=400 2>/dev/null || echo "dd failed at step $i"; sleep 3; done; sleep 15; rm -f /mnt/f*; echo 3 > /proc/sys/vm/drop_caches' >/tmp/auto-$LABEL-workload.log 2>&1 &
calm=0; cool=0; target=$FLOOR
for t in $(seq 1 90); do
  read -r total avail <<<"$("$MSB" exec "$NAME" -- awk '/MemTotal/ {t=int($2/1024)} /MemAvailable/ {a=int($2/1024)} END {print t, a}' /proc/meminfo 2>/dev/null)"
  action="-"
  if [ $cool -gt 0 ]; then cool=$((cool - 1))
  elif [ -n "${total:-}" ]; then
    if [ $((avail * 100)) -lt $((total * 45)) ] && [ $target -lt $CAP ]; then
      target=$((target + STEP)); calm=0; cool=3; action="grow->${target}M"
      "$MSB" modify "$NAME" --memory "${target}M" >/dev/null 2>&1 &
    elif [ $((avail * 100)) -gt $((total * 70)) ] && [ $target -gt $FLOOR ]; then
      calm=$((calm + 1))
      if [ $calm -ge 4 ]; then target=$((target - STEP)); calm=0; action="shrink->${target}M"
        "$MSB" modify "$NAME" --memory "${target}M" >/dev/null 2>&1 & fi
    else calm=0; fi
  fi
  printf '%s t=%02d guest_total=%sM avail=%sM host=%s %s\n' "$(date -u +%T)" "$t" "${total:-?}" "${avail:-?}" "$(host_mib)" "$action"
  sleep 1
done
wait
echo "workload: $(cat /tmp/auto-$LABEL-workload.log)"
"$MSB" stop "$NAME" >/dev/null 2>&1; "$MSB" remove -f "$NAME" >/dev/null 2>&1
echo done

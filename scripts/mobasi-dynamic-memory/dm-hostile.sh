#!/usr/bin/env bash
# Hostile guest test, for macOS and Linux.
# Usage: dm-hostile.sh <msb-binary> <msb-home> <label> [model steps]
# A root program in the guest takes the virtio-mem device from the kernel and drives it through
# /dev/mem on the real hypervisor: random and hostile requests against a model, a race of memory
# access against plug and unplug, and access to memory that is not plugged. The VM process must
# live, and the device must answer as the model says.
set -u
MSB="$1"; export MSB_HOME="$2"; LABEL="$3"; STEPS="${4:-20000}"; NAME="hostile-$LABEL"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$MSB_HOME"
step() { echo "== $(date -u +%T) $*"; }
host_mib() {
  local p; p=$(pgrep -f "machine --name $NAME" | head -1)
  [ -z "$p" ] && { echo "no-vm"; return; }
  if [ "$(uname)" = Darwin ]; then footprint -p "$p" 2>/dev/null | awk '/phys_footprint:/ {print $2 $3; exit}'
  else awk '/^VmRSS/ {print int($2/1024) "MiB"}' /proc/$p/status 2>/dev/null; fi
}
"$MSB" remove -f "$NAME" >/dev/null 2>&1
step "boot --memory 1G --max-memory 3G --cpus 2"
"$MSB" run -d -n "$NAME" --memory 1G --max-memory 3G --cpus 2 alpine -- sleep 100000 2>&1 | tail -1
sleep 3
VMPID=$(pgrep -f "machine --name $NAME" | head -1)
step "put the hostile driver in the guest and take the device from the kernel"
"$MSB" exec "$NAME" -- sh -c "echo $(base64 < "$HERE/hostile.c" | tr -d '\n') | base64 -d > /root/hostile.c"
"$MSB" exec "$NAME" -- sh -c "$(cat "$HERE/guest-hostile-prepare.sh")" 2>&1 | sed 's/^/  /'
step "the host asks for the full size; only the hostile driver can plug now"
"$MSB" modify "$NAME" --memory 3G >/dev/null 2>&1
sleep 2
for mode in "info" "model $STEPS 1" "model $STEPS 77" "racesafe 15" "race 15" "touch" "ringmove" "resetloop 300000" "model $STEPS 5"; do
  step "hostile $mode (host $(host_mib))"
  "$MSB" exec "$NAME" -- sh -c "/root/hostile \$(cat /root/mmio) $mode; echo exit=\$?" 2>&1 | sed 's/^/  /'
done
step "after"
"$MSB" exec "$NAME" -- sh -c 'dmesg | grep -iE "BUG:|Oops|corrupt|Bad page|unable to handle|nobody cared" | tail -5; echo "kernel lines: $(dmesg | wc -l)"' 2>&1 | sed 's/^/  /'
NOW=$(pgrep -f "machine --name $NAME" | head -1)
echo "  host=$(host_mib) vm_pid_before=$VMPID vm_pid_now=${NOW:-none}"
[ "$VMPID" = "${NOW:-none}" ] && echo "  RESULT: the VM process lived" || echo "  RESULT: the VM process changed or died"
grep -iE "panic|abort|fail_stop|the VM stops" "$MSB_HOME/sandboxes/$NAME/logs/runtime.log" 2>/dev/null | tail -5 | sed 's/^/  log: /'
"$MSB" stop "$NAME" >/dev/null 2>&1; "$MSB" remove -f "$NAME" >/dev/null 2>&1
echo done

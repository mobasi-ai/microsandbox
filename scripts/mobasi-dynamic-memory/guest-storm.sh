# Runs in the guest. Holds 1.2 GiB of random data in memory with a checksum list, and checks
# it again and again while it also fills and frees 300 MiB of memory and writes to the disk.
# The host changes the memory size of the VM at the same time. Prints "rounds=N bad=M".
mount -t tmpfs -o size=4000m tmpfs /mnt 2>/dev/null
cd /mnt || exit 1
i=0
while [ $i -lt 12 ]; do
  i=$((i + 1))
  dd if=/dev/urandom of=keep$i bs=1M count=100 2>/dev/null || echo "BAD fill $i"
done
sha256sum keep* > /mnt/sums
echo ready
n=0
bad=0
while [ ! -e /mnt/stop ]; do
  n=$((n + 1))
  sha256sum -c /mnt/sums >/dev/null 2>&1 || { bad=$((bad + 1)); echo "BAD memory round $n"; }
  dd if=/dev/urandom of=/mnt/scratch bs=1M count=300 2>/dev/null || echo "scratch full round $n"
  rm -f /mnt/scratch
  dd if=/dev/urandom of=/root/disk bs=1M count=64 2>/dev/null
  a=$(sha256sum < /root/disk)
  sync
  echo 1 > /proc/sys/vm/drop_caches
  b=$(sha256sum < /root/disk)
  [ "$a" = "$b" ] || { bad=$((bad + 1)); echo "BAD disk round $n"; }
done
sha256sum -c /mnt/sums >/dev/null 2>&1 || { bad=$((bad + 1)); echo "BAD memory final"; }
echo "rounds=$n bad=$bad"

# Runs in the guest as root. Builds the hostile driver and takes the virtio-mem device from the
# kernel: first from the virtio-mem driver, then from the virtio-mmio transport, so that
# /dev/mem can map the device registers and the hotplug region. Writes the register address to
# /root/mmio.
apk add --quiet gcc musl-dev >/dev/null 2>&1 || { echo FAIL: cannot install the compiler; exit 1; }
gcc -O2 -pthread -o /root/hostile /root/hostile.c || { echo FAIL: cannot build; exit 1; }
for d in /sys/bus/virtio/devices/*; do
  if [ $(cat $d/device) = 0x0018 ]; then
    V=$(basename $d)
    P=$(basename $(dirname $(readlink -f $d)))
  fi
done
MMIO=$(awk -v p=$P '$3 == p { sub(/-.*/, "", $1); print $1; exit }' /proc/iomem)
echo virtio-mem is $V on $P at 0x$MMIO, cpus $(nproc)
echo $V > /sys/bus/virtio/drivers/virtio_mem/unbind || { echo FAIL: unbind virtio_mem; exit 1; }
echo $P > /sys/bus/platform/drivers/virtio-mmio/unbind || { echo FAIL: unbind virtio-mmio; exit 1; }
echo $MMIO > /root/mmio
echo prepared

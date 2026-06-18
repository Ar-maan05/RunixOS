#!/usr/bin/env bash
# Script to build and run the RunixOS kernel in QEMU.
set -e

# Make sure we are in the script's directory
cd "$(dirname "$0")"

# Rebuild disk image if it doesn't exist
if [ ! -f disk.img ]; then
    ./build_disk.sh
fi

echo "=== Launching RunixOS in QEMU ==="
echo "Press Ctrl+A then X to exit QEMU if running in -nographic mode."
echo "--------------------------------------------------------"

# Run QEMU with UEFI (OVMF), the hard drive image, and serial output sent to host console.
# We also forward any additional CLI arguments.
qemu-system-x86_64 \
    -M q35 \
    -smp 2 \
    -drive if=pflash,unit=0,format=raw,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on \
    -drive file=disk.img,format=raw,media=disk \
    -serial stdio \
    -m 2G \
    -monitor unix:qemu-monitor.sock,server,nowait \
    "$@"

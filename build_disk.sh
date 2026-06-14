#!/usr/bin/env bash
# Script to compile the kernel and build a UEFI-bootable GPT partitioned disk image.
set -e

# Make sure we are in the script's directory
cd "$(dirname "$0")"

echo "=== Building RunixOS Kernel ==="
cargo build

echo "=== Preparing EFI System Partition (ESP) ==="
rm -rf esp
mkdir -p esp/EFI/BOOT
mkdir -p esp/boot/limine
mkdir -p esp/limine

# Copy the UEFI bootloader binary, kernel, and configurations in all possible formats/locations
cp limine-bin/BOOTX64.EFI esp/EFI/BOOT/BOOTX64.EFI
cp limine.conf esp/limine.conf
cp limine.conf esp/limine.cfg
cp limine.conf esp/EFI/BOOT/limine.conf
cp limine.conf esp/EFI/BOOT/limine.cfg
cp limine.conf esp/boot/limine/limine.conf
cp limine.conf esp/boot/limine/limine.cfg
cp target/x86_64-unknown-none/debug/runixos esp/boot/runixos

echo "=== Creating esp.img (62MB FAT16 filesystem) ==="
rm -f esp.img
dd if=/dev/zero of=esp.img bs=1M count=62

# Format as FAT16
mkfs.vfat -F 16 esp.img

# Recursively copy all files into the FAT32 image
mcopy -i esp.img -s esp/* ::/
rm -rf esp

echo "=== Creating disk.img (64MB GPT Partitioned Disk) ==="
rm -f disk.img
dd if=/dev/zero of=disk.img bs=1M count=64

# Create GPT partition table
parted -s disk.img mklabel gpt

# Create partition starting at sector 2048 (1MB offset) and ending at 129023 (~63MB)
parted -s disk.img mkpart ESP fat16 2048s 129023s
parted -s disk.img set 1 esp on

# Copy the formatted FAT16 filesystem image into the partition offset (1MB seek)
dd if=esp.img of=disk.img bs=1M seek=1 conv=notrunc
rm -f esp.img

echo "=== Build Complete: Partitioned disk.img is ready! ==="

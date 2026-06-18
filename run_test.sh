#!/usr/bin/env bash
(sleep 4; echo "hello") | timeout 15 qemu-system-x86_64 -M q35 -smp 2 -drive if=pflash,unit=0,format=raw,file=/usr/share/OVMF/OVMF_CODE.fd,readonly=on -drive file=disk.img,format=raw,media=disk -serial stdio -display none -m 2G -monitor none

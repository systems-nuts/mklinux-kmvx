#!/bin/bash
set -euo pipefail

# IP of the VM
VM_IP="145.108.189.163"
# Path of mklinux-utils on the VM
MKLU="/root/mklinux-kmvx-utils"

CPUS=`cat /proc/cpuinfo | grep processor | wc -l`

KCPPFLAGS="-std=gnu89" make -j$CPUS vmlinux CC=gcc-4.9
if [ ! "$?" == "0" ]; then echo "Error during compilation."; exit; fi

echo "SCP kernel + remote call to create_elf.sh"
scp vmlinux root@$VM_IP:$MKLU/vmlinux
if [ ! "$?" == "0" ]; then echo "Error during scp."; exit; fi

ssh root@$VM_IP "cd $MKLU ; ./create_elf.sh vmlinux ; rm vmlinux"

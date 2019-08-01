#!/bin/bash
set -euo pipefail

# Path of mklinux-utils
MKLU="/root/mklinux-kmvx-utils"

CPUS=`cat /proc/cpuinfo | grep processor | wc -l`

KCPPFLAGS="-std=gnu89" make -j$CPUS vmlinux
if [ ! "$?" == "0" ]; then echo "Error during compilation."; exit; fi

echo "Creating elf in $MKLU"
cp vmlinux $MKLU && cd $MKLU && ./create_elf.sh vmlinux && cd - && rm $MKLU/vmlinux

#!/bin/bash
set -euo pipefail

# IP/port of the VM
VM_IP="145.108.189.163"
VM_PORT="22"
VM_IDENTFILE="/home/sebastian/.ssh/id_rsa"

reboot=0
do_modules=0
njobs=`nproc`
CC=gcc-4.9

while [ $# -gt 0 ]; do
    case ${1:-} in
        -r|--reboot)
            printf " - Will reboot VM at end\n"
            reboot=1
            ;;
        -m|--modules)
            printf " - Will compile and install modules\n"
            do_modules=1
            ;;
        *)
            printf "ERROR: unknown option ${1:-}\n"
            exit 1
        ;;
    esac
shift
done

make include/config/kernel.release
VER=`cat include/config/kernel.release`
CPUS=`nproc`

KCPPFLAGS="-std=gnu89" make -j$CPUS bzImage CC=gcc-4.9
if [ ! "$?" == "0" ]; then echo "Error during kernel compilation."; exit; fi

if [ $do_modules -eq 1 ]; then
    KCPPFLAGS="-std=gnu89" make -j$CPUS modules CC=gcc-4.9
    if [ ! "$?" == "0" ]; then echo "Error during modules compilation."; exit; fi

    # For some reason this fails in out of tree mode when the firmware dir
    # tree is not already present ...
    mkdir -p .tmp_popmod/lib/firmware
    rsync -a --include '*/' --exclude '*' firmware/ .tmp_popmod/lib/firmware/
    KCPPFLAGS="-std=gnu89" make modules_install INSTALL_MOD_PATH=./.tmp_popmod
    if [ ! "$?" == "0" ]; then echo "Error during modules install."; exit; fi
fi

KCPPFLAGS="-std=gnu89" make headers_install INSTALL_HDR_PATH=./.tmp_pophds
if [ ! "$?" == "0" ]; then echo "Error during headears install."; exit; fi

echo "Scp of kernel + confi + system.map to $VM_IP:/boot"
scp -i $VM_IDENTFILE -P $VM_PORT arch/x86/boot/bzImage root@$VM_IP:/boot/vmlinuz-"$VER"
scp -i $VM_IDENTFILE -P $VM_PORT .config root@$VM_IP:/boot/config-"$VER"
scp -i $VM_IDENTFILE -P $VM_PORT System.map root@$VM_IP:/boot/System.map-"$VER"


if [ $do_modules -eq 1 ]; then
    echo "Scp modules"
    ssh -i $VM_IDENTFILE -p $VM_PORT root@$VM_IP mkdir -p /lib/firmware/
    ssh -i $VM_IDENTFILE -p $VM_PORT root@$VM_IP mkdir -p /lib/modules/$VER/
    rsync -az -e "ssh -i $VM_IDENTFILE -p $VM_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" --delete-before --progress ./.tmp_popmod/lib/firmware/ root@$VM_IP:/lib/firmware/
    rsync -az -e "ssh -i $VM_IDENTFILE -p $VM_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" --delete-before --progress ./.tmp_popmod/lib/modules/$VER/ root@$VM_IP:/lib/modules/$VER/
fi

echo "Scp headers"
ssh -i $VM_IDENTFILE -p $VM_PORT root@$VM_IP mkdir -p /usr/src/linux-headers-$VER/include/
rsync -az -e "ssh -i $VM_IDENTFILE -p $VM_PORT -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" --delete-before --progress ./.tmp_pophds/include/ root@$VM_IP:/usr/src/linux-headers-$VER/include/

echo "Updating initramfs + grub + ldconfig + depmod"
ssh -i $VM_IDENTFILE -p $VM_PORT root@$VM_IP ldconfig
ssh -i $VM_IDENTFILE -p $VM_PORT root@$VM_IP depmod
ssh -i $VM_IDENTFILE -p $VM_PORT root@$VM_IP update-initramfs -c -k "$VER" || true
ssh -i $VM_IDENTFILE -p $VM_PORT root@$VM_IP update-grub

if [ $reboot -eq 1 ]; then
	ssh -i $VM_IDENTFILE -p $VM_PORT root@$VM_IP reboot
fi

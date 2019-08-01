#!/bin/bash
set -euo pipefail

REP1_DIR="../kmvx-replica1"
REP2_DIR="../kmvx-replica2"

# Cleanup if needed
rm -rf $REP1_DIR $REP2_DIR &> /dev/null
mkdir $REP1_DIR $REP2_DIR

# Get the config
cp -f configft-dcl .config

# Setup directories
make O=$REP1_DIR oldconfig
make O=$REP2_DIR oldconfig

# Change the config in each dir
sed -i "s/^.*CONFIG_KMVX_REP2.*$/CONFIG_KMVX_REP2=n/" $REP1_DIR/.config
sed -i "s/^.*CONFIG_KMVX_REP2.*$/CONFIG_KMVX_REP2=y/" $REP2_DIR/.config

# This is needed here in case we previously compiled something "in-tree"
make mrproper

# Setup the building scripts
for script in build_local_primary.sh build_remote_primary.sh kinst.sh build_local_secondary.sh build_remote_secondary.sh; do
	ln -s $PWD/mklinux-kmvx-scripts/$script $REP1_DIR/$script
	ln -s $PWD/mklinux-kmvx-scripts/$script $REP2_DIR/$script
done

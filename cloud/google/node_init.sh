#! /bin/bash
export DATA_DIR=/data
export DATA_DEV=/dev/disk/by-id/google-persistent-disk-1

sudo mkdir ${DATA_DIR}
sudo /usr/share/google/safe_format_and_mount \
  -m "mkfs.ext4 -F" ${DATA_DEV} ${DATA_DIR}



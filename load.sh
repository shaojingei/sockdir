#!/bin/bash

# enable debug output for each executed command
# to disable: set +x
set -x
# exit if any command fails
set -e

# Mount the bpf filesystem
sudo mount -t bpf bpf /sys/fs/bpf/

# Compile the bpf_sockops_v4 program
clang -O2 -g -target bpf -I/usr/include/linux/ -I/usr/src/linux-headers-5.3.0-42/include/ -c bpf_sockops_v4.c -o bpf_sockops_v4.o

# Load and attach the bpf_sockops_v4 program
sudo bpftool prog load bpf_sockops_v4.o "/sys/fs/bpf/bpf_sockops"
sudo bpftool cgroup attach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"


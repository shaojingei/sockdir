#!/bin/bash
set -x

# Detach and unload the bpf_sockops_v4 program
sudo bpftool cgroup detach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"
sudo rm "/sys/fs/bpf/bpf_sockops"


#!/bin/sh
set -eu

curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s builtin
cd KernelSU
curl -LSs "https://raw.githubusercontent.com/vc-teahouse/SukiSU-Ultra/main/add-key-to-builtin.patch" | patch -p1

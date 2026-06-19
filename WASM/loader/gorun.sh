#!/usr/bin/env bash
export HOME=/root
export PATH=/root/goroot/bin:/root/go/bin:$PATH
cd /mnt/c/Users/ander/Documents/GitHub/seedkernel/WASM/loader || exit 1
exec go "$@"

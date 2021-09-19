#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi
set -ex
prog="$1"
shift
# Here's the Magic: Load the libanpnetstack before any other library
LD_PRELOAD="/usr/local/lib/libanpnetstack.so" "$prog" "$@"


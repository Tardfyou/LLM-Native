#!/bin/sh
set -e
make clean
make -j"$(nproc)"

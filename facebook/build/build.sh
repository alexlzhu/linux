#!/usr/bin/env bash
set -e

cd "$(buck root)" || echo "must run from somewhere in the linux tree" && exit 1
./facebook/build/buck build $@

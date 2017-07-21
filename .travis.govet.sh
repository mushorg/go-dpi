#!/bin/bash

cd "$(dirname $0)"
set -e
for subdir in $GO_DIRS; do
  pushd $subdir
  go vet
  popd
done

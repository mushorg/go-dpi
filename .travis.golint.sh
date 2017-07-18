#!/bin/bash

cd "$(dirname $0)"

go get github.com/golang/lint/golint
# Add subdirectories here as we clean up golint on each.
for subdir in $GO_DIRS; do
  res=$(golint $subdir)
  if [[ $res != '' ]]; then
      echo "$res"
      exit 1
  fi
done

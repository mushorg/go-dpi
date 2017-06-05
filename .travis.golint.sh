#!/bin/bash

cd "$(dirname $0)"

go get github.com/golang/lint/golint
DIRS=". examples"
# Add subdirectories here as we clean up golint on each.
for subdir in $DIRS; do
  if [[ $(golint $subdir) != '' ]]; then
      exit 1
  fi
done

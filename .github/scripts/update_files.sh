#!/usr/bin/env bash

set -euo pipefail

FILE=".github/workflows/python-sbom-vulnerability-scan.yml"

if [ ! -f "$FILE" ]; then
    echo "File not found: $FILE"
    exit 0
fi

sed -i \
  's/dependency-track-project-version: latest/dependency-track-project-version: test-multi-gitter/' \
  "$FILE"

echo "Updated: $FILE"

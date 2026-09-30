#!/usr/bin/env bash

set -euo pipefail

FILE=".github/multi-gitter-test.txt"

mkdir -p .github

cat > "$FILE" <<'EOF'
This file was created automatically with multi-gitter.

It is used to test repository-wide file updates.
EOF

echo "Updated: $FILE"

#!/bin/bash
# Release script — bumps version, commits, tags, pushes. CI publishes.
# Usage: ./scripts/release.sh 0.3.17

set -e
V=$1
if [ -z "$V" ]; then
  echo "Usage: ./scripts/release.sh <version>"
  echo "Example: ./scripts/release.sh 0.3.17"
  exit 1
fi

cd "$(dirname "$0")/.."

# Update all version strings
sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$V\"/" package.json
sed -i "0,/^version = \"[^\"]*\"/s//version = \"$V\"/" rust/Cargo.toml
sed -i "0,/^version = \"[^\"]*\"/s//version = \"$V\"/" daemon/Cargo.toml

# Build to verify
npm run build

echo ""
echo "Bumped to v$V"
echo ""

# Commit, tag, push
git add package.json rust/Cargo.toml daemon/Cargo.toml
git commit -m "chore: release v$V"
git push origin main
git tag "v$V"
git push origin "v$V"

echo ""
echo "Tagged v$V — CI will publish to npm + crates.io + Docker"

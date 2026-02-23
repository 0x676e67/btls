#!/bin/sh

set -euo pipefail

SCRIPT_NAME=$(basename "$0")
REQUIRE_BRANCH='master'
CURRENT_BRANCH="$(git symbolic-ref --short HEAD)"

if [[ "$CURRENT_BRANCH" != "$REQUIRE_BRANCH" ]]; then
  echo "Please \`git checkout $REQUIRE_BRANCH\` to run $SCRIPT_NAME (cannot run from current branch $CURRENT_BRANCH)."
  exit 1
fi

if [[ "$(git diff --stat)" != '' ]]; then
  echo 'Please commit or discard your changes before creating a new release.'
  exit 1
fi

echo "===  Publishing btls-sys... ==="
(cd btls-sys && cargo publish)
sleep 20

echo "===  Publishing btls... ==="
(cd btls && cargo publish)
sleep 20

echo "===  Publishing tokio-btls... ==="
(cd tokio-btls && cargo publish)
sleep 20

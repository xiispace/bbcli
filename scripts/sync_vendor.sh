#!/usr/bin/env bash
# Re-sync the vendored Bytebase catalog and task guides.
#
#   scripts/sync_vendor.sh /path/to/bytebase
#
# Copies the four embedded files and stamps the source commit into
# vendor/bytebase/SOURCE.md and vendor/bytebase/COMMIT (the latter is
# compiled into `bbcli --version`). Review the diff before committing:
# the catalog is what keeps agents from guessing field names.
set -euo pipefail

repo=${1:?usage: sync_vendor.sh /path/to/bytebase}
src=$repo/backend/api/mcp
dst=$(cd "$(dirname "$0")/.." && pwd)/vendor/bytebase

[ -f "$src/gen/openapi.yaml" ] || { echo "not a bytebase checkout: $repo" >&2; exit 1; }

mkdir -p "$dst/skills"
cp "$src/gen/openapi.yaml" "$dst/openapi.yaml"
for guide in query database-change grant-permission; do
  cp "$src/skills/$guide.md" "$dst/skills/$guide.md"
done

commit=$(git -C "$repo" rev-parse HEAD)
date=$(git -C "$repo" log -1 --format=%cd --date=short)
printf '%s' "$commit" > "$dst/COMMIT"
sed -i.bak -E "s/^Synced from commit \`[0-9a-f]+\` \([0-9-]+\)\./Synced from commit \`$commit\` ($date)./" "$dst/SOURCE.md"
rm -f "$dst/SOURCE.md.bak"

echo "synced from $commit ($date)"
git -C "$(dirname "$dst")/.." status --short vendor 2>/dev/null || true

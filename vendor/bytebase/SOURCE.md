# Vendored Bytebase resources

Copied verbatim from the Bytebase monorepo; embedded into the binary at build
time (`include_str!`) so `bbcli search` and `bbcli skill` work offline.

| File | Source path in bytebase/bytebase |
|---|---|
| `openapi.yaml` | `backend/api/mcp/gen/openapi.yaml` (generated from proto by buf) |
| `skills/query.md` | `backend/api/mcp/skills/query.md` |
| `skills/database-change.md` | `backend/api/mcp/skills/database-change.md` |
| `skills/grant-permission.md` | `backend/api/mcp/skills/grant-permission.md` |

Synced from commit `c19b6bf4b46ab9f333bc2790bd8ed7992f9805ea` (2026-06-18).

`bbcli --version` and `bbcli search` report this commit, so an agent can tell
which API surface the catalog describes.

## Re-syncing

```bash
scripts/sync_vendor.sh /path/to/bytebase
```

The script copies the four files, rewrites the commit above, and leaves the
result for review — the catalog is only as current as this sync.

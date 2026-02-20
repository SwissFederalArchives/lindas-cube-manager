# LINDAS Cube Manager — Documentation

**Version:** 2.0 | **Last updated:** 2026-02-20

This is the single reference document for the LINDAS Cube Manager tool.
It covers architecture, deployment, usage, security, and known limitations.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Deployment](#deployment)
4. [Configuration](#configuration)
5. [Deletion Wizard](#deletion-wizard)
6. [Backup System](#backup-system)
7. [Security](#security)
8. [Infrastructure Requirements](#infrastructure-requirements)
9. [SPARQL Query Reference](#sparql-query-reference)
10. [Orphan Shape Cleanup](#orphan-shape-cleanup)
11. [Known Issues & Troubleshooting](#known-issues--troubleshooting)

---

## Overview

LINDAS Cube Manager is a web application for deleting old cube versions from a
LINDAS-compatible RDF triplestore while preserving the N most recent versions
(default: 2). It was built to address triple accumulation caused by the LINDAS
design paradigm of never deleting data.

**What it does:**
- Identifies cube versions older than the N most recent per base cube
- Creates a full ZIP backup before any deletion
- Deletes observations, observation links, and cube metadata in sequence
- Detects and cleans up orphaned SHACL shapes left by deleted cubes
- Provides a restore path from any previously created backup

**Supported triplestores:** Apache Fuseki, Stardog, GraphDB, LINDAS (read-only)

---

## Architecture

```
web-app/
  server.js       Express.js API server (~4300 lines)
  public/app.js   Single-page frontend (vanilla JS)
queries/          SPARQL query templates (01-15)
queries/universal/  Graph-URI-parameterized versions of all queries
Dockerfile        node:18-alpine, non-root user, port 3001
docker-compose.yml  Single-service compose with volume mounts
```

### Server

The server is an Express.js application (`server.js`) that:
- Serves the frontend from `public/`
- Exposes REST API endpoints for all triplestore operations
- Loads SPARQL query templates from `queries/` at runtime
- Manages backup ZIP files in a local `backups/` directory
- Runs backup cleanup every hour (7-day retention)

### Frontend

A single-page application served from `public/`. Uses no framework.
Communicates with the server exclusively via `fetch()` API calls.
State is managed via a plain `state` object in `app.js`.

---

## Deployment

### Docker (recommended)

```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f web-app

# Stop
docker-compose down
```

The container runs as non-root user `appuser` on `node:18-alpine`.
Volumes are mounted for `backups/`, `exports/`, and `uploads/` to persist
data across container restarts.

Memory is limited to **512M** in `docker-compose.yml`.

### Native Node.js

```bash
cd web-app
npm install
node server.js
```

The server starts on port 3001. Open `http://localhost:3001` in the browser.

To enable deletion operations, set `ENABLE_DESTRUCTIVE_API=true` before
starting the server:

```bash
# macOS / Linux
ENABLE_DESTRUCTIVE_API=true node server.js

# Windows Command Prompt
SET ENABLE_DESTRUCTIVE_API=true && node server.js
```

---

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Web server port |
| `ENABLE_DESTRUCTIVE_API` | `false` | Enables all deletion, backup creation, restore, and import endpoints. Must be `true` to run the Deletion Wizard. |
| `API_AUTH_TOKEN` | (none) | If set, all destructive endpoints require `Authorization: Bearer <token>`. |

**Security note:** Backup creation endpoints (`/api/backup/create`,
`/api/backup/create-multi`) are gated by `ENABLE_DESTRUCTIVE_API` — you
cannot accidentally create a large backup without intending to run deletions.

---

## Deletion Wizard

The wizard walks through five steps:

### Step 1 — Select Graph
Connect to a triplestore (Fuseki, Stardog, GraphDB) and select a named graph.
The graph URI is validated against a whitelist character set to prevent SPARQL injection.

### Step 2 — Explore Cubes
Loads all cube versions in the graph. Shows: base cube URI, version URI,
version number, and date created. Uses SPARQL queries 01-03.

### Step 3 — Preview Deletions
Identifies which cube versions will be deleted vs. kept.
The default is to keep the 2 most recent versions per base cube; this is configurable.
Uses query 03 (version ranking with FILTER to exclude non-versioned URIs).

### Step 4 — Execute Cleanup
In sequence:
1. **Create backup** — a single ZIP containing N-Triples for all cube versions
   to be deleted, plus a JSON manifest
2. **Delete each cube version** — for each version:
   - Delete observations (query 07, chunked)
   - Delete observation links (query 08)
   - Delete cube metadata and SHACL shapes (query 09)
3. **Orphan shape cleanup** — detects and removes any SHACL shapes left
   without a referencing cube (queries 11-14)

### Step 5 — Summary
Shows: versions deleted, versions preserved, total triples removed, backups
created, orphan shapes cleaned. Offers JSON report export and backup download.

---

## Backup System

### Format
Backups are ZIP files stored in `backups/` with the naming pattern
`backup_<timestamp>.zip`. Each ZIP contains:
- One `.nt` (N-Triples) file per cube
- A `manifest.json` with cube URIs, triple counts, creation time, and expiry

### Retention
Backups are automatically deleted after **7 days**. Cleanup runs on server
startup and every hour.

### Multi-Cube Backup
The wizard creates a single consolidated backup for all cube versions being
deleted before any deletion begins. This uses `Buffer.from(await response.arrayBuffer())`
internally to avoid the V8 string length limit (~512 MB) when backing up
large graphs.

### Restore
Backups can be restored to any connected triplestore from the Backups screen.
Selective restore is supported — you can choose which cubes from a multi-cube
backup to restore.

### Backup-Before-Delete Enforcement
Every destructive endpoint (`delete-observations`, `delete-observation-links`,
`delete-metadata`) validates that a backup exists and covers the cube URI being
deleted (`validateBackupCoversUri()`), closing the TOCTOU window between backup
creation and deletion.

---

## Security

### Authentication & Authorization
- `requireDestructiveAccess` middleware gates all destructive endpoints
- When `API_AUTH_TOKEN` is set, requests must include `Authorization: Bearer <token>`
- SPARQL UPDATE queries in the Query Editor also require `ENABLE_DESTRUCTIVE_API=true`
  and a valid token

### Input Validation
- `validateUriParam()` — whitelists URI characters; applied to all `graphUri`
  and `cubeUri` parameters before interpolation into SPARQL
- `validateEndpointUrl()` — rejects `file://`, `ftp://`, and private IP ranges
  (SSRF protection); localhost is allowed for local development
- `validateBackupId()` — sanitizes backup IDs used in file paths
- Multer file upload limit: **200 MB**

### Container Security
- Docker image runs as non-root user `appuser` (group `appgroup`)
- `ENABLE_DESTRUCTIVE_API=false` by default in `docker-compose.yml`

---

## Infrastructure Requirements

### Proxy Timeout (Critical for Stardog / LINDAS production)

When the tool runs against a Stardog instance behind a reverse proxy (Nginx,
HAProxy, etc.) with a default **30-second request timeout**, deletion of large
cube versions will fail with:

```
ERROR: SPARQL update failed: 504 - 504 Gateway Time-out
```

**Root cause:** SPARQL DELETE of large observation sets exceeds the 30-second
proxy timeout even when chunked to 100,000 triples per DELETE.

**Code-level workaround (already applied):** The `/api/cubes/delete-observations`
endpoint loops over 100,000-triple chunks (`CHUNK_SIZE = 100000`) until the
observation count reaches zero. Each chunk takes 5-30 seconds on Stardog test.
This achieves ~94% success on the LINDAS test environment (Feb 2026 test run).

**Required infrastructure fix:** Configure the proxy to allow 300 seconds for
SPARQL UPDATE requests:

```nginx
location ~ ^/sparql {
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;
}
```

With a 300-second timeout, the 100K-chunk strategy handles all practical cube
sizes without failure.

### Test Results (2026-02-20, Stardog test cluster)

| Metric | Value |
|--------|-------|
| Graph tested | `https://lindas.admin.ch/foen/cube` |
| Cube versions to delete | 128 |
| Successfully deleted | 120 (93.75%) |
| Failed (504 timeout) | 8 (edge cases, millions of observations) |
| Triples removed | 8,124,002 |
| Backup size | 85.4 MB ZIP |
| Orphan shapes found | 0 (cleaned by query 09 during deletion) |

---

## SPARQL Query Reference

All queries live in `queries/` (graph-specific) and `queries/universal/`
(parameterized with `GRAPH_URI` placeholder).

| # | File | Type | Description |
|---|------|------|-------------|
| 01 | `01-list-all-cube-versions.rq` | SELECT | All cube versions with parsed version numbers |
| 02 | `02-count-versions-per-cube.rq` | SELECT | Version count per base cube |
| 03 | `03-identify-versions-to-delete.rq` | SELECT | Versions older than top-N, excludes non-versioned URIs |
| 04 | `04-preview-triples-to-delete.rq` | SELECT | Counts by category for a version |
| 05 | `05-preview-single-cube-triples.rq` | CONSTRUCT | All triples for one version (specific property traversal, no unbounded paths) |
| 06 | `06-delete-single-cube.rq` | DELETE | Full deletion of one version excluding incoming references from other cubes |
| 07 | `07-delete-observations-chunked.rq` | DELETE | Chunked observation delete (`LIMIT` in subquery) |
| 08 | `08-delete-observation-links.rq` | DELETE | Remove `cube:observation` links |
| 09 | `09-delete-cube-metadata.rq` | DELETE | Cube structure, SHACL shapes, metadata |
| 10 | `10-count-observations-per-cube.rq` | SELECT | Observation triple count |
| 11 | `11-find-orphan-shapes.rq` | SELECT | NodeShapes with no referencing cube |
| 12 | `12-preview-orphan-shape-triples.rq` | CONSTRUCT | All triples belonging to orphan shapes |
| 13 | `13-delete-orphan-shapes.rq` | DELETE | Removes shapes, property shapes, RDF list nodes |
| 14 | `14-count-orphan-shapes.rq` | SELECT | Count of orphan shapes and their triples |
| 15 | `15-preview-single-orphan-shape.rq` | SELECT | Triples for one specific orphan shape |

### Key Design Decisions

- **Query 03:** Uses `FILTER` to exclude cube URIs that do not match the
  versioned URI pattern, preventing non-versioned cubes from appearing as candidates
- **Query 05:** Uses explicit `sh:property` / `sh:in` traversal instead of
  `(<>|!<>)*` to avoid runaway property path expansion
- **Query 06 / 09:** Removes incoming reference UNION branches (`?s ?p ?targetCube`)
  to avoid accidentally deleting triples from other cubes that reference this one
- **Query 07:** Uses `LIMIT` inside a `WHERE { { SELECT ... LIMIT N } }` subquery,
  which is valid SPARQL 1.1 (LIMIT on DELETE WHERE is not)
- **Stardog compatibility:** DELETE queries use `WITH <graph> DELETE { ... } WHERE { ... }`
  pattern with BIND instead of FILTER for variable binding in DELETE clauses

---

## Orphan Shape Cleanup

When cube versions are deleted, their SHACL constraint shapes may be left
without a referencing cube:

```
?cube cube:observationConstraint ?shape .
?shape a sh:NodeShape .
?shape sh:property ?propShape .
?propShape sh:in <list> .
```

If the `?cube` triples are deleted but the shape triples are not, the shapes
become orphans. Query 09 handles shape cleanup as part of metadata deletion,
so orphans only arise from partial failures.

Orphan detection (query 14) runs automatically after all deletions complete.
If orphans are found, the wizard offers preview (query 12), cleanup (query 13),
or skip.

---

## Known Issues & Troubleshooting

### 504 Gateway Timeout on observation deletion

**Cause:** Nginx/proxy between the tool and Stardog has a short request timeout
(30s by default). Chunked DELETEs on very large cube versions can still exceed it.

**Fix:** Increase proxy timeout to 300s (see [Infrastructure Requirements](#infrastructure-requirements)).

**Behavior when this occurs:** The wizard logs the error, marks the cube as
failed, and continues to the next one. Observations are partially removed (some
chunks may have succeeded). Metadata and shapes are not touched for failed cubes.

### V8 string length error during backup

**Symptom:** `Cannot create a string longer than 0x1fffffe8 characters`

**Cause:** Old code used `response.text()` for large N-Triples payloads,
exceeding V8's ~512 MB string limit.

**Status:** Fixed. `/api/backup/create-multi` now uses
`Buffer.from(await response.arrayBuffer())`.

### Destructive API not enabled

**Symptom:** `ERROR: Backup error - Destructive API endpoints are disabled`

**Fix:** Start the server with `ENABLE_DESTRUCTIVE_API=true`.

### Duplicate cube version numbers in graph

Some cubes in the LINDAS test environment have duplicate version entries
(e.g., version 2 listed twice). The wizard processes each entry independently,
so the second deletion of the same version is a no-op (no triples remain).
This is a data quality issue in the source graph, not a tool bug.

### Orphan shapes not found after deletion

If all cube versions are deleted successfully, their shapes are removed by
query 09 during the metadata deletion step. The orphan detector correctly
reports 0 orphans. This is expected behavior.

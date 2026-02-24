# Changelog

All notable changes to the LINDAS Cube Version Cleanup Tool are documented in this file.

## [2026-02-24] - Service-Deployment Mode, Keycloak Auth, CI/CD, GitOps

### Added

- **Service-deployment mode** (`server.js`): When `STORE_QUERY_ENDPOINT` is set in the
  environment, the server pre-configures the triplestore connection and ignores any connection
  parameters sent by the frontend. A single Express middleware applies the override to all
  POST `/api/*` routes so no individual handler needed to change.

- **`/api/config` endpoint** (`server.js`): Public endpoint that returns `{ serviceMode,
  connection, auth }`. Used by the frontend to detect service mode and bootstrap the OIDC flow.

- **Keycloak JWT authentication** (`server.js`): When both `SERVICE_MODE` and `AUTH_ISSUER` are
  set, all `/api/*` routes (except `/api/config` and `/api/health`) require a valid RS256 JWT
  from the configured Keycloak realm. Uses `express-jwt` + `jwks-rsa` (same packages as
  cube-creator).

- **OIDC authorization code + PKCE flow** (`public/app.js`, `public/index.html`): When the
  server returns `auth.enabled: true` from `/api/config`, the frontend starts an OIDC flow
  using the `oidc-client` library (served from `/oidc-client.js`). All `fetch('/api/...` calls
  replaced with `authFetch('/api/...` wrapper that injects the Bearer token.

- **Service-mode banner** (`public/index.html`, `public/styles.css`): Shows a locked-connection
  indicator when running in service mode, hiding the manual connection form.

- **GitHub Actions CI/CD** (`.github/workflows/`):
  - `docker.yaml`: Builds and pushes `master`, `test_YYYY-MM-DD_HHmmss`, and `sha-*` tags on
    every push to master. Mirrors cube-creator's tag naming exactly.
  - `promote.yaml`: Manual workflow to promote `test_*` to `int_*` + `prod_*` via retag (no
    rebuild). Also supports rollback actions for each environment.

- **GitOps Kubernetes manifests** (in `gitops-main`):
  - `zazuko-test/cube-manager/`: configmap, deployment (master tag, Always pull), service, pvc
  - `zazuko-int/cube-manager/`: configmap, deployment (Flux-managed int_ tag), service, pvc, flux

- **New npm dependencies**: `express-jwt@^8.3.0`, `jwks-rsa@^3.0.0`, `oidc-client@^1.11.5`

- **Local docker-compose integration** (`local-setup/docker-compose.yml`): Added `cube-manager`
  service with service-deployment mode enabled (pointing to local Fuseki). Port `8090`.

## [2026-02-20] - Fix 504 Gateway Timeout on Large Cube Observation Deletion

### Fixed

- **504 Gateway Timeout during observation deletion** (`/api/cubes/delete-observations`):
  The endpoint previously sent a single unbounded SPARQL DELETE with no LIMIT, causing
  Nginx/proxy gateway timeouts (30s) for large cube versions. Replaced with a server-side
  chunked loop: repeatedly executes `DELETE { ... } WHERE { { SELECT ... LIMIT 100000 } }`
  until the observation count reaches zero. Each individual DELETE request now completes
  well within the 30-second gateway timeout. `chunksProcessed` is returned in the response
  for diagnostics.

## [2026-02-20] - Fix V8 String Limit and Add Buffer Support for Multi-Cube Backup

### Fixed

- **V8 string length limit exceeded during multi-cube backup** (`/api/backup/create-multi`):
  Changed `response.text()` to `Buffer.from(await response.arrayBuffer())` to avoid V8's
  ~512MB string limit when backing up many large cubes. Updated newline counting to use a
  byte-level loop (counting `0x0A` bytes). Updated `createZipBackup()` to handle both
  `string` and `Buffer` inputs for the `triples` parameter.

### Added

- **`web-app/start-destructive.bat`**: Helper script to start the server with
  `ENABLE_DESTRUCTIVE_API=true` from the correct working directory. For dev/test use only.

## [2026-02-18] - Code Review Fixes: Security, SPARQL, Frontend, Docker

### Fixed (Security - server.js)

- **URI validation regex bug**: Fixed character class in `validateUriParam` that contained
  a misplaced space and comma, and added parentheses to blocked characters.

- **SPARQL injection via searchTerm**: Replaced weak backslash/double-quote escape with
  a whitelist regex that only allows safe URI characters in search terms.

- **Multer upload size limit**: Added 200MB file size limit to prevent DoS via oversized
  file uploads.

- **SSRF protection**: Added `validateEndpointUrl()` helper that rejects non-HTTP protocols
  and private IP ranges (while allowing localhost for local development).

- **Backup identity validation (TOCTOU)**: Added `validateBackupCoversUri()` that opens
  the backup ZIP at deletion time to verify the cube URI is listed in the manifest, closing
  the time-of-check-time-of-use gap.

- **Auth bypass on query execute**: The `/api/query/execute` endpoint now checks
  `API_AUTH_TOKEN` for UPDATE queries, not just `ENABLE_DESTRUCTIVE_API`.

- **Auth bypass on backup endpoints**: Added `requireDestructiveAccess` middleware to
  `/api/backup/create`, `/api/backup/create-multi`, and `/api/backup/upload`.

- **Multi-cube backup partial failure**: Backup creation now tracks failed cubes and
  returns HTTP 207 with a `cubesNotBackedUp` list when some cubes fail.

### Fixed (Frontend - app.js)

- **Wizard state leak**: `resetWizard()` now clears `selectedCubesForDeletion` set.

- **Deletion button not re-enabled on error**: Wrapped `wizardExecuteDeletion()` body
  in try/finally to ensure the execute button is always re-enabled.

- **Duplicate checkbox IDs**: Backup section select-all now uses unique ID
  `backup-select-all-cubes` to avoid collision with wizard section.

- **Event listener accumulation**: Select-all checkbox is now cloned before adding a
  new event listener, preventing duplicate handler buildup.

- **Silent total failure**: Added explicit error log when all cube deletions fail.

- **Queue item ID collisions**: Changed queue item IDs to index-based format.

- **Progress bar stuck on download error**: Added hidden class to progress container
  in download error catch block.

- **Backup export URL encoding**: Added `encodeURIComponent()` for backup IDs in export
  download URL to handle special characters.

- **Wrong state property for Fuseki dataset**: Changed `state.datasetName` to
  `state.fusekiDataset` in input handler.

### Fixed (SPARQL Queries)

- **Query 03 (root + universal)**: Added FILTER to exclude non-versioned cube URIs from
  version ranking, preventing unversioned cubes from appearing as deletion candidates.

- **Query 05 (root)**: Replaced unbounded property path `(<>|!<>)*` with specific SHACL
  property traversal (sh:property direct + sh:in RDF lists) to avoid runaway traversal.

- **Query 05 (universal)**: Same property path fix as root version.

- **Query 06 (root + universal)**: Removed incoming-reference UNION branches
  (`?s ?p ?targetCube`, `?s ?p ?shape`, `?s ?p ?obsSet`, `?s ?p ?obs`) that could
  delete triples belonging to other cubes that reference this one.

- **Query 07 (root)**: Moved LIMIT into a subquery for valid SPARQL 1.1 Update chunking
  (LIMIT on DELETE WHERE is not valid SPARQL 1.1).

- **Query 08 (root)**: Same LIMIT-into-subquery fix as query 07.

- **Query 09 (root + universal)**: Removed incoming-reference branches matching the
  same fix applied to query 06.

### Added (SPARQL Queries)

- **Universal versions for queries 07-10**: Created parameterized universal versions
  with GRAPH_URI placeholder for queries 07 (delete observations chunked),
  08 (delete observation links), 09 (delete cube metadata), and 10 (count observations).

### Changed (Docker)

- **Dockerfile**: Added non-root user (`appuser`) for container security; created
  runtime directories (backups, exports, uploads) with proper ownership.

- **docker-compose.yml**: Removed deprecated `version` key; added volume mounts for
  exports/ and uploads/ directories; added memory limit (512M).

## [2026-02-18] - Bug Fixes: API Contracts, Security, and Reliability

### Fixed

- **`/api/lindas/all-graphs` response contract**: Endpoint now returns `{ graphs: [{ uri }] }`
  instead of raw SPARQL JSON, matching what the frontend expects. Load Graphs feature
  now works correctly.

- **`/api/lindas/cubes` response contract**: Endpoint now returns `{ cubes: [{ cube, title, version, baseCube, dateCreated }] }`
  instead of raw SPARQL JSON. Download All Cubes feature now works correctly.

- **Download-import field name mismatch**: Frontend now correctly reads `downloadResult.triples`
  (was `downloadResult.ntriples`), fixing the cube download-and-import pipeline.

- **Configurable `versionsToKeep` now respected server-side**: Both `/api/cubes/count-versions`
  and `/api/cubes/identify-deletions` now accept and use the `versionsToKeep` parameter
  from the frontend instead of hardcoding `2`.

- **Backup cleanup pattern**: `cleanupOldBackups()` now correctly matches files starting
  with `backup_` (was looking for `_backup_` which never matched). Old backups are now
  properly cleaned up after the retention period.

- **SPARQL injection via `searchTerm`**: The `/api/lindas/graphs` endpoint now escapes
  backslash and double-quote characters in the search term before interpolating into SPARQL.

- **SPARQL injection via `offset`/`limit`**: The `/api/lindas/download-graph` endpoint
  now validates `offset` and `limit` as non-negative integers before use in SPARQL.

- **Missing auth guards on restore/import endpoints**: Added `requireDestructiveAccess`
  middleware to `/api/backup/restore`, `/api/backup/import`, and `/api/backup/restore-to`.
  These endpoints now correctly respect `ENABLE_DESTRUCTIVE_API` and `API_AUTH_TOKEN`.

- **Orphan cleanup wizard hang**: `waitForOrphanCleanupDecision()` now resolves
  immediately with `skip` if no buttons exist in the DOM, and includes a 5-minute
  safety timeout to prevent permanent promise hang.

- **Dataset creation parameter injection**: `datasetName` is now URL-encoded with
  `encodeURIComponent()` in both legacy and current Fuseki dataset creation endpoints.
  Legacy endpoint also validates that `endpoint` is a localhost URL to prevent SSRF.

## [2026-02-15] - Orphan Shape Wizard Integration

### Added

- **Backend API endpoints for orphan shapes**:
  - `POST /api/orphans/shapes/count` - Returns precise orphan shape count and total
    triple count using the comprehensive query 14 pattern.
  - `POST /api/orphans/shapes/list` - Returns individual orphan shapes with details
    (shape URI, type, property shape count, estimated triples) using query 11 pattern.
  - `POST /api/orphans/shapes/preview` - Returns CONSTRUCT triples showing exactly
    what would be deleted, using the comprehensive query 12 pattern.

- **Wizard "Preview Orphan Triples" button**: Users can now preview the exact triples
  that will be deleted before confirming orphan shape cleanup. Shows a sample of the
  first 10 triples in the deletion log.

- **Shape-specific verification after cleanup**: The cleanup endpoint now runs query 14
  after deletion to verify that remaining orphan shape count is 0, reporting detailed
  verification results (shapes removed, triples cleaned, remaining count).

- **Orphan shape cleanup results in wizard summary**: Step 5 summary now shows
  "Orphan Shapes Cleaned" and "Orphan Triples Removed" stats alongside cube deletion
  metrics.

- **Query editor templates**: Added "Count Orphan Shapes (Query 14)", "Find Orphan
  Shapes - Details (Query 11)", and "Delete Orphan Shapes (Query 13)" to the query
  editor template dropdown for manual execution.

- **Deletion report export**: The JSON export now includes an `orphanCleanup` section
  with `performed`, `shapesCleaned`, and `shapeTriplesCleaned` fields.

### Changed

- **`constructOrphanShapesQuery()`**: Replaced with comprehensive version matching
  query 12 - now captures property shape triples, RDF list nodes, and incoming
  references (previously only captured direct shape triples).

- **`deleteOrphanShapesQuery()`**: Replaced with comprehensive version matching
  query 13 - now deletes the full nested structure including property shapes, RDF
  list nodes (sh:in value lists), and incoming references. Uses `GRAPH` clause with
  BIND pattern for Stardog compatibility.

- **`/api/orphans/detect` endpoint**: Now also returns shape-specific counts
  (`shapes.orphanShapeCount` and `shapes.orphanShapeTriples`) from query 14,
  in addition to the existing general summary.

- **`/api/orphans/cleanup` endpoint**: Now runs shape count verification (query 14)
  before and after cleanup. Returns a `verification` object with `remainingOrphanShapes`,
  `remainingOrphanShapeTriples`, `shapesRemoved`, and `shapeTriplesCleaned`.

- **Wizard Step 4 orphan flow**: Enhanced from simple detect-and-delete to a full
  workflow: detect -> show shape-specific details -> preview (optional) -> cleanup ->
  verify. Three buttons are now shown: "Preview Orphan Triples", "Clean Up Orphans",
  and "Skip Cleanup".

- **`waitForOrphanCleanupDecision()`**: Now handles three choices (preview, cleanup,
  skip) instead of two (cleanup, skip).

## [2026-02-15] - Orphan Shape Queries

### Added

- **Query 11 - find-orphan-shapes.rq**: SELECT query that discovers SHACL NodeShapes
  in a graph that are not referenced by any remaining cube via `cube:observationConstraint`.
  Reports each orphan shape with its property shape count and estimated triple count.

- **Query 12 - preview-orphan-shape-triples.rq**: CONSTRUCT query that returns the
  complete set of triples belonging to orphan shapes. Produces exactly the triples
  that query 13 would delete. Can be saved as a backup before deletion.

- **Query 13 - delete-orphan-shapes.rq**: DELETE query that removes all orphan shapes
  and their full nested structure: shape direct triples, property shapes, RDF list
  nodes (sh:in value lists), and incoming references. Uses BIND pattern for Stardog
  compatibility, matching the style of existing queries 06 and 09.

- **Query 14 - count-orphan-shapes.rq**: Summary SELECT query that returns the total
  count of orphan shapes and total orphan triples. Useful for quick impact assessment
  before and after cleanup (post-cleanup should return 0).

- **Query 15 - preview-single-orphan-shape.rq**: Parameterized SELECT query that shows
  all triples for a specific orphan shape, categorized by type (shape-direct,
  shape-incoming, property-shape, rdf-list-node). For detailed inspection of
  individual orphan shapes.

- **Universal versions**: All five new queries (11-15) also added to `queries/universal/`
  with `GRAPH_URI` placeholder for use with any LINDAS graph.

- **docs/architecture/orphan-shapes-solution.md**: Technical documentation explaining
  the orphan shapes problem, the data model, the solution approach, and execution steps.

### Changed

- **docs/architecture/query-reference.md**: Added documentation for queries 11-15 and
  a new "Full Cleanup" execution order section that includes orphan shape cleanup
  as a post-deletion step.

- **docs/architecture/solution-overview.md**: Added orphan shape cleanup description,
  updated cube structure documentation to detail SHACL shape relationships, and updated
  the file structure listing to include new queries.

## [2026-02-03] - Initial Tool

### Added

- Queries 01-10 for cube version discovery, preview, and deletion
- Universal parameterized query versions
- Web application for interactive usage
- Docker configuration
- Documentation (solution overview, query reference, execution log, data analysis)
- Test data setup and execution reports

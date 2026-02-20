# Stardog Gateway Timeout Issue

**Status:** Known infrastructure limitation
**Affected operation:** Observation deletion for large cube versions
**Observed in:** Stardog test environment (`stardog-test.cluster.ldbar.ch`)
**Date first observed:** 2026-02-20

---

## Problem

When deleting cube versions that contain a large number of observation triples,
SPARQL UPDATE requests to Stardog can take more than 30 seconds to complete.
If a reverse proxy (Nginx, HAProxy, etc.) sits between this tool and Stardog with
a default 30-second request timeout, those requests are terminated and the deletion
fails with a 504 Gateway Timeout error.

```
ERROR: SPARQL update failed: 504 - <html><body><h1>504 Gateway Time-out</h1>
The server didn't respond in time.
</body></html>
```

---

## Root Cause

The Nginx proxy in front of the Stardog test cluster has a **30-second HTTP timeout**
on proxied requests. SPARQL UPDATE operations that delete observations from large cube
versions (millions of triples) exceed this limit even when chunked into 100,000-triple
batches.

The timeout applies only to the individual Nginx-to-Stardog HTTP hop. The
browser-to-Node.js connection (localhost:3001) is not affected and does not timeout.

---

## Observed Impact During Testing (2026-02-20)

Full test run against `https://lindas.admin.ch/foen/cube`:

| Metric | Value |
|--------|-------|
| Cube versions to delete | 128 |
| Successfully deleted | 120 (93.75%) |
| Failed (504 timeout) | 8 (6.25%) |
| Triples removed | 8,124,002 |

The 8 failures were exclusively on very large cube versions (millions of observations
per version). Smaller cubes (up to ~500K observations) deleted without issue.

Notably, even for failed cube versions, the chunked DELETE loop ran for several
minutes and deleted many chunks before the final timeout:
- `wald-faostat-production-test002/19`: ran for ~6 minutes before the last chunk timed out

---

## Workaround Applied (Code-Level)

The tool was updated to use a **server-side chunked DELETE loop** instead of a single
unbounded DELETE. Each chunk deletes at most 100,000 observation triples:

```sparql
WITH <graphUri>
DELETE { ?obs ?p ?o }
WHERE {
  { SELECT ?obs ?p ?o WHERE { ... } LIMIT 100000 }
}
```

The loop re-counts remaining observations after each chunk and repeats until the count
reaches zero. This keeps each individual Stardog request under 30 seconds for most
real-world cube sizes.

This workaround achieves ~94% success rate on the test environment. The remaining
failures are on cube versions where even a single 100K-triple DELETE exceeds 30 seconds
(very rare in practice).

---

## Recommended Fix (Infrastructure-Level)

Configure the Nginx proxy to use a longer timeout for SPARQL UPDATE endpoints:

```nginx
location ~ ^/sparql {
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;
}
```

Or more broadly for all Stardog traffic:

```nginx
location / {
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;
}
```

**With a 300-second proxy timeout, the 100K-chunk strategy handles all practical
cube sizes without timeout failures.**

This configuration change should be requested from the infrastructure team before
running the tool against production LINDAS.

---

## Cube Versions That Failed in Testing

All failures were in the `https://lindas.admin.ch/foen/cube` graph:

- `aussenhandel_holz_test_tim_aggregiert_v1/3`, `/2`, `/1`
- `aussenhandel_holz_test_tim_v3/9` through `/1` (large version series)
- `klee/3`
- `wald-faostat-production-test002/19`, `/18`

These cube versions have their observations still intact in the graph (the deletion
was aborted mid-chunk). Their metadata and SHACL shapes were not touched.

---

## See Also

- Test report: `docs/testing/` (in parent `lindas-local-environment` repo at
  `docs/ticket-255-cube-cleanup-test-report-2026-02-20.md`)
- Chunked deletion implementation: `web-app/server.js`, `/api/cubes/delete-observations`
- Query: `queries/07-delete-observations-chunked.rq`

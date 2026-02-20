# LINDAS Cube Manager

A web application for cleaning up old cube versions in a LINDAS-compatible RDF triplestore. It identifies cube versions older than the N most recent per base cube, backs them up, and deletes them.

## Features

- Interactive deletion wizard (select graph → preview → backup → delete → summary)
- Chunked SPARQL DELETE to handle large cube versions without proxy timeouts
- ZIP backup with selective restore per cube
- Orphan SHACL shape detection and cleanup
- Supports Apache Fuseki, Stardog, and GraphDB

## Quick Start

```bash
cd web-app
npm install
ENABLE_DESTRUCTIVE_API=true node server.js
```

Open `http://localhost:3001`.

### Docker

```bash
docker-compose up -d
```

The destructive API is disabled by default. Uncomment `ENABLE_DESTRUCTIVE_API=true` in `docker-compose.yml` to enable deletions.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Web server port |
| `ENABLE_DESTRUCTIVE_API` | `false` | Must be `true` to run deletions |
| `API_AUTH_TOKEN` | (none) | Optional bearer token for destructive endpoints |

## Infrastructure Note

When running against Stardog behind a reverse proxy, set the proxy read timeout to at least **300 seconds** for SPARQL UPDATE endpoints. The default 30-second timeout causes failures on large cube versions.

## Documentation

See [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md) for full reference.

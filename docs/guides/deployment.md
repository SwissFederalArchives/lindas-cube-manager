# Deployment Guide

This guide covers all methods for deploying the LINDAS Cube Cleanup web application.

## Option 1: Docker (Recommended)

The simplest deployment method uses Docker.

### Build and Run

```bash
# Build the image
docker-compose build

# Start the web app
docker-compose up -d

# View logs
docker-compose logs -f web-app

# Stop
docker-compose down
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Web server port |
| `ENABLE_DESTRUCTIVE_API` | `false` | Enable deletion endpoints |
| `API_AUTH_TOKEN` | (none) | Bearer token for destructive operations |

### Docker Compose Configuration

The `docker-compose.yml` at the project root defines the web-app service. The triplestore is NOT included -- you provide your own (Fuseki, GraphDB, Stardog, or LINDAS).

To enable destructive operations, uncomment the `ENABLE_DESTRUCTIVE_API=true` line in `docker-compose.yml`.

---

## Option 2: Native Node.js

### Prerequisites

- Node.js v16 or later
- npm (comes with Node.js)

### Installation

```bash
cd web-app
npm install
```

### Running

```bash
# Start the server
npm start

# Or use the platform-specific startup scripts:
# Windows (Command Prompt): start.bat
# Windows (PowerShell):     .\start.ps1
# macOS/Linux:              ./start.sh
```

The startup scripts automatically check for Node.js, install dependencies if needed, and launch the server.

### Access

Open http://localhost:3001 in your browser.

---

## Triplestore Setup

The web app connects to an external triplestore. See `docs/guides/multi-triplestore-docker-setup.md` for detailed setup instructions for each supported triplestore:

| Triplestore | Port | License |
|-------------|------|---------|
| Apache Fuseki | 3030 | Free/Open Source |
| GraphDB Free | 7200 | Free (rate limited) |
| Stardog | 5820 | Requires license |
| LINDAS (online) | N/A | Public read access |

---

## Proxy Timeout Requirement (Important)

When running against a Stardog instance behind a reverse proxy (Nginx, HAProxy, etc.),
the proxy's request timeout must be set to at least **300 seconds** for SPARQL UPDATE
endpoints. The default 30-second timeout causes 504 Gateway Timeout errors when deleting
large cube versions with millions of observations.

Add to your Nginx configuration:

```nginx
location ~ ^/sparql {
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;
}
```

Without this change, cube versions with very large observation sets will fail to delete.
The tool handles these failures gracefully (logs the error, continues to the next cube),
but those versions will remain undeleted.

See `docs/reference/stardog-proxy-timeout.md` for full details and background.

---

## Security Notes

- Destructive API endpoints (deletion) are **disabled by default**
- Set `ENABLE_DESTRUCTIVE_API=true` to enable deletion operations
- Optionally set `API_AUTH_TOKEN` to require bearer token authentication
- Backups are automatically created before any deletion and retained for 7 days

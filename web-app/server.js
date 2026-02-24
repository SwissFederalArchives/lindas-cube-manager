const express = require('express');
const fetch = require('node-fetch');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const stardog = require('stardog');
const archiver = require('archiver');
const AdmZip = require('adm-zip');

const app = express();
const PORT = process.env.PORT || 3001;

// =============================================================================
// API SECURITY: Toggle destructive APIs on/off via environment variable
// Set ENABLE_DESTRUCTIVE_API=true to enable deletion endpoints
// Set API_AUTH_TOKEN to require a bearer token for destructive operations
// =============================================================================
const ENABLE_DESTRUCTIVE_API = process.env.ENABLE_DESTRUCTIVE_API === 'true';
const API_AUTH_TOKEN = process.env.API_AUTH_TOKEN || null;

// =============================================================================
// SERVICE-DEPLOYMENT MODE
// When STORE_QUERY_ENDPOINT is set, the server pre-configures the triplestore
// connection from environment variables instead of accepting it from the
// frontend. This is the production deployment pattern (same as cube-creator).
// =============================================================================
const SERVICE_MODE = !!process.env.STORE_QUERY_ENDPOINT;
let SERVICE_CONNECTION = null;

if (SERVICE_MODE) {
    const queryUrl = new URL(process.env.STORE_QUERY_ENDPOINT);
    const pathParts = queryUrl.pathname.replace(/\/(query|update)$/, '').split('/').filter(Boolean);
    const dbName = pathParts[pathParts.length - 1] || '';
    const baseUrl = `${queryUrl.protocol}//${queryUrl.host}`;
    SERVICE_CONNECTION = {
        type: process.env.STORE_ENGINE || 'fuseki',
        mode: 'local',
        baseUrl,
        database: dbName,
        dataset: dbName,
        repository: dbName,
        username: process.env.STORE_ENDPOINTS_USERNAME || '',
        password: process.env.STORE_ENDPOINTS_PASSWORD || '',
        queryEndpoint: process.env.STORE_QUERY_ENDPOINT,
        updateEndpoint: process.env.STORE_UPDATE_ENDPOINT || '',
        graphEndpoint: process.env.STORE_GRAPH_ENDPOINT || '',
    };
    console.log(`Service-deployment mode: connected to ${baseUrl} [${dbName}] (${SERVICE_CONNECTION.type})`);
}

/**
 * Merge service-mode connection fields into a request body object.
 * In service mode, the frontend cannot override the triplestore connection.
 * All other fields (graphUri, query, etc.) are preserved from the body.
 */
function getEffectiveConnection(body) {
    if (!SERVICE_MODE) return body;
    return {
        ...body,
        type: SERVICE_CONNECTION.type,
        mode: SERVICE_CONNECTION.mode,
        baseUrl: SERVICE_CONNECTION.baseUrl,
        dataset: SERVICE_CONNECTION.dataset,
        database: SERVICE_CONNECTION.database,
        repository: SERVICE_CONNECTION.repository,
        username: SERVICE_CONNECTION.username,
        password: SERVICE_CONNECTION.password,
    };
}

// =============================================================================
// KEYCLOAK AUTH (service-deployment mode only)
// Auth is only enforced when SERVICE_MODE is active and AUTH_ISSUER is set.
// In local dev or manual-connection mode, auth is not required.
// =============================================================================
const AUTH_ENABLED = SERVICE_MODE && !!process.env.AUTH_ISSUER;
let jwtMiddleware = null;

if (AUTH_ENABLED) {
    const { expressjwt } = require('express-jwt');
    const { expressJwtSecret } = require('jwks-rsa');
    jwtMiddleware = expressjwt({
        secret: expressJwtSecret({
            cache: true,
            rateLimit: true,
            jwksRequestsPerMinute: 5,
            jwksUri: `${process.env.AUTH_ISSUER}/.well-known/jwks.json`,
        }),
        audience: process.env.AUTH_AUDIENCE,
        issuer: process.env.AUTH_ISSUER,
        algorithms: ['RS256'],
    });
    console.log(`Keycloak auth enabled: issuer=${process.env.AUTH_ISSUER}`);
}

/**
 * Middleware to gate destructive API endpoints.
 * Blocks delete/update operations unless explicitly enabled via environment variable.
 * When API_AUTH_TOKEN is set, requires Bearer token authentication.
 */
function requireDestructiveAccess(req, res, next) {
    if (!ENABLE_DESTRUCTIVE_API) {
        return res.status(403).json({
            error: 'Destructive API endpoints are disabled',
            detail: 'Set ENABLE_DESTRUCTIVE_API=true environment variable to enable deletion operations',
            endpoint: req.path
        });
    }
    if (API_AUTH_TOKEN) {
        const authHeader = req.headers.authorization;
        if (!authHeader || authHeader !== `Bearer ${API_AUTH_TOKEN}`) {
            return res.status(401).json({
                error: 'Authentication required',
                detail: 'Provide a valid Bearer token in the Authorization header'
            });
        }
    }
    next();
}

/**
 * Validate a URI parameter to prevent SPARQL injection.
 * Returns sanitized URI or throws an error.
 */
function validateUriParam(uri, paramName) {
    if (!uri || typeof uri !== 'string') {
        throw new Error(`${paramName} must be a non-empty string`);
    }
    uri = uri.trim();
    if (!/^https?:\/\//.test(uri)) {
        throw new Error(`${paramName} has invalid URI scheme`);
    }
    const dangerousChars = /[<>"{}|\\^`()\n\r\t]/;
    if (dangerousChars.test(uri)) {
        throw new Error(`${paramName} contains invalid characters`);
    }
    return uri;
}

/**
 * Resolve the correct dataset/database/repository name based on triplestore type.
 * Each triplestore uses a different field name: Fuseki uses 'dataset', Stardog uses 'database',
 * GraphDB uses 'repository'. The frontend sends all three fields regardless of which triplestore
 * is selected, so we must pick the right one based on the type to avoid using stale defaults.
 */
function resolveDbName({ type, dataset, database, repository }) {
    switch (type) {
        case 'graphdb':
            return repository || database || dataset;
        case 'stardog':
            return database || dataset || repository;
        case 'fuseki':
        default:
            return dataset || database || repository;
    }
}

/**
 * Validate a backup ID parameter to prevent path traversal attacks.
 * Only allows alphanumeric characters, hyphens, and underscores.
 * Throws an error if the backup ID contains invalid characters.
 */
function validateBackupId(backupId) {
    if (!backupId || typeof backupId !== 'string') {
        throw new Error('Backup ID is required');
    }
    // Only allow alphanumeric, hyphens, and underscores
    if (!/^[a-zA-Z0-9_-]+$/.test(backupId)) {
        throw new Error('Invalid backup ID format');
    }
}

/**
 * Validate that a backup ZIP actually covers the given cube URI(s).
 * Opens the ZIP, reads the manifest, and checks that the cubeUri is listed.
 * Throws an error if the backup does not cover the cube.
 */
function validateBackupCoversUri(backupZipPath, cubeUri) {
    try {
        const zip = new AdmZip(backupZipPath);
        const manifestEntry = zip.getEntry('manifest.json');
        if (!manifestEntry) {
            throw new Error('Backup ZIP does not contain a manifest.json');
        }
        const manifest = JSON.parse(manifestEntry.getData().toString('utf8'));
        // Check single-cube backups (manifest.cube.uri) and multi-cube backups (manifest.cubes[].uri)
        const backedUpUris = [];
        if (manifest.cube && manifest.cube.uri) {
            backedUpUris.push(manifest.cube.uri);
        }
        if (manifest.cubes && Array.isArray(manifest.cubes)) {
            manifest.cubes.forEach(c => { if (c.uri) backedUpUris.push(c.uri); });
        }
        if (!backedUpUris.includes(cubeUri)) {
            throw new Error(`Backup does not cover cube ${cubeUri}. Backed up cubes: ${backedUpUris.join(', ')}`);
        }
    } catch (err) {
        if (err.message.includes('Backup does not cover') || err.message.includes('does not contain')) {
            throw err;
        }
        throw new Error(`Failed to validate backup: ${err.message}`);
    }
}

/**
 * Validate that a base URL is safe (not targeting internal services).
 * Rejects file://, ftp://, and private IP ranges to prevent SSRF.
 */
function validateEndpointUrl(url) {
    if (!url || typeof url !== 'string') {
        throw new Error('Endpoint URL is required');
    }
    url = url.trim();
    // Only allow http and https
    if (!/^https?:\/\//i.test(url)) {
        throw new Error('Endpoint URL must use http or https protocol');
    }
    // Block common internal/private ranges (when not localhost)
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    // Allow localhost and 127.0.0.1 (local development)
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
        return url;
    }
    // Block private IP ranges
    const privatePatterns = [
        /^10\./,
        /^172\.(1[6-9]|2\d|3[01])\./,
        /^192\.168\./,
        /^169\.254\./,
        /^0\./,
        /^fc00:/i,
        /^fe80:/i,
    ];
    for (const pattern of privatePatterns) {
        if (pattern.test(hostname)) {
            throw new Error('Endpoint URL must not target private network addresses');
        }
    }
    return url;
}

// Log API security state on startup
console.log(`[Security] Destructive API endpoints: ${ENABLE_DESTRUCTIVE_API ? 'ENABLED' : 'DISABLED'}`);
console.log(`[Security] API auth token: ${API_AUTH_TOKEN ? 'CONFIGURED' : 'NOT SET (no auth required when destructive API is enabled)'}`);

// Backup directory
const BACKUP_DIR = path.join(__dirname, 'backups');
const BACKUP_RETENTION_DAYS = 7;
const EXPORT_DIR = path.join(__dirname, 'exports');

// Ensure directories exist
if (!fs.existsSync(BACKUP_DIR)) {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
}
if (!fs.existsSync(EXPORT_DIR)) {
    fs.mkdirSync(EXPORT_DIR, { recursive: true });
}

// Configure multer for file uploads with size limit (200MB)
const upload = multer({
    dest: path.join(__dirname, 'uploads'),
    limits: { fileSize: 200 * 1024 * 1024 }
});

// Middleware
app.use(express.json({ limit: '100mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Service oidc-client library (only loaded when auth is enabled)
app.get('/oidc-client.js', (req, res) => {
    if (!AUTH_ENABLED) return res.type('js').send('/* oidc-client not enabled */');
    res.sendFile(path.join(__dirname, 'node_modules/oidc-client/lib/oidc-client.min.js'));
});

// Service-deployment mode: override connection fields in all POST /api/* requests
// so that no matter what the frontend sends, the server always uses the
// pre-configured triplestore connection from environment variables.
if (SERVICE_MODE) {
    app.use('/api', (req, res, next) => {
        if (req.method === 'POST') {
            req.body = getEffectiveConnection(req.body);
        }
        next();
    });
}

// Auth middleware: protect all /api/* routes except /config and /health
app.use('/api', (req, res, next) => {
    if (req.path === '/config' || req.path === '/health') return next();
    if (jwtMiddleware) return jwtMiddleware(req, res, next);
    next();
});

// =============================================================================
// TRIPLESTORE CONFIGURATION
// =============================================================================

// Default endpoints for different triplestore types
const TRIPLESTORE_DEFAULTS = {
    fuseki: {
        local: {
            baseUrl: 'http://localhost:3030',
            queryPath: '/{dataset}/query',
            updatePath: '/{dataset}/update',
            dataPath: '/{dataset}/data',
            datasetsPath: '/$/datasets',
            description: 'Apache Fuseki - Local Development',
            setupInstructions: 'Download from https://jena.apache.org/download/ and run fuseki-server'
        },
        cloud: {
            baseUrl: 'https://lindas.admin.ch',
            queryPath: '/query',
            updatePath: '/update',
            dataPath: '/data',
            description: 'LINDAS Production - Swiss Government Linked Data',
            isProduction: true,
            warning: 'CAUTION: This is the production LINDAS endpoint. All changes affect live data!'
        }
    },
    stardog: {
        local: {
            baseUrl: 'http://localhost:5820',
            queryPath: '/{database}/query',
            updatePath: '/{database}/update',
            dataPath: '/{database}',
            defaultCredentials: { username: 'admin', password: 'admin' },
            description: 'Stardog Free - Local Development (up to 25 databases, 10GB data)',
            setupInstructions: 'Download Stardog Free from https://www.stardog.com/get-started/',
            dockerCommand: 'docker run -d --name stardog -p 5820:5820 -v stardog-data:/var/opt/stardog stardog/stardog:latest',
            freeEditionLimits: {
                maxDatabases: 25,
                maxDataSize: '10GB',
                maxQueryTime: '1 hour'
            }
        },
        cloud: {
            baseUrl: 'https://sd-xxxxx.stardog.cloud:5820',
            queryPath: '/{database}/query',
            updatePath: '/{database}/update',
            dataPath: '/{database}',
            description: 'Stardog Cloud - Production Environment',
            isProduction: true,
            warning: 'CAUTION: This is a cloud/production endpoint. All changes affect live data!'
        }
    },
    graphdb: {
        local: {
            baseUrl: 'http://localhost:7200',
            queryPath: '/repositories/{repository}',
            updatePath: '/repositories/{repository}/statements',
            dataPath: '/repositories/{repository}/statements',
            repositoriesPath: '/rest/repositories',
            description: 'GraphDB Free - Local Development (unlimited data, 2 queries/second)',
            setupInstructions: 'Download from https://graphdb.ontotext.com/documentation/free/',
            dockerCommand: 'docker run -d --name graphdb -p 7200:7200 ontotext/graphdb:free',
            freeEditionLimits: {
                queriesPerSecond: 2,
                concurrentQueries: 1
            }
        },
        cloud: {
            baseUrl: 'https://your-instance.graphdb.cloud',
            queryPath: '/repositories/{repository}',
            updatePath: '/repositories/{repository}/statements',
            dataPath: '/repositories/{repository}/statements',
            description: 'GraphDB Cloud - Production Environment',
            isProduction: true,
            warning: 'CAUTION: This is a cloud/production endpoint. All changes affect live data!'
        }
    }
};

// Environment mode tracking
let currentEnvironmentMode = 'local';
let cloudModeWarningAcknowledged = false;

const LINDAS_ENDPOINT = 'https://lindas.admin.ch/query';
const DEFAULT_FUSEKI_ENDPOINT = 'http://localhost:3030';

// Load universal queries from files
// Checks both the standard path (web-app/../queries) and Docker path (__dirname/queries)
function loadQuery(queryName) {
    const standardPath = path.join(__dirname, '..', 'queries', 'universal', queryName);
    if (fs.existsSync(standardPath)) {
        return fs.readFileSync(standardPath, 'utf8');
    }
    const dockerPath = path.join(__dirname, 'queries', 'universal', queryName);
    if (fs.existsSync(dockerPath)) {
        return fs.readFileSync(dockerPath, 'utf8');
    }
    return null;
}

// =============================================================================
// TRIPLESTORE-AWARE SPARQL EXECUTION
// =============================================================================

/**
 * Build endpoint URLs based on triplestore type
 */
function buildEndpoints(config) {
    const { type, mode, baseUrl, dataset, database, repository, username, password } = config;
    const defaults = TRIPLESTORE_DEFAULTS[type]?.[mode] || TRIPLESTORE_DEFAULTS.fuseki.local;

    const base = baseUrl || defaults.baseUrl;
    let queryEndpoint, updateEndpoint, dataEndpoint;

    switch (type) {
        case 'stardog':
            const db = database || 'mydb';
            queryEndpoint = `${base}${defaults.queryPath.replace('{database}', db)}`;
            updateEndpoint = `${base}${defaults.updatePath.replace('{database}', db)}`;
            dataEndpoint = `${base}${defaults.dataPath.replace('{database}', db)}`;
            break;
        case 'graphdb':
            const repo = repository || 'test';
            queryEndpoint = `${base}${defaults.queryPath.replace('{repository}', repo)}`;
            updateEndpoint = `${base}${defaults.updatePath.replace('{repository}', repo)}`;
            dataEndpoint = `${base}${defaults.dataPath.replace('{repository}', repo)}`;
            break;
        case 'fuseki':
        default:
            const ds = dataset || 'lindas';
            if (defaults.queryPath.includes('{dataset}')) {
                queryEndpoint = `${base}${defaults.queryPath.replace('{dataset}', ds)}`;
                updateEndpoint = `${base}${defaults.updatePath.replace('{dataset}', ds)}`;
                dataEndpoint = `${base}${defaults.dataPath.replace('{dataset}', ds)}`;
            } else {
                queryEndpoint = `${base}${defaults.queryPath}`;
                updateEndpoint = `${base}${defaults.updatePath}`;
                dataEndpoint = `${base}${defaults.dataPath}`;
            }
            break;
    }

    return { queryEndpoint, updateEndpoint, dataEndpoint, username, password };
}

/**
 * Build auth headers based on credentials
 */
function buildAuthHeaders(username, password) {
    if (username && password) {
        const credentials = Buffer.from(`${username}:${password}`).toString('base64');
        return { 'Authorization': `Basic ${credentials}` };
    }
    return {};
}

// Execute SPARQL SELECT query
async function executeSparqlSelect(endpoint, query, auth = {}) {
    const headers = {
        'Accept': 'application/sparql-results+json',
        'Content-Type': 'application/x-www-form-urlencoded',
        ...buildAuthHeaders(auth.username, auth.password)
    };

    const response = await fetch(endpoint, {
        method: 'POST',
        headers: headers,
        body: `query=${encodeURIComponent(query)}`
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`SPARQL query failed: ${response.status} - ${text}`);
    }

    return await response.json();
}

// Execute SPARQL UPDATE query
async function executeSparqlUpdate(endpoint, query, auth = {}) {
    const headers = {
        'Content-Type': 'application/sparql-update',
        ...buildAuthHeaders(auth.username, auth.password)
    };

    const response = await fetch(endpoint, {
        method: 'POST',
        headers: headers,
        body: query
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`SPARQL update failed: ${response.status} - ${text}`);
    }

    return { success: true };
}

// Execute SPARQL CONSTRUCT query to get triples
async function executeSparqlConstruct(endpoint, query, auth = {}) {
    const headers = {
        'Accept': 'application/n-triples',
        'Content-Type': 'application/x-www-form-urlencoded',
        ...buildAuthHeaders(auth.username, auth.password)
    };

    const response = await fetch(endpoint, {
        method: 'POST',
        headers: headers,
        body: `query=${encodeURIComponent(query)}`
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`SPARQL construct failed: ${response.status} - ${text}`);
    }

    return await response.text();
}

// Import data to triplestore
async function importData(config, graphUri, triples) {
    const { dataEndpoint, username, password } = buildEndpoints(config);
    const type = config.type || 'fuseki';

    let url, contentType = 'application/n-triples';

    switch (type) {
        case 'stardog':
            url = `${dataEndpoint}?graph=${encodeURIComponent(graphUri)}`;
            break;
        case 'graphdb':
            url = `${dataEndpoint}?context=${encodeURIComponent('<' + graphUri + '>')}`;
            break;
        case 'fuseki':
        default:
            url = `${dataEndpoint}?graph=${encodeURIComponent(graphUri)}`;
            break;
    }

    const headers = {
        'Content-Type': contentType,
        ...buildAuthHeaders(username, password)
    };

    const response = await fetch(url, {
        method: 'POST',
        headers: headers,
        body: triples
    });

    if (!response.ok) {
        const text = await response.text();
        throw new Error(`Import failed: ${response.status} - ${text}`);
    }

    return { success: true };
}

// =============================================================================
// TRIPLESTORE CONNECTION MANAGEMENT
// =============================================================================

/**
 * Check triplestore connection based on type
 */
async function checkTriplestoreConnection(config) {
    const { type, mode, baseUrl, dataset, database, repository, username, password } = config;
    const defaults = TRIPLESTORE_DEFAULTS[type]?.[mode] || TRIPLESTORE_DEFAULTS.fuseki.local;
    const base = baseUrl || defaults.baseUrl;
    const authHeaders = buildAuthHeaders(username, password);

    let checkUrl, checkPath, checkMethod = 'GET';
    let availableDatasets = [];

    switch (type) {
        case 'stardog':
            // Stardog: Use official stardog.js library
            const stardogDb = database || 'lindas';
            try {
                console.log(`Stardog: Connecting to ${base} with user ${username}`);
                const conn = new stardog.Connection({
                    username: username || 'admin',
                    password: password || 'admin',
                    endpoint: base
                });

                // Try to list databases first
                console.log(`Stardog: Listing databases...`);
                const dbListResult = await stardog.db.list(conn);
                console.log(`Stardog db.list result:`, dbListResult);

                if (dbListResult.ok) {
                    const databases = dbListResult.body.databases || [];
                    return {
                        connected: true,
                        type: 'stardog',
                        mode,
                        baseUrl: base,
                        databases: databases,
                        message: `Connected! Available databases: ${databases.join(', ') || 'none'}`
                    };
                } else {
                    // db.list failed, try a simple query on the specific database
                    console.log(`Stardog: db.list failed, trying query on ${stardogDb}...`);
                    const queryResult = await stardog.query.execute(
                        conn,
                        stardogDb,
                        'ASK { ?s ?p ?o }',
                        'application/sparql-results+json'
                    );
                    console.log(`Stardog query result:`, queryResult);

                    if (queryResult.ok) {
                        return {
                            connected: true,
                            type: 'stardog',
                            mode,
                            baseUrl: base,
                            database: stardogDb,
                            message: `Connected to database: ${stardogDb}`
                        };
                    } else {
                        const status = dbListResult.status || queryResult.status;
                        let errorMessage = `Connection failed: ${dbListResult.statusText || queryResult.statusText || 'Unknown error'}. Status: ${status}`;

                        // Provide helpful message for Stardog Cloud auth failures
                        if (status === 401 && base.includes('.stardog.cloud')) {
                            errorMessage = `Authentication failed (401). For Stardog Cloud: SSO credentials do not work for API access. You need to create a dedicated API user in Stardog Studio: 1) Log into cloud.stardog.com 2) Click your connection 3) Launch Stardog Studio 4) Go to Security > Users 5) Create a new user with username/password 6) Use those credentials here.`;
                        } else if (status === 401) {
                            errorMessage = `Authentication failed (401). Check your username and password.`;
                        }

                        return {
                            connected: false,
                            type: 'stardog',
                            mode,
                            baseUrl: base,
                            error: errorMessage
                        };
                    }
                }
            } catch (err) {
                console.error(`Stardog connection error:`, err);
                return {
                    connected: false,
                    type: 'stardog',
                    mode,
                    baseUrl: base,
                    error: `Connection error: ${err.message}`
                };
            }
            break;

        case 'graphdb':
            // GraphDB: GET /rest/repositories
            checkUrl = `${base}/rest/repositories`;
            try {
                console.log(`GraphDB: Connecting to ${checkUrl}`);
                const response = await fetch(checkUrl, {
                    method: 'GET',
                    headers: { 'Accept': 'application/json', ...authHeaders }
                });
                console.log(`GraphDB response status: ${response.status}`);
                if (response.ok) {
                    const data = await response.json();
                    console.log(`GraphDB repositories:`, data);
                    availableDatasets = data.map(r => r.id);
                    return {
                        connected: true,
                        type: 'graphdb',
                        mode,
                        baseUrl: base,
                        repositories: availableDatasets,
                        message: `Connected! Available repositories: ${availableDatasets.join(', ') || 'none'}`
                    };
                } else {
                    const errorText = await response.text();
                    console.error(`GraphDB connection failed: ${response.status} - ${errorText}`);
                    return {
                        connected: false,
                        type: 'graphdb',
                        mode,
                        baseUrl: base,
                        error: `Connection failed: ${response.status} - ${errorText || response.statusText}`
                    };
                }
            } catch (err) {
                console.error(`GraphDB connection error:`, err);
                return {
                    connected: false,
                    type: 'graphdb',
                    mode,
                    baseUrl: base,
                    error: `Connection error: ${err.message}. Make sure GraphDB is running at ${base}`
                };
            }

        case 'fuseki':
        default:
            // Fuseki: GET /$/datasets
            checkUrl = `${base}/$/datasets`;
            try {
                console.log(`Fuseki: Connecting to ${checkUrl}`);
                const response = await fetch(checkUrl, {
                    method: 'GET',
                    headers: { 'Accept': 'application/json', ...authHeaders }
                });
                console.log(`Fuseki response status: ${response.status}`);
                if (response.ok) {
                    const data = await response.json();
                    availableDatasets = data.datasets || [];
                    return {
                        connected: true,
                        type: 'fuseki',
                        mode,
                        baseUrl: base,
                        datasets: availableDatasets,
                        message: `Connected! Available datasets: ${availableDatasets.map(d => d.ds.name).join(', ') || 'none'}`
                    };
                } else {
                    const errorText = await response.text();
                    console.error(`Fuseki connection failed: ${response.status} - ${errorText}`);
                    return {
                        connected: false,
                        type: 'fuseki',
                        mode,
                        baseUrl: base,
                        error: `Connection failed: ${response.status} - ${errorText || response.statusText}`
                    };
                }
            } catch (err) {
                console.error(`Fuseki connection error:`, err);
                return {
                    connected: false,
                    type: 'fuseki',
                    mode,
                    baseUrl: base,
                    error: `Connection error: ${err.message}. Make sure Fuseki is running at ${base}`
                };
            }
    }

    return { connected: false, type, mode, baseUrl: base, error: 'Could not connect to triplestore' };
}

// =============================================================================
// EXPORT/IMPORT WITH METADATA
// =============================================================================

/**
 * Create a downloadable export package with complete metadata for effortless restore
 * Version 2.0 format includes all necessary information to restore data to any triplestore
 */
function createExportPackage(triples, metadata) {
    // Parse cube URI to extract structured information
    const cubeUri = metadata.cubeUri || '';
    const uriParts = cubeUri.split('/');
    const versionMatch = cubeUri.match(/\/(\d+)\/?$/);
    const version = versionMatch ? parseInt(versionMatch[1]) : null;
    const baseCube = version !== null ? cubeUri.replace(/\/\d+\/?$/, '') : cubeUri;

    // Create a comprehensive JSON wrapper with all restore metadata
    const exportPackage = {
        // Package metadata
        packageVersion: '2.0',
        exportedAt: new Date().toISOString(),
        exportedBy: 'lindas-cube-cleanup',
        format: 'n-triples',

        // Source information (where the data came from)
        source: {
            endpoint: metadata.endpoint,
            dataset: metadata.dataset,
            database: metadata.database,
            repository: metadata.repository,
            triplestoreType: metadata.triplestoreType || 'fuseki',
            triplestoreMode: metadata.triplestoreMode || 'local'
        },

        // Cube metadata for identification
        cube: {
            uri: cubeUri,
            baseCube: baseCube,
            version: version,
            name: metadata.cubeName || uriParts.slice(-2).join('/'),
            graphUri: metadata.graphUri
        },

        // Restore instructions
        restore: {
            targetGraph: metadata.graphUri,
            recommendedDataset: metadata.dataset,
            instructions: [
                'This backup can be restored to any SPARQL-compliant triplestore',
                'The data should be imported into the target graph specified above',
                'For Fuseki: POST to /{dataset}/data?graph=<graphUri>',
                'For Stardog: POST to /{database}?graph=<graphUri>',
                'For GraphDB: POST to /repositories/{repo}/statements?context=<graphUri>'
            ],
            supportedTargets: ['fuseki', 'stardog', 'graphdb']
        },

        // Statistics
        stats: {
            tripleCount: metadata.tripleCount,
            sizeBytes: triples ? Buffer.byteLength(triples, 'utf8') : 0,
            backupId: metadata.backupId
        },

        // Deletion context (if this was a pre-deletion backup)
        deletionContext: metadata.deletionContext || null,

        // The actual data
        data: triples
    };

    return exportPackage;
}

/**
 * Create a ZIP archive backup with manifest and data files
 * This format is preferred for backups as it:
 * - Compresses the data (often 70-90% size reduction)
 * - Separates manifest from data for easy inspection
 * - Is a standard format that can be opened by any ZIP tool
 *
 * ZIP Structure:
 * - manifest.json: Complete metadata for identification and restore
 * - data.nt: The actual triples in N-Triples format
 */
// =============================================================================
// ORPHAN DETECTION QUERIES
// =============================================================================

const ORPHAN_PREFIXES = `
PREFIX cube: <https://cube.link/>
PREFIX schema: <http://schema.org/>
PREFIX sh: <http://www.w3.org/ns/shacl#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
`;

/**
 * Query to find orphan observation sets with their observations (CONSTRUCT for backup)
 */
function constructOrphanObservationSetsQuery(graphUri) {
    return `${ORPHAN_PREFIXES}
CONSTRUCT { ?s ?p ?o }
WHERE {
  {
    SELECT ?s ?p ?o
    WHERE {
      GRAPH <${graphUri}> {
        {
          SELECT ?orphanSet
          WHERE {
            ?orphanSet cube:observation ?someObs .
            FILTER NOT EXISTS { ?anyCube cube:observationSet ?orphanSet }
          }
        }
        {
          ?orphanSet ?p ?o .
          BIND(?orphanSet AS ?s)
        }
        UNION
        {
          ?orphanSet cube:observation ?obs .
          ?obs ?p ?o .
          BIND(?obs AS ?s)
        }
      }
    }
  }
}`;
}

/**
 * Query to find orphan SHACL shapes (CONSTRUCT for backup/preview)
 * Comprehensive version matching query 12: captures shape triples,
 * incoming references, property shape triples, and RDF list nodes.
 */
function constructOrphanShapesQuery(graphUri) {
    return `${ORPHAN_PREFIXES}
CONSTRUCT { ?s ?p ?o }
WHERE {
  GRAPH <${graphUri}> {
    ?orphanShape a sh:NodeShape .
    FILTER NOT EXISTS {
      ?anyCube cube:observationConstraint ?orphanShape .
      ?anyCube a cube:Cube .
    }

    {
      # Shape's own outgoing triples
      ?orphanShape ?p ?o .
      BIND(?orphanShape AS ?s)
    }
    UNION
    {
      # Incoming references to the shape
      ?s ?p ?orphanShape .
      BIND(?orphanShape AS ?o)
    }
    UNION
    {
      # Property shape triples
      ?orphanShape sh:property ?propShape .
      ?propShape ?p ?o .
      BIND(?propShape AS ?s)
    }
    UNION
    {
      # RDF list nodes in property shapes (sh:in value lists)
      ?orphanShape sh:property ?propShape .
      ?propShape sh:in ?list .
      ?list rdf:rest*/rdf:first ?item .
      ?list ?p ?o .
      BIND(?list AS ?s)
    }
  }
}`;
}

/**
 * Query to get summary of orphan objects by type
 */
function findOrphansSummaryQuery(graphUri) {
    return `${ORPHAN_PREFIXES}
SELECT ?orphanType (COUNT(DISTINCT ?orphan) AS ?count)
WHERE {
  {
    SELECT ?orphan ("ObservationSet" AS ?orphanType)
    WHERE {
      GRAPH <${graphUri}> {
        ?orphan cube:observation ?someObs .
        FILTER NOT EXISTS { ?anyCube cube:observationSet ?orphan }
      }
    }
  }
  UNION
  {
    SELECT ?orphan ("NodeShape" AS ?orphanType)
    WHERE {
      GRAPH <${graphUri}> {
        ?orphan a sh:NodeShape .
        FILTER NOT EXISTS { ?anyCube cube:observationConstraint ?orphan }
      }
    }
  }
  UNION
  {
    SELECT ?orphan ("PropertyShape" AS ?orphanType)
    WHERE {
      GRAPH <${graphUri}> {
        ?orphan a sh:PropertyShape .
        FILTER NOT EXISTS { ?anyShape sh:property ?orphan }
      }
    }
  }
}
GROUP BY ?orphanType
ORDER BY ?orphanType`;
}

/**
 * Query to delete orphan observation sets and their observations
 */
function deleteOrphanObservationSetsQuery(graphUri) {
    return `${ORPHAN_PREFIXES}
WITH <${graphUri}>
DELETE {
  ?orphanSet ?setP ?setO .
  ?obs ?obsP ?obsO .
}
WHERE {
  {
    SELECT ?orphanSet
    WHERE {
      ?orphanSet cube:observation ?someObs .
      FILTER NOT EXISTS { ?anyCube cube:observationSet ?orphanSet }
    }
  }
  ?orphanSet ?setP ?setO .
  OPTIONAL {
    ?orphanSet cube:observation ?obs .
    ?obs ?obsP ?obsO .
  }
}`;
}

/**
 * Query to delete orphan SHACL shapes and their full nested structure.
 * Comprehensive version matching query 13: deletes shape triples,
 * incoming references, property shape triples, and RDF list nodes.
 * Uses BIND pattern for Stardog compatibility.
 */
function deleteOrphanShapesQuery(graphUri) {
    return `${ORPHAN_PREFIXES}
DELETE {
  GRAPH <${graphUri}> {
    ?s ?p ?o .
  }
}
WHERE {
  GRAPH <${graphUri}> {
    ?orphanShape a sh:NodeShape .
    FILTER NOT EXISTS {
      ?anyCube cube:observationConstraint ?orphanShape .
      ?anyCube a cube:Cube .
    }

    {
      # Shape's own outgoing triples
      ?orphanShape ?p ?o .
      BIND(?orphanShape AS ?s)
    }
    UNION
    {
      # Incoming references to the shape
      ?s ?p ?orphanShape .
      BIND(?orphanShape AS ?o)
    }
    UNION
    {
      # Property shape triples
      ?orphanShape sh:property ?propShape .
      ?propShape ?p ?o .
      BIND(?propShape AS ?s)
    }
    UNION
    {
      # RDF list nodes in property shapes (sh:in value lists)
      ?orphanShape sh:property ?propShape .
      ?propShape sh:in ?list .
      ?list rdf:rest*/rdf:first ?item .
      ?list ?p ?o .
      BIND(?list AS ?s)
    }
  }
}`;
}

/**
 * Query to count orphan shapes with total triple count (query 14).
 * Returns orphanShapeCount and totalOrphanTriples for quick impact assessment.
 */
function countOrphanShapesQuery(graphUri) {
    return `${ORPHAN_PREFIXES}
SELECT
  (COUNT(DISTINCT ?orphanShape) AS ?orphanShapeCount)
  (COUNT(DISTINCT ?triple) AS ?totalOrphanTriples)
WHERE {
  GRAPH <${graphUri}> {
    ?orphanShape a sh:NodeShape .
    FILTER NOT EXISTS {
      ?anyCube cube:observationConstraint ?orphanShape .
      ?anyCube a cube:Cube .
    }

    {
      ?orphanShape ?sp ?so .
      BIND(CONCAT(STR(?orphanShape), "|", STR(?sp), "|", STR(?so)) AS ?triple)
    }
    UNION
    {
      ?inS ?inP ?orphanShape .
      BIND(CONCAT(STR(?inS), "|", STR(?inP), "|", STR(?orphanShape)) AS ?triple)
    }
    UNION
    {
      ?orphanShape sh:property ?ps .
      ?ps ?psp ?pso .
      BIND(CONCAT(STR(?ps), "|", STR(?psp), "|", STR(?pso)) AS ?triple)
    }
    UNION
    {
      ?orphanShape sh:property ?ps .
      ?ps sh:in ?list .
      ?list rdf:rest*/rdf:first ?item .
      ?list ?lp ?lo .
      BIND(CONCAT(STR(?list), "|", STR(?lp), "|", STR(?lo)) AS ?triple)
    }
  }
}`;
}

/**
 * Query to find individual orphan shapes with details (query 11).
 * Returns each orphan shape with its type, property shape count, and estimated triple count.
 */
function findOrphanShapesQuery(graphUri) {
    return `${ORPHAN_PREFIXES}
SELECT
  ?shape
  ?shapeType
  (COUNT(DISTINCT ?propShape) AS ?propertyShapeCount)
  (COUNT(DISTINCT ?allTriple) AS ?estimatedTriples)
WHERE {
  GRAPH <${graphUri}> {
    ?shape a sh:NodeShape .

    FILTER NOT EXISTS {
      ?anyCube cube:observationConstraint ?shape .
      ?anyCube a cube:Cube .
    }

    OPTIONAL { ?shape rdf:type ?shapeType }

    OPTIONAL { ?shape sh:property ?propShape }

    OPTIONAL {
      {
        ?shape ?sp ?so .
        BIND(CONCAT(STR(?shape), "|", STR(?sp), "|", STR(?so)) AS ?allTriple)
      }
      UNION
      {
        ?shape sh:property ?ps .
        ?ps ?psp ?pso .
        BIND(CONCAT(STR(?ps), "|", STR(?psp), "|", STR(?pso)) AS ?allTriple)
      }
      UNION
      {
        ?shape sh:property ?ps .
        ?ps sh:in ?list .
        ?list rdf:rest*/rdf:first ?item .
        ?list ?lp ?lo .
        BIND(CONCAT(STR(?list), "|", STR(?lp), "|", STR(?lo)) AS ?allTriple)
      }
    }
  }
}
GROUP BY ?shape ?shapeType
ORDER BY ?shape`;
}

/**
 * Create a self-contained ZIP backup that can contain one or more cubes
 * @param {Array|Object} cubesData - Single cube data {triples, cubeUri, ...} or array of cube data
 * @param {Object} metadata - Common metadata (graphUri, endpoint, etc.)
 * @param {Object} options - Backup options { includeMetadata: boolean, includeOrphans: boolean, orphanTriples: string, orphanStats: Object }
 * @returns {Promise} Resolves with backup info
 */
function createZipBackup(cubesData, metadata, options = {}) {
    return new Promise((resolve, reject) => {
        try {
            // Normalize to array for consistent handling
            const cubes = Array.isArray(cubesData) ? cubesData : [cubesData];

            // Build cube info array
            const cubeInfos = cubes.map((cubeData, index) => {
                const cubeUri = cubeData.cubeUri || metadata.cubeUri || '';
                const triples = cubeData.triples || cubeData;
                const versionMatch = cubeUri.match(/\/(\d+)\/?$/);
                const version = versionMatch ? parseInt(versionMatch[1]) : null;
                const baseCube = version !== null ? cubeUri.replace(/\/\d+\/?$/, '') : cubeUri;
                const cubeName = cubeUri.split('/').slice(-2).join('/');
                const dataFileName = cubes.length > 1 ? `data_${index + 1}.nt` : 'data.nt';
                const tripleCount = typeof triples === 'string'
                    ? triples.split('\n').filter(line => line.trim()).length
                    : (cubeData.tripleCount || metadata.tripleCount || 0);

                return {
                    uri: cubeUri,
                    baseCube: baseCube,
                    version: version,
                    name: cubeName,
                    dataFile: dataFileName,
                    tripleCount: tripleCount,
                    dataFileSize: Buffer.isBuffer(triples) ? triples.length : (typeof triples === 'string' ? Buffer.byteLength(triples, 'utf8') : 0),
                    triples: (typeof triples === 'string' || Buffer.isBuffer(triples)) ? triples : ''
                };
            });

            // Calculate totals
            const totalTripleCount = cubeInfos.reduce((sum, c) => sum + c.tripleCount, 0);
            const totalDataSize = cubeInfos.reduce((sum, c) => sum + c.dataFileSize, 0);

            // Generate backup ID
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupId = cubes.length > 1
                ? `multi_${cubes.length}cubes_${timestamp}`
                : `${cubeInfos[0].uri.split('/').slice(-2).join('_')}_${timestamp}`;

            // Calculate options
            const includeMetadata = options.includeMetadata !== false; // Default to true
            const orphanStats = options.orphanStats || { totalCount: 0, types: {} };
            const includeOrphans = options.includeOrphans || false;
            const orphanTriples = options.orphanTriples || '';
            const orphanTripleCount = orphanTriples ? orphanTriples.split('\n').filter(line => line.trim()).length : 0;

            // Create manifest with all information needed for restore (v4.1 format with orphan support)
            const manifest = {
                // Package metadata
                formatVersion: '4.1',
                formatType: 'lindas-cube-backup',
                createdAt: new Date().toISOString(),
                createdBy: 'LINDAS Cube Manager',
                backupId: backupId,

                // Source information (where the data came from)
                source: {
                    endpoint: metadata.endpoint,
                    dataset: metadata.dataset,
                    database: metadata.database,
                    repository: metadata.repository,
                    triplestoreType: metadata.type || metadata.triplestoreType || 'fuseki',
                    triplestoreMode: metadata.triplestoreMode || 'local'
                },

                // Graph information
                graph: {
                    uri: metadata.graphUri,
                    description: 'Named graph containing the cube(s)'
                },

                // Cubes array (v4.0 - supports multiple cubes)
                cubes: cubeInfos.map(c => ({
                    uri: c.uri,
                    baseCube: c.baseCube,
                    version: c.version,
                    name: c.name,
                    dataFile: c.dataFile,
                    tripleCount: c.tripleCount
                })),

                // Backward compatibility: single cube info for v3.0 readers
                cube: cubeInfos.length === 1 ? {
                    uri: cubeInfos[0].uri,
                    baseCube: cubeInfos[0].baseCube,
                    version: cubeInfos[0].version,
                    name: cubeInfos[0].name
                } : undefined,

                // Restore configuration
                restore: {
                    targetGraph: metadata.graphUri,
                    recommendedEndpoint: metadata.endpoint,
                    recommendedDataset: metadata.dataset,
                    dataFormat: 'application/n-triples',
                    instructions: [
                        'Use the LINDAS Cube Manager import function, or:',
                        'For Fuseki: POST each data file to /{dataset}/data?graph=<graphUri>',
                        'For Stardog: POST each data file to /{database}?graph=<graphUri>',
                        'For GraphDB: POST each data file to /repositories/{repo}/statements?context=<graphUri>',
                        includeMetadata ? 'Metadata included: cube properties, SHACL shapes, and structural information.' : 'Metadata excluded: only observations backed up.',
                        includeOrphans ? 'Orphan triples are included in this backup and will be restored.' : ''
                    ].filter(Boolean)
                },

                // Statistics
                stats: {
                    cubeCount: cubeInfos.length,
                    totalTripleCount: totalTripleCount,
                    totalDataSize: totalDataSize,
                    backupId: backupId,
                    includesMetadata: includeMetadata,
                    includesOrphans: includeOrphans,
                    orphanTripleCount: orphanTripleCount
                },

                // Orphan information (v4.1)
                orphans: includeOrphans ? {
                    included: true,
                    tripleCount: orphanTripleCount,
                    stats: orphanStats,
                    dataFile: 'orphans.nt'
                } : undefined,

                // Deletion context (if this was a pre-deletion backup)
                deletionContext: metadata.deletionContext || {
                    reason: 'Cube version deletion',
                    deletedAt: new Date().toISOString(),
                    includeMetadata: includeMetadata,
                    includeOrphans: includeOrphans
                }
            };

            // Generate ZIP filename
            const zipFilename = `backup_${backupId}.zip`;
            const zipPath = path.join(BACKUP_DIR, zipFilename);

            // Create ZIP archive
            const output = fs.createWriteStream(zipPath);
            const archive = archiver('zip', {
                zlib: { level: 9 } // Maximum compression
            });

            output.on('close', () => {
                resolve({
                    zipPath: zipPath,
                    zipFilename: zipFilename,
                    backupId: backupId,
                    manifest: manifest,
                    compressedSize: archive.pointer(),
                    uncompressedSize: totalDataSize
                });
            });

            archive.on('error', (err) => {
                reject(err);
            });

            archive.pipe(output);

            // Add manifest.json
            archive.append(JSON.stringify(manifest, null, 2), { name: 'manifest.json' });

            // Add data files for each cube
            cubeInfos.forEach(cubeInfo => {
                archive.append(cubeInfo.triples, { name: cubeInfo.dataFile });
            });

            // Add orphan triples if included
            if (includeOrphans && orphanTriples) {
                archive.append(orphanTriples, { name: 'orphans.nt' });
            }

            // Add a README for human readability
            const cubeList = cubeInfos.map(c => `  - ${c.uri} (v${c.version || 'N/A'}, ${c.tripleCount} triples, ${c.dataFile})`).join('\n');
            const metadataInfo = includeMetadata ? `
Metadata: INCLUDED
  - Cube properties (schema:name, schema:dateCreated, etc.)
  - SHACL NodeShapes (observationConstraint)
  - SHACL PropertyShapes (sh:property)
  - RDF Lists (sh:in with rdf:first/rdf:rest chains)
` : `
Metadata: EXCLUDED
  - Only observations and observation sets backed up
`;
            const orphanInfo = includeOrphans ? `
Orphan Triples: ${orphanTripleCount} triples included
  - Orphan observation sets and observations
  - Orphan SHACL shapes (NodeShapes, PropertyShapes)
` : '';
            const readme = `LINDAS Cube Backup
==================

Graph: ${metadata.graphUri}
Created: ${manifest.createdAt}
Backup ID: ${backupId}
Total Cubes: ${cubeInfos.length}
Total Triples: ${totalTripleCount}
${metadataInfo}${includeOrphans ? `Orphan Triples: ${orphanTripleCount}\n` : ''}
Cubes in this backup:
${cubeList}
${orphanInfo}
Files in this archive:
- manifest.json: Complete metadata and restore instructions
- restore-instructions.json: Machine-readable restore configuration
${cubeInfos.map(c => `- ${c.dataFile}: RDF triples for ${c.name}`).join('\n')}${includeOrphans ? '\n- orphans.nt: Orphan observation sets, observations, and SHACL shapes' : ''}
- README.txt: This file

To restore this backup:
1. Use the LINDAS Cube Manager "Import Backup" function:
   a. Open the LINDAS Cube Manager web app
   b. Go to the Backups section
   c. Click "Import Backup" and select this ZIP file
   d. Configure the target triplestore connection
   e. Select cubes to restore (or restore all)
   f. Click "Restore"
2. Or use the API:
   POST /api/backup/restore-to with backupId and target connection details
   (see restore-instructions.json for the full API payload)
3. Or manually POST each data file to your triplestore's data endpoint:
   - For Fuseki: POST to /{dataset}/data?graph=<graphUri>
   - For Stardog: POST to /{database}?graph=<graphUri>
   - For GraphDB: POST to /repositories/{repo}/statements?context=<graphUri>

Source Triplestore: ${manifest.source.triplestoreType}
Source Endpoint: ${manifest.source.endpoint}
Source Dataset: ${manifest.source.dataset || manifest.source.database || manifest.source.repository}
`;
            archive.append(readme, { name: 'README.txt' });

            // Add restore-instructions.json for machine-readable restore configuration
            const restoreInstructions = {
                description: 'Instructions for restoring this backup using the LINDAS Cube Manager',
                restoreMethod: 'web-app-import',
                steps: [
                    '1. Open the LINDAS Cube Manager web app',
                    '2. Go to the Backups section',
                    '3. Click "Import Backup" and select this ZIP file',
                    '4. Configure the target triplestore connection',
                    '5. Select cubes to restore (or restore all)',
                    '6. Click "Restore"'
                ],
                targetConnection: {
                    triplestoreType: manifest.source.triplestoreType,
                    endpoint: manifest.source.endpoint,
                    database: manifest.source.database || manifest.source.dataset || manifest.source.repository,
                    graphUri: metadata.graphUri
                },
                cubes: cubeInfos.map(c => ({
                    uri: c.uri,
                    version: c.version,
                    dataFile: c.dataFile,
                    tripleCount: c.tripleCount
                })),
                dataFormat: 'application/n-triples',
                apiEndpoint: {
                    method: 'POST',
                    path: '/api/backup/restore-to',
                    body: {
                        backupId: backupId,
                        type: manifest.source.triplestoreType,
                        baseUrl: manifest.source.endpoint,
                        database: manifest.source.database || manifest.source.dataset || manifest.source.repository,
                        graphUri: metadata.graphUri
                    }
                }
            };
            archive.append(JSON.stringify(restoreInstructions, null, 2), { name: 'restore-instructions.json' });

            archive.finalize();

        } catch (error) {
            reject(error);
        }
    });
}

/**
 * Parse a ZIP backup file and extract manifest and triples
 * Supports both single-cube (data.nt) and multi-cube (data_1.nt, data_2.nt, ...) backups
 */
function parseZipBackup(zipPath) {
    try {
        const zip = new AdmZip(zipPath);
        const entries = zip.getEntries();

        let manifest = null;
        const dataFiles = {};
        let orphanTriples = '';

        for (const entry of entries) {
            if (entry.entryName === 'manifest.json') {
                manifest = JSON.parse(entry.getData().toString('utf8'));
            } else if (entry.entryName === 'orphans.nt') {
                // Orphan triples file (v4.1+)
                orphanTriples = entry.getData().toString('utf8');
            } else if (entry.entryName.endsWith('.nt')) {
                // Collect all .nt data files (data.nt or data_1.nt, data_2.nt, etc.)
                dataFiles[entry.entryName] = entry.getData().toString('utf8');
            }
        }

        if (!manifest) {
            throw new Error('Invalid backup ZIP: missing manifest.json');
        }

        // Combine all triples from data files
        let allTriples = '';
        const dataFileNames = Object.keys(dataFiles).sort();

        if (dataFileNames.length === 0) {
            throw new Error('Invalid backup ZIP: no data files found');
        }

        // For single-cube backups (data.nt) or multi-cube backups (data_N.nt)
        for (const fileName of dataFileNames) {
            if (allTriples) allTriples += '\n';
            allTriples += dataFiles[fileName];
        }

        // Get cubes info from manifest (v4.0 format) or build from single cube (v3.0)
        const cubes = manifest.cubes || (manifest.cube ? [manifest.cube] : []);

        return {
            isPackage: true,
            isZip: true,
            packageVersion: manifest.formatVersion || '3.0',
            metadata: {
                // For multi-cube, use first cube as primary
                cubeUri: manifest.cube?.uri || cubes[0]?.uri,
                baseCube: manifest.cube?.baseCube || cubes[0]?.baseCube,
                version: manifest.cube?.version || cubes[0]?.version,
                cubeName: manifest.cube?.name || cubes[0]?.name,
                cubeTitle: manifest.cube?.title || cubes[0]?.title,
                graphUri: manifest.graph?.uri,
                // Source information
                sourceEndpoint: manifest.source?.endpoint,
                sourceDataset: manifest.source?.dataset,
                sourceDatabase: manifest.source?.database,
                sourceRepository: manifest.source?.repository,
                sourceType: manifest.source?.triplestoreType,
                sourceMode: manifest.source?.triplestoreMode,
                // Stats
                tripleCount: manifest.stats?.totalTripleCount || manifest.stats?.tripleCount,
                dataFileSize: manifest.stats?.totalDataSize || manifest.stats?.dataFileSize,
                backupId: manifest.backupId || manifest.stats?.backupId,
                // Orphan info (v4.1+)
                includesOrphans: manifest.stats?.includesOrphans || manifest.orphans?.included || false,
                orphanTripleCount: manifest.stats?.orphanTripleCount || manifest.orphans?.tripleCount || 0,
                // Export info
                createdAt: manifest.createdAt,
                createdBy: manifest.createdBy
            },
            restore: manifest.restore,
            triples: allTriples,
            orphanTriples: orphanTriples,
            format: 'n-triples',
            manifest: manifest,
            // Multi-cube support
            cubes: cubes,
            cubeCount: cubes.length,
            dataFiles: dataFiles
        };
    } catch (error) {
        throw new Error(`Failed to parse ZIP backup: ${error.message}`);
    }
}

/**
 * Parse an import package to extract metadata and triples
 * Supports ZIP (v3.0), JSON v2.0, JSON v1.0, and raw N-Triples formats
 */
function parseImportPackage(content, filePath = null) {
    try {
        // Try to parse as JSON export package
        const pkg = JSON.parse(content);

        // Check for v2.0 format (packageVersion field)
        if (pkg.packageVersion === '2.0' && pkg.cube && pkg.data) {
            return {
                isPackage: true,
                packageVersion: '2.0',
                metadata: {
                    cubeUri: pkg.cube.uri,
                    baseCube: pkg.cube.baseCube,
                    version: pkg.cube.version,
                    cubeName: pkg.cube.name,
                    graphUri: pkg.cube.graphUri,
                    // Source information
                    sourceEndpoint: pkg.source?.endpoint,
                    sourceDataset: pkg.source?.dataset,
                    sourceDatabase: pkg.source?.database,
                    sourceRepository: pkg.source?.repository,
                    sourceType: pkg.source?.triplestoreType,
                    sourceMode: pkg.source?.triplestoreMode,
                    // Stats
                    tripleCount: pkg.stats?.tripleCount,
                    sizeBytes: pkg.stats?.sizeBytes,
                    backupId: pkg.stats?.backupId,
                    // Export info
                    exportedAt: pkg.exportedAt,
                    exportedBy: pkg.exportedBy
                },
                restore: pkg.restore,
                triples: pkg.data,
                format: pkg.format || 'n-triples'
            };
        }

        // Check for v1.0 format (version field with metadata object)
        if (pkg.version && pkg.metadata && pkg.data) {
            return {
                isPackage: true,
                packageVersion: '1.0',
                metadata: {
                    cubeUri: pkg.metadata.cubeUri,
                    graphUri: pkg.metadata.graphUri,
                    sourceEndpoint: pkg.metadata.sourceEndpoint,
                    sourceDataset: pkg.metadata.sourceDataset,
                    sourceType: pkg.metadata.sourceType || 'fuseki',
                    tripleCount: pkg.metadata.tripleCount,
                    cubeName: pkg.metadata.cubeName,
                    description: pkg.metadata.description
                },
                triples: pkg.data,
                format: pkg.format || 'n-triples'
            };
        }
    } catch (e) {
        // Not JSON, treat as raw N-Triples
    }

    // Fallback: raw N-Triples content
    return {
        isPackage: false,
        packageVersion: null,
        metadata: null,
        triples: content,
        format: 'n-triples'
    };
}

// API Routes

// Service configuration (public — used by the frontend to detect service mode)
// Must be public (no auth) so the frontend can bootstrap the OIDC flow.
app.get('/api/config', (req, res) => {
    if (SERVICE_MODE) {
        res.json({
            serviceMode: true,
            connection: {
                type: SERVICE_CONNECTION.type,
                baseUrl: SERVICE_CONNECTION.baseUrl,
                database: SERVICE_CONNECTION.database,
                queryEndpoint: SERVICE_CONNECTION.queryEndpoint,
                // credentials are never sent to the frontend
            },
            auth: AUTH_ENABLED ? {
                enabled: true,
                issuer: process.env.AUTH_ISSUER,
                clientId: process.env.AUTH_CLIENT_ID,
                audience: process.env.AUTH_AUDIENCE,
            } : { enabled: false },
        });
    } else {
        res.json({ serviceMode: false });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// =============================================================================
// MULTI-TRIPLESTORE API ENDPOINTS
// =============================================================================

// Check any triplestore connection
app.post('/api/triplestore/check', async (req, res) => {
    try {
        const config = req.body;
        const result = await checkTriplestoreConnection(config);
        res.json(result);
    } catch (error) {
        res.json({ connected: false, error: error.message });
    }
});

// Get triplestore defaults
app.get('/api/triplestore/defaults', (req, res) => {
    res.json(TRIPLESTORE_DEFAULTS);
});

// Get environment information with setup instructions
app.get('/api/environment/info', (req, res) => {
    const { type, mode } = req.query;
    const triplestoreType = type || 'fuseki';
    const triplestoreMode = mode || 'local';

    const config = TRIPLESTORE_DEFAULTS[triplestoreType]?.[triplestoreMode];

    if (!config) {
        return res.status(400).json({ error: 'Invalid triplestore type or mode' });
    }

    res.json({
        type: triplestoreType,
        mode: triplestoreMode,
        isProduction: config.isProduction || false,
        isCloud: triplestoreMode === 'cloud',
        description: config.description || '',
        setupInstructions: config.setupInstructions || '',
        dockerCommand: config.dockerCommand || '',
        warning: config.warning || '',
        freeEditionLimits: config.freeEditionLimits || null,
        defaultEndpoint: config.baseUrl
    });
});

// Check if cloud mode requires warning acknowledgment
app.post('/api/environment/check-mode', (req, res) => {
    const { type, mode } = req.body;
    const config = TRIPLESTORE_DEFAULTS[type]?.[mode];

    if (!config) {
        return res.status(400).json({ error: 'Invalid triplestore type or mode' });
    }

    const isProduction = config.isProduction || false;
    const requiresAcknowledgment = mode === 'cloud' && isProduction;

    res.json({
        type,
        mode,
        isProduction,
        isCloud: mode === 'cloud',
        requiresAcknowledgment,
        warning: config.warning || null,
        description: config.description || ''
    });
});

// Get setup instructions for a specific triplestore
app.get('/api/triplestore/setup/:type', (req, res) => {
    const { type } = req.params;
    const config = TRIPLESTORE_DEFAULTS[type];

    if (!config) {
        return res.status(404).json({ error: 'Unknown triplestore type' });
    }

    const setupInfo = {
        type,
        name: type === 'fuseki' ? 'Apache Fuseki' : type === 'stardog' ? 'Stardog' : 'GraphDB',
        local: {
            description: config.local.description,
            setupInstructions: config.local.setupInstructions,
            dockerCommand: config.local.dockerCommand,
            defaultEndpoint: config.local.baseUrl,
            freeEditionLimits: config.local.freeEditionLimits,
            defaultCredentials: config.local.defaultCredentials
        },
        cloud: {
            description: config.cloud.description,
            warning: config.cloud.warning,
            isProduction: config.cloud.isProduction
        },
        paths: {
            query: config.local.queryPath,
            update: config.local.updatePath,
            data: config.local.dataPath
        }
    };

    res.json(setupInfo);
});

// Execute SPARQL query on any triplestore
app.post('/api/triplestore/query', async (req, res) => {
    try {
        const { type, mode, baseUrl, dataset, database, repository, username, password, query, queryType } = req.body;

        const config = { type, mode, baseUrl, dataset, database, repository, username, password };
        const endpoints = buildEndpoints(config);
        const auth = { username, password };

        const startTime = Date.now();

        if (queryType === 'update') {
            await executeSparqlUpdate(endpoints.updateEndpoint, query, auth);
            const duration = Date.now() - startTime;
            res.json({ success: true, queryType: 'update', message: 'Update executed successfully', duration });
        } else if (queryType === 'construct') {
            const triples = await executeSparqlConstruct(endpoints.queryEndpoint, query, auth);
            const tripleCount = triples.split('\n').filter(line => line.trim()).length;
            const duration = Date.now() - startTime;
            res.json({ success: true, queryType: 'construct', triples, tripleCount, duration });
        } else {
            const result = await executeSparqlSelect(endpoints.queryEndpoint, query, auth);
            const duration = Date.now() - startTime;
            res.json({
                success: true,
                queryType: 'select',
                results: result.results,
                head: result.head,
                duration,
                rowCount: result.results.bindings.length
            });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Import data to any triplestore
app.post('/api/triplestore/import', requireDestructiveAccess, async (req, res) => {
    try {
        const { type, mode, baseUrl, dataset, database, repository, username, password, graphUri, triples } = req.body;

        const config = { type, mode, baseUrl, dataset, database, repository, username, password };
        await importData(config, graphUri, triples);

        const tripleCount = triples.split('\n').filter(line => line.trim()).length;
        res.json({ success: true, tripleCount });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Check Fuseki connection
app.post('/api/fuseki/check', async (req, res) => {
    try {
        const { endpoint } = req.body;
        const fusekiEndpoint = endpoint || DEFAULT_FUSEKI_ENDPOINT;

        // Try to get datasets
        const response = await fetch(`${fusekiEndpoint}/$/datasets`, {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
        });

        if (response.ok) {
            const data = await response.json();
            res.json({
                connected: true,
                datasets: data.datasets || [],
                endpoint: fusekiEndpoint
            });
        } else {
            res.json({ connected: false, error: 'Fuseki not responding' });
        }
    } catch (error) {
        res.json({ connected: false, error: error.message });
    }
});

// List graphs in Fuseki dataset
app.post('/api/fuseki/graphs', async (req, res) => {
    try {
        const { endpoint, dataset } = req.body;
        const sparqlEndpoint = `${endpoint}/${dataset}/query`;

        const query = `
            SELECT DISTINCT ?graph (COUNT(*) as ?tripleCount)
            WHERE {
                GRAPH ?graph { ?s ?p ?o }
            }
            GROUP BY ?graph
            ORDER BY DESC(?tripleCount)
        `;

        const result = await executeSparqlSelect(sparqlEndpoint, query);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// List available graphs in LINDAS
app.post('/api/lindas/graphs', async (req, res) => {
    try {
        const { searchTerm } = req.body;

        // Sanitize search term: only allow URI-safe characters to prevent SPARQL injection
        const safeTerm = searchTerm ? searchTerm.replace(/[^a-zA-Z0-9._~:/?#@!$&'*+,;=%-]/g, '') : '';

        let query = `
            SELECT DISTINCT ?graph (COUNT(*) as ?tripleCount)
            WHERE {
                GRAPH ?graph { ?s ?p ?o }
                ${safeTerm ? `FILTER(CONTAINS(LCASE(STR(?graph)), LCASE("${safeTerm}")))` : ''}
            }
            GROUP BY ?graph
            ORDER BY DESC(?tripleCount)
            LIMIT 50
        `;

        const result = await executeSparqlSelect(LINDAS_ENDPOINT, query);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// List all graphs from LINDAS that contain cubes (much faster than listing all graphs)
app.post('/api/lindas/all-graphs', async (req, res) => {
    try {
        // Only list graphs that contain cube:Cube - this is much faster
        const query = `
            PREFIX cube: <https://cube.link/>
            SELECT DISTINCT ?graph
            WHERE {
                GRAPH ?graph { ?s a cube:Cube }
            }
            ORDER BY ?graph
            LIMIT 200
        `;

        const result = await executeSparqlSelect(LINDAS_ENDPOINT, query);
        const graphs = (result.results?.bindings || [])
            .map(b => ({ uri: b.graph?.value }))
            .filter(g => g.uri);
        res.json({ graphs });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// List all cubes from a LINDAS graph
app.post('/api/lindas/cubes', async (req, res) => {
    try {
        const { graphUri } = req.body;

        if (!graphUri) {
            return res.status(400).json({ error: 'graphUri is required' });
        }

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');

        const query = `
            PREFIX cube: <https://cube.link/>
            PREFIX schema: <http://schema.org/>
            PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

            SELECT DISTINCT ?cube ?title ?version ?baseCube ?dateCreated
            WHERE {
                GRAPH <${graphUri}> {
                    ?cube a cube:Cube .
                    OPTIONAL { ?cube schema:name ?title . FILTER(lang(?title) = "en" || lang(?title) = "de" || lang(?title) = "") }
                    OPTIONAL { ?cube schema:dateCreated ?dateCreated }

                    # Extract version number and base cube from URI
                    BIND(REPLACE(STR(?cube), "^.*/([0-9]+)/?$", "$1") AS ?versionStr)
                    BIND(IF(REGEX(STR(?cube), "^.*/[0-9]+/?$"), xsd:integer(?versionStr), 0) AS ?version)
                    BIND(REPLACE(STR(?cube), "^(.*/[^/]+)/[0-9]+/?$", "$1") AS ?baseCubeStr)
                    BIND(IF(REGEX(STR(?cube), "^.*/[^/]+/[0-9]+/?$"), IRI(?baseCubeStr), ?cube) AS ?baseCube)
                }
            }
            ORDER BY ?baseCube DESC(?version)
            LIMIT 500
        `;

        const result = await executeSparqlSelect(LINDAS_ENDPOINT, query);
        const cubes = (result.results?.bindings || []).map(b => ({
            cube: b.cube?.value,
            title: b.title?.value,
            version: b.version?.value,
            baseCube: b.baseCube?.value,
            dateCreated: b.dateCreated?.value
        })).filter(c => c.cube);
        res.json({ cubes });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Download cube data from LINDAS
app.post('/api/lindas/download-cube', async (req, res) => {
    try {
        const { graphUri, cubeUri } = req.body;

        // Validate URI parameters to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        validateUriParam(cubeUri, 'cubeUri');

        // Construct query to get all triples for a specific cube
        const query = `
            PREFIX cube: <https://cube.link/>
            PREFIX schema: <http://schema.org/>
            PREFIX sh: <http://www.w3.org/ns/shacl#>
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

            CONSTRUCT {
                ?s ?p ?o .
            }
            WHERE {
                GRAPH <${graphUri}> {
                    {
                        # Cube metadata
                        <${cubeUri}> ?p ?o .
                        BIND(<${cubeUri}> AS ?s)
                    }
                    UNION
                    {
                        # Blank node metadata (second level)
                        <${cubeUri}> ?p1 ?bn .
                        FILTER(isBlank(?bn))
                        ?bn ?p ?o .
                        BIND(?bn AS ?s)
                    }
                    UNION
                    {
                        # Observation constraint (shape)
                        <${cubeUri}> cube:observationConstraint ?shape .
                        ?shape ?p ?o .
                        BIND(?shape AS ?s)
                    }
                    UNION
                    {
                        # Property shapes
                        <${cubeUri}> cube:observationConstraint ?shape .
                        ?shape sh:property ?propShape .
                        ?propShape ?p ?o .
                        BIND(?propShape AS ?s)
                    }
                    UNION
                    {
                        # RDF list items in property shapes
                        <${cubeUri}> cube:observationConstraint ?shape .
                        ?shape sh:property ?propShape .
                        ?propShape sh:in ?list .
                        ?list rdf:rest*/rdf:first ?item .
                        ?list ?p ?o .
                        BIND(?list AS ?s)
                    }
                    UNION
                    {
                        # Observation set
                        <${cubeUri}> cube:observationSet ?obsSet .
                        ?obsSet ?p ?o .
                        BIND(?obsSet AS ?s)
                    }
                    UNION
                    {
                        # Observations
                        <${cubeUri}> cube:observationSet ?obsSet .
                        ?obsSet cube:observation ?obs .
                        ?obs ?p ?o .
                        BIND(?obs AS ?s)
                    }
                }
            }
        `;

        const triples = await executeSparqlConstruct(LINDAS_ENDPOINT, query);
        const tripleCount = triples.split('\n').filter(line => line.trim()).length;

        res.json({
            success: true,
            triples: triples,
            tripleCount: tripleCount,
            cubeUri: cubeUri
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Download entire graph from LINDAS (chunked approach for large graphs)
app.post('/api/lindas/download-graph', async (req, res) => {
    try {
        const { graphUri } = req.body;
        const offset = Math.max(0, parseInt(req.body.offset, 10) || 0);
        const limit = Math.min(100000, Math.max(1, parseInt(req.body.limit, 10) || 100000));

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');

        const query = `
            CONSTRUCT { ?s ?p ?o }
            WHERE {
                GRAPH <${graphUri}> { ?s ?p ?o }
            }
            OFFSET ${offset}
            LIMIT ${limit}
        `;

        const triples = await executeSparqlConstruct(LINDAS_ENDPOINT, query);
        const tripleCount = triples.split('\n').filter(line => line.trim()).length;

        res.json({
            success: true,
            triples: triples,
            tripleCount: tripleCount,
            offset: offset,
            hasMore: tripleCount >= limit
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Import triples into Fuseki
app.post('/api/fuseki/import', requireDestructiveAccess, async (req, res) => {
    try {
        const { endpoint, dataset, graphUri, triples } = req.body;
        const dataEndpoint = `${endpoint}/${dataset}/data`;

        const response = await fetch(`${dataEndpoint}?graph=${encodeURIComponent(graphUri)}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/n-triples'
            },
            body: triples
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Import failed: ${response.status} - ${text}`);
        }

        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// List cube versions in a graph (uses universal query 01)
app.post('/api/cubes/list-versions', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, username, password, type } = req.body;

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        // Support both endpoint and baseUrl, and dataset/database/repository for different triplestores
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });

        // Construct triplestore-specific endpoint
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            // Fuseki and Stardog use /{db}/query pattern
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }
        const auth = { username, password };

        let query = loadQuery('01-list-all-cube-versions.rq');
        if (!query) {
            // Fallback query
            query = `
                PREFIX cube: <https://cube.link/>
                PREFIX schema: <http://schema.org/>
                PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

                SELECT ?baseCube ?cube ?version ?dateCreated ?dateModified ?title
                WHERE {
                    GRAPH <GRAPH_URI> {
                        ?cube a cube:Cube .
                        OPTIONAL { ?cube schema:dateCreated ?dateCreated }
                        OPTIONAL { ?cube schema:dateModified ?dateModified }
                        OPTIONAL { ?cube schema:name ?title . FILTER(LANG(?title) = "de" || LANG(?title) = "") }

                        BIND(REPLACE(STR(?cube), "^(.*/[^/]+)/[0-9]+/?$", "$1") AS ?baseCube)
                        BIND(REPLACE(STR(?cube), "^.*/([^/]+)/([0-9]+)/?$", "$2") AS ?versionStr)
                        BIND(IF(REGEX(STR(?cube), "^.*/[^/]+/[0-9]+/?$"), xsd:integer(?versionStr), 0) AS ?version)
                    }
                }
                ORDER BY ?baseCube DESC(?version)
            `;
        }

        query = query.replace(/<GRAPH_URI>/g, `<${graphUri}>`);

        const result = await executeSparqlSelect(sparqlEndpoint, query, auth);

        // Format response for client - extract versions from SPARQL bindings
        const versions = (result.results?.bindings || []).map(binding => ({
            baseCube: binding.baseCube?.value,
            cube: binding.cube?.value,
            version: binding.version?.value,
            dateCreated: binding.dateCreated?.value,
            dateModified: binding.dateModified?.value,
            title: binding.title?.value
        }));

        res.json({ versions });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Count versions per cube (uses universal query 02)
app.post('/api/cubes/count-versions', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, username, password, type, versionsToKeep } = req.body;

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });
        const keepCount = Math.max(1, parseInt(versionsToKeep, 10) || 2);

        // Construct triplestore-specific endpoint
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }
        const auth = { username, password };

        let query = loadQuery('02-count-versions-per-cube.rq');
        if (!query) {
            query = `
                PREFIX cube: <https://cube.link/>
                PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

                SELECT ?baseCube (COUNT(DISTINCT ?cube) AS ?versionCount)
                       (GROUP_CONCAT(DISTINCT ?versionStr; separator=", ") AS ?versions)
                WHERE {
                    GRAPH <GRAPH_URI> {
                        ?cube a cube:Cube .
                        BIND(REPLACE(STR(?cube), "^(.*/[^/]+)/[0-9]+/?$", "$1") AS ?baseCube)
                        BIND(REPLACE(STR(?cube), "^.*/([0-9]+)/?$", "$1") AS ?versionStr)
                        FILTER(REGEX(STR(?cube), "^.*/[^/]+/[0-9]+/?$"))
                    }
                }
                GROUP BY ?baseCube
                HAVING (COUNT(DISTINCT ?cube) > ${keepCount})
                ORDER BY DESC(?versionCount)
            `;
        }

        query = query.replace(/<GRAPH_URI>/g, `<${graphUri}>`);

        const result = await executeSparqlSelect(sparqlEndpoint, query, auth);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Identify versions to delete - gets all versions and calculates which to keep/delete
app.post('/api/cubes/identify-deletions', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, username, password, type, versionsToKeep } = req.body;

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });

        // Construct triplestore-specific endpoint
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }
        const auth = { username, password };

        // Use the list-versions query to get ALL versions
        let query = loadQuery('01-list-all-cube-versions.rq');
        if (!query) {
            query = `
                PREFIX cube: <https://cube.link/>
                PREFIX schema: <http://schema.org/>
                PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

                SELECT ?baseCube ?cube ?version ?dateCreated ?dateModified ?title
                WHERE {
                    GRAPH <GRAPH_URI> {
                        ?cube a cube:Cube .
                        OPTIONAL { ?cube schema:dateCreated ?dateCreated }
                        OPTIONAL { ?cube schema:dateModified ?dateModified }
                        OPTIONAL { ?cube schema:name ?title . FILTER(LANG(?title) = "de" || LANG(?title) = "") }

                        BIND(REPLACE(STR(?cube), "^(.*/[^/]+)/[0-9]+/?$", "$1") AS ?baseCube)
                        BIND(REPLACE(STR(?cube), "^.*/([^/]+)/([0-9]+)/?$", "$2") AS ?versionStr)
                        BIND(IF(REGEX(STR(?cube), "^.*/[^/]+/[0-9]+/?$"), xsd:integer(?versionStr), 0) AS ?version)
                    }
                }
                ORDER BY ?baseCube DESC(?version)
            `;
        }

        query = query.replace(/<GRAPH_URI>/g, `<${graphUri}>`);

        const result = await executeSparqlSelect(sparqlEndpoint, query, auth);

        // Parse SPARQL results into version objects
        const bindings = result.results?.bindings || [];
        const versions = bindings.map(binding => ({
            baseCube: binding.baseCube?.value,
            cube: binding.cube?.value,
            version: parseInt(binding.version?.value) || 0,
            dateCreated: binding.dateCreated?.value,
            title: binding.title?.value
        }));

        // Group by baseCube and calculate ranks
        const baseCubeGroups = {};
        versions.forEach(v => {
            if (!baseCubeGroups[v.baseCube]) {
                baseCubeGroups[v.baseCube] = [];
            }
            baseCubeGroups[v.baseCube].push(v);
        });

        // Sort each group by version descending and assign ranks
        const toDelete = [];
        const toKeep = [];
        const keepCount = Math.max(1, parseInt(versionsToKeep, 10) || 2);

        Object.values(baseCubeGroups).forEach(group => {
            // Sort by version number descending (newest first)
            group.sort((a, b) => b.version - a.version);

            group.forEach((v, index) => {
                const rank = index + 1; // 1-based rank
                const action = rank <= keepCount ? 'KEEP' : 'DELETE';
                const cube = { ...v, rank, action };

                if (action === 'DELETE') {
                    toDelete.push(cube);
                } else {
                    toKeep.push(cube);
                }
            });
        });

        res.json({ toDelete, toKeep });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Preview triples to delete for a specific cube
app.post('/api/cubes/preview-deletion', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, cubeUri, username, password, type } = req.body;

        // Validate URI parameters to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        validateUriParam(cubeUri, 'cubeUri');
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });

        // Construct triplestore-specific endpoint
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }
        const auth = { username, password };

        const query = `
            PREFIX cube: <https://cube.link/>
            PREFIX sh: <http://www.w3.org/ns/shacl#>
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

            SELECT
                (COUNT(DISTINCT ?metaTriple) AS ?metaTriples)
                (COUNT(DISTINCT ?shapeTriple) AS ?shapeTriples)
                (COUNT(DISTINCT ?obsTriple) AS ?observationTriples)
            WHERE {
                GRAPH <${graphUri}> {
                    {
                        <${cubeUri}> ?p1 ?o1 .
                        BIND(CONCAT(STR(<${cubeUri}>), STR(?p1), STR(?o1)) AS ?metaTriple)
                    }
                    UNION
                    {
                        <${cubeUri}> ?p2 ?bn2 .
                        FILTER(isBlank(?bn2))
                        ?bn2 ?p3 ?o3 .
                        BIND(CONCAT(STR(?bn2), STR(?p3), STR(?o3)) AS ?metaTriple)
                    }
                    UNION
                    {
                        <${cubeUri}> cube:observationConstraint ?shape .
                        ?shape ?p4 ?o4 .
                        BIND(CONCAT(STR(?shape), STR(?p4), STR(?o4)) AS ?shapeTriple)
                    }
                    UNION
                    {
                        <${cubeUri}> cube:observationConstraint ?shape .
                        ?shape sh:property ?propShape .
                        ?propShape ?p5 ?o5 .
                        BIND(CONCAT(STR(?propShape), STR(?p5), STR(?o5)) AS ?shapeTriple)
                    }
                    UNION
                    {
                        <${cubeUri}> cube:observationSet ?obsSet .
                        ?obsSet ?p6 ?o6 .
                        BIND(CONCAT(STR(?obsSet), STR(?p6), STR(?o6)) AS ?obsTriple)
                    }
                    UNION
                    {
                        <${cubeUri}> cube:observationSet ?obsSet .
                        ?obsSet cube:observation ?obs .
                        ?obs ?p7 ?o7 .
                        BIND(CONCAT(STR(?obs), STR(?p7), STR(?o7)) AS ?obsTriple)
                    }
                }
            }
        `;

        const result = await executeSparqlSelect(sparqlEndpoint, query, auth);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete observations - Query 07
app.post('/api/cubes/delete-observations', requireDestructiveAccess, async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, cubeUri, username, password, type, backupId } = req.body;

        // Require a valid backup that covers this specific cube before allowing deletion
        if (!backupId) {
            return res.status(400).json({ error: 'backupId is required. A backup must be created before deletion.' });
        }
        validateBackupId(backupId);
        const backupZipPath = path.join(BACKUP_DIR, `backup_${backupId}.zip`);
        if (!fs.existsSync(backupZipPath)) {
            return res.status(400).json({ error: 'No backup found with the provided backupId. Create a backup first.' });
        }
        const safeGraphUri = validateUriParam(graphUri, 'graphUri');
        const safeCubeUri = validateUriParam(cubeUri, 'cubeUri');
        validateBackupCoversUri(backupZipPath, safeCubeUri);
        const base = endpoint || baseUrl;
        validateEndpointUrl(base);
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });

        // Construct triplestore-specific endpoints
        let queryEndpoint, updateEndpoint;
        if (triplestoreType === 'graphdb') {
            queryEndpoint = db ? `${base}/repositories/${db}` : base;
            updateEndpoint = db ? `${base}/repositories/${db}/statements` : `${base}/statements`;
        } else {
            queryEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
            updateEndpoint = db ? `${base}/${db}/update` : `${base}/update`;
        }
        const auth = { username, password };

        // Count triples before deletion (for reporting)
        const countQuery = `
            PREFIX cube: <https://cube.link/>
            SELECT (COUNT(*) AS ?count)
            WHERE {
                GRAPH <${safeGraphUri}> {
                    <${safeCubeUri}> cube:observationSet ?obsSet .
                    ?obsSet cube:observation ?obs .
                    ?obs ?p ?o .
                }
            }
        `;
        const countResult = await executeSparqlSelect(queryEndpoint, countQuery, auth);
        const triplesDeleted = parseInt(countResult.results?.bindings?.[0]?.count?.value) || 0;

        // Delete observations in chunks to stay within the proxy gateway timeout.
        // Each chunked DELETE targets CHUNK_SIZE triples at a time; we loop until
        // the count reaches zero. This avoids 504 errors on large cubes.
        const CHUNK_SIZE = 100000;
        const MAX_CHUNKS = 100000; // absolute safety limit
        let chunksProcessed = 0;
        let remaining = triplesDeleted;

        while (remaining > 0 && chunksProcessed < MAX_CHUNKS) {
            const chunkQuery = `
                PREFIX cube: <https://cube.link/>
                WITH <${safeGraphUri}>
                DELETE {
                    ?obs ?p ?o .
                }
                WHERE {
                    {
                        SELECT ?obs ?p ?o
                        WHERE {
                            <${safeCubeUri}> cube:observationSet ?obsSet .
                            ?obsSet cube:observation ?obs .
                            ?obs ?p ?o .
                        }
                        LIMIT ${CHUNK_SIZE}
                    }
                }
            `;
            await executeSparqlUpdate(updateEndpoint, chunkQuery, auth);
            chunksProcessed++;

            // Re-check remaining count
            const checkResult = await executeSparqlSelect(queryEndpoint, countQuery, auth);
            remaining = parseInt(checkResult.results?.bindings?.[0]?.count?.value) || 0;
        }

        res.json({ success: true, message: 'Deleted observation triples', triplesDeleted, chunksProcessed });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete observation links - Query 08
app.post('/api/cubes/delete-observation-links', requireDestructiveAccess, async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, cubeUri, username, password, type, backupId } = req.body;

        // Require a valid backup that covers this specific cube before allowing deletion
        if (!backupId) {
            return res.status(400).json({ error: 'backupId is required. A backup must be created before deletion.' });
        }
        validateBackupId(backupId);
        const backupZipPath = path.join(BACKUP_DIR, `backup_${backupId}.zip`);
        if (!fs.existsSync(backupZipPath)) {
            return res.status(400).json({ error: 'No backup found with the provided backupId. Create a backup first.' });
        }
        const safeGraphUri = validateUriParam(graphUri, 'graphUri');
        const safeCubeUri = validateUriParam(cubeUri, 'cubeUri');
        validateBackupCoversUri(backupZipPath, safeCubeUri);
        const base = endpoint || baseUrl;
        validateEndpointUrl(base);
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });

        // Construct triplestore-specific endpoints
        let queryEndpoint, updateEndpoint;
        if (triplestoreType === 'graphdb') {
            queryEndpoint = db ? `${base}/repositories/${db}` : base;
            updateEndpoint = db ? `${base}/repositories/${db}/statements` : `${base}/statements`;
        } else {
            queryEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
            updateEndpoint = db ? `${base}/${db}/update` : `${base}/update`;
        }
        const auth = { username, password };

        // Count links before deletion
        const countQuery = `
            PREFIX cube: <https://cube.link/>
            SELECT (COUNT(*) AS ?count)
            WHERE {
                GRAPH <${safeGraphUri}> {
                    <${safeCubeUri}> cube:observationSet ?obsSet .
                    ?obsSet cube:observation ?obs .
                }
            }
        `;
        const countResult = await executeSparqlSelect(queryEndpoint, countQuery, auth);
        const triplesDeleted = parseInt(countResult.results?.bindings?.[0]?.count?.value) || 0;

        const query = `
            PREFIX cube: <https://cube.link/>

            DELETE {
                GRAPH <${safeGraphUri}> {
                    ?obsSet cube:observation ?obs .
                }
            }
            WHERE {
                GRAPH <${safeGraphUri}> {
                    <${safeCubeUri}> cube:observationSet ?obsSet .
                    ?obsSet cube:observation ?obs .
                }
            }
        `;

        await executeSparqlUpdate(updateEndpoint, query, auth);
        res.json({ success: true, message: 'Deleted observation links', triplesDeleted });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete cube metadata - Query 09
app.post('/api/cubes/delete-metadata', requireDestructiveAccess, async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, cubeUri, username, password, type, backupId } = req.body;

        // Require a valid backup before allowing deletion
        if (!backupId) {
            return res.status(400).json({ error: 'backupId is required. A backup must be created before deletion.' });
        }
        validateBackupId(backupId);
        const backupZipPath = path.join(BACKUP_DIR, `backup_${backupId}.zip`);
        if (!fs.existsSync(backupZipPath)) {
            return res.status(400).json({ error: 'No backup found with the provided backupId. Create a backup first.' });
        }
        const safeGraphUri = validateUriParam(graphUri, 'graphUri');
        const safeCubeUri = validateUriParam(cubeUri, 'cubeUri');
        validateBackupCoversUri(backupZipPath, safeCubeUri);
        const base = endpoint || baseUrl;
        validateEndpointUrl(base);
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });

        // Construct triplestore-specific endpoints
        let queryEndpoint, updateEndpoint;
        if (triplestoreType === 'graphdb') {
            queryEndpoint = db ? `${base}/repositories/${db}` : base;
            updateEndpoint = db ? `${base}/repositories/${db}/statements` : `${base}/statements`;
        } else {
            queryEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
            updateEndpoint = db ? `${base}/${db}/update` : `${base}/update`;
        }
        const auth = { username, password };

        // Count metadata triples before deletion
        const countQuery = `
            PREFIX cube: <https://cube.link/>
            PREFIX sh: <http://www.w3.org/ns/shacl#>
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
            SELECT (COUNT(*) AS ?count)
            WHERE {
                GRAPH <${safeGraphUri}> {
                    {
                        <${safeCubeUri}> ?p ?o .
                    }
                    UNION
                    {
                        <${safeCubeUri}> ?p1 ?bn .
                        FILTER(isBlank(?bn))
                        ?bn ?p ?o .
                    }
                    UNION
                    {
                        <${safeCubeUri}> cube:observationConstraint ?shape .
                        ?shape ?p ?o .
                    }
                    UNION
                    {
                        <${safeCubeUri}> cube:observationConstraint ?shape .
                        ?shape sh:property ?propShape .
                        ?propShape ?p ?o .
                    }
                    UNION
                    {
                        <${safeCubeUri}> cube:observationConstraint ?shape .
                        ?shape sh:property ?propShape .
                        ?propShape sh:in ?list .
                        ?list rdf:rest*/rdf:first ?item .
                        ?list ?p ?o .
                    }
                    UNION
                    {
                        <${safeCubeUri}> cube:observationSet ?obsSet .
                        ?obsSet ?p ?o .
                    }
                }
            }
        `;
        const countResult = await executeSparqlSelect(queryEndpoint, countQuery, auth);
        const triplesDeleted = parseInt(countResult.results?.bindings?.[0]?.count?.value) || 0;

        const query = `
            PREFIX cube: <https://cube.link/>
            PREFIX sh: <http://www.w3.org/ns/shacl#>
            PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

            DELETE {
                GRAPH <${safeGraphUri}> {
                    ?s ?p ?o .
                }
            }
            WHERE {
                GRAPH <${safeGraphUri}> {
                    {
                        # Cube direct properties
                        <${safeCubeUri}> ?p ?o .
                        BIND(<${safeCubeUri}> AS ?s)
                    }
                    UNION
                    {
                        # Blank node properties
                        <${safeCubeUri}> ?p1 ?bn .
                        FILTER(isBlank(?bn))
                        ?bn ?p ?o .
                        BIND(?bn AS ?s)
                    }
                    UNION
                    {
                        # Observation constraint shape
                        <${safeCubeUri}> cube:observationConstraint ?shape .
                        ?shape ?p ?o .
                        BIND(?shape AS ?s)
                    }
                    UNION
                    {
                        # Property shapes
                        <${safeCubeUri}> cube:observationConstraint ?shape .
                        ?shape sh:property ?propShape .
                        ?propShape ?p ?o .
                        BIND(?propShape AS ?s)
                    }
                    UNION
                    {
                        # RDF list items
                        <${safeCubeUri}> cube:observationConstraint ?shape .
                        ?shape sh:property ?propShape .
                        ?propShape sh:in ?list .
                        ?list rdf:rest*/rdf:first ?item .
                        ?list ?p ?o .
                        BIND(?list AS ?s)
                    }
                    UNION
                    {
                        # Observation set
                        <${safeCubeUri}> cube:observationSet ?obsSet .
                        ?obsSet ?p ?o .
                        BIND(?obsSet AS ?s)
                    }
                }
            }
        `;

        await executeSparqlUpdate(updateEndpoint, query, auth);
        res.json({ success: true, message: 'Deleted cube metadata and shapes', triplesDeleted });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Count remaining observations for a cube
app.post('/api/cubes/count-observations', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, graphUri, cubeUri, username, password } = req.body;

        // Validate URI parameters to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        validateUriParam(cubeUri, 'cubeUri');
        const base = endpoint || baseUrl;
        const sparqlEndpoint = dataset ? `${base}/${dataset}/query` : base;
        const auth = { username, password };

        const query = `
            PREFIX cube: <https://cube.link/>

            SELECT (COUNT(*) AS ?count)
            WHERE {
                GRAPH <${graphUri}> {
                    <${cubeUri}> cube:observationSet ?obsSet .
                    ?obsSet cube:observation ?obs .
                    ?obs ?p ?o .
                }
            }
        `;

        const result = await executeSparqlSelect(sparqlEndpoint, query, auth);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Count total triples in a graph
app.post('/api/cubes/count-triples', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, graphUri, username, password } = req.body;

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        const base = endpoint || baseUrl;
        const sparqlEndpoint = dataset ? `${base}/${dataset}/query` : base;
        const auth = { username, password };

        const query = `
            SELECT (COUNT(*) AS ?count)
            WHERE {
                GRAPH <${graphUri}> { ?s ?p ?o }
            }
        `;

        const result = await executeSparqlSelect(sparqlEndpoint, query, auth);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create Fuseki dataset (legacy endpoint, use /api/triplestore/create-dataset instead)
app.post('/api/fuseki/create-dataset', async (req, res) => {
    try {
        const { endpoint, datasetName } = req.body;

        // Validate endpoint to prevent SSRF
        if (!endpoint || !endpoint.startsWith('http://localhost')) {
            return res.status(400).json({ error: 'endpoint must be a localhost URL' });
        }

        const response = await fetch(`${endpoint}/$/datasets`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `dbName=${encodeURIComponent(datasetName)}&dbType=tdb2`
        });

        if (!response.ok && response.status !== 409) { // 409 means already exists
            const text = await response.text();
            throw new Error(`Failed to create dataset: ${response.status} - ${text}`);
        }

        res.json({ success: true, dataset: datasetName });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Generic create dataset/repository endpoint for all triplestore types
app.post('/api/triplestore/create-dataset', async (req, res) => {
    try {
        const { type, baseUrl, dataset, database, repository, username, password } = req.body;
        const triplestoreType = type || 'fuseki';
        const authHeaders = buildAuthHeaders(username, password);

        switch (triplestoreType) {
            case 'fuseki': {
                const datasetName = dataset || 'lindas';
                const endpoint = baseUrl || 'http://localhost:3030';

                const response = await fetch(`${endpoint}/$/datasets`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        ...authHeaders
                    },
                    body: `dbName=${encodeURIComponent(datasetName)}&dbType=tdb2`
                });

                if (!response.ok && response.status !== 409) { // 409 means already exists
                    const text = await response.text();
                    throw new Error(`Failed to create dataset: ${response.status} - ${text}`);
                }

                res.json({ success: true, dataset: datasetName, type: 'fuseki' });
                break;
            }

            case 'graphdb': {
                const repoName = repository || 'test';
                const endpoint = baseUrl || 'http://localhost:7200';

                // GraphDB requires a JSON payload to create a repository
                const repoConfig = {
                    id: repoName,
                    title: repoName,
                    type: 'graphdb:FreeSailRepository',
                    params: {
                        'base-URL': { value: 'http://example.org', type: 'string' },
                        'repository-type': { value: 'file-repository', type: 'string' },
                        'ruleset': { value: 'rdfsplus-optimized', type: 'string' },
                        'storage-folder': { value: '', type: 'string' },
                        'enable-context-index': { value: 'false', type: 'boolean' },
                        'enablePredicateList': { value: 'true', type: 'boolean' },
                        'enable-fts-index': { value: 'false', type: 'boolean' },
                        'fts-indexes': { value: '', type: 'string' },
                        'fts-string-literals-only': { value: 'true', type: 'boolean' },
                        'fts-default-analyzer': { value: 'standard', type: 'string' },
                        'check-for-inconsistencies': { value: 'false', type: 'boolean' },
                        'disable-sameAs': { value: 'true', type: 'boolean' },
                        'query-timeout': { value: '0', type: 'number' },
                        'query-limit-results': { value: '0', type: 'number' },
                        'throw-QueryEvaluationException-on-timeout': { value: 'false', type: 'boolean' },
                        'read-only': { value: 'false', type: 'boolean' }
                    }
                };

                const response = await fetch(`${endpoint}/rest/repositories`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...authHeaders
                    },
                    body: JSON.stringify(repoConfig)
                });

                if (!response.ok && response.status !== 409) { // 409 means already exists
                    const text = await response.text();
                    // Try to parse GraphDB error message
                    let errorMsg = `Failed to create repository: ${response.status}`;
                    try {
                        const errorData = JSON.parse(text);
                        errorMsg = errorData.message || errorData.error || text || errorMsg;
                    } catch (e) {
                        errorMsg = text || errorMsg;
                    }
                    throw new Error(errorMsg);
                }

                res.json({ success: true, repository: repoName, type: 'graphdb' });
                break;
            }

            case 'stardog': {
                const dbName = database || 'lindas';
                const endpoint = baseUrl || 'http://localhost:5820';

                // Stardog uses the stardog.js library
                const conn = new stardog.Connection({
                    username: username || 'admin',
                    password: password || 'admin',
                    endpoint: endpoint
                });

                try {
                    // Check if database already exists
                    const dbListResult = await stardog.db.list(conn);
                    if (dbListResult.ok && dbListResult.body.databases && dbListResult.body.databases.includes(dbName)) {
                        res.json({ success: true, database: dbName, type: 'stardog', message: 'Database already exists' });
                        return;
                    }

                    // Create the database
                    const createResult = await stardog.db.create(conn, dbName, {
                        database: {
                            name: dbName
                        }
                    });

                    if (createResult.ok) {
                        res.json({ success: true, database: dbName, type: 'stardog' });
                    } else {
                        throw new Error(`Failed to create database: ${createResult.statusText || createResult.status}`);
                    }
                } catch (err) {
                    throw new Error(`Stardog error: ${err.message}`);
                }
                break;
            }

            default:
                res.status(400).json({ error: `Unknown triplestore type: ${triplestoreType}` });
        }
    } catch (error) {
        console.error('Create dataset error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ========== QUERY EDITOR API ==========

// List all graphs in triplestore (for Query Editor dropdown)
app.post('/api/query/graphs', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, username, password, type } = req.body;
        // Support both endpoint/baseUrl and dataset/database/repository field names
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });

        // Construct triplestore-specific endpoint
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }

        const query = `
            SELECT DISTINCT ?graph (COUNT(*) as ?tripleCount)
            WHERE {
                GRAPH ?graph { ?s ?p ?o }
            }
            GROUP BY ?graph
            ORDER BY DESC(?tripleCount)
            LIMIT 100
        `;

        const result = await executeSparqlSelect(sparqlEndpoint, query, { username, password });
        // Extract graph URIs from results
        const bindings = result.results?.bindings || [];
        const graphs = bindings.map(b => b.graph?.value).filter(Boolean);
        res.json({ graphs });
    } catch (error) {
        console.error('Error fetching graphs:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// List all cubes in a graph (for Query Editor dropdown)
app.post('/api/query/cubes', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, username, password, type } = req.body;

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        // Support both endpoint/baseUrl and dataset/database/repository field names
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });

        // Construct triplestore-specific endpoint
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }

        const query = `
            PREFIX cube: <https://cube.link/>
            PREFIX schema: <http://schema.org/>
            PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>

            SELECT DISTINCT ?cube ?title ?version ?dateCreated
            WHERE {
                GRAPH <${graphUri}> {
                    ?cube a cube:Cube .
                    OPTIONAL { ?cube schema:name ?title . FILTER(lang(?title) = "en" || lang(?title) = "de" || lang(?title) = "") }
                    OPTIONAL { ?cube schema:dateCreated ?dateCreated }

                    # Extract version number from URI
                    BIND(REPLACE(STR(?cube), "^.*/([0-9]+)/?$", "$1") AS ?versionStr)
                    BIND(IF(REGEX(STR(?cube), "^.*/[0-9]+/?$"), xsd:integer(?versionStr), 0) AS ?version)
                }
            }
            ORDER BY ?cube DESC(?version)
            LIMIT 200
        `;

        const result = await executeSparqlSelect(sparqlEndpoint, query, { username, password });
        // Extract cube URIs from results and deduplicate
        const bindings = result.results?.bindings || [];
        const cubes = [...new Set(bindings.map(b => b.cube?.value).filter(Boolean))];
        res.json({ cubes });
    } catch (error) {
        console.error('Error fetching cubes:', error.message);
        res.status(500).json({ error: error.message });
    }
});

// Execute raw SPARQL query (SELECT or UPDATE)
app.post('/api/query/execute', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, query, queryType, username, password, triplestoreType } = req.body;
        // Support all field naming conventions: dataset (Fuseki), database (Stardog), repository (GraphDB)
        const base = endpoint || baseUrl;
        const type = triplestoreType || 'fuseki';
        const db = resolveDbName({ type, dataset, database, repository });
        const auth = { username, password };

        if (!query || !query.trim()) {
            return res.status(400).json({ error: 'Query is required' });
        }

        // Block UPDATE queries unless destructive API is enabled and auth token is valid
        if (queryType === 'update') {
            if (!ENABLE_DESTRUCTIVE_API) {
                return res.status(403).json({
                    error: 'SPARQL UPDATE queries are disabled',
                    detail: 'Set ENABLE_DESTRUCTIVE_API=true environment variable to enable update operations'
                });
            }
            if (API_AUTH_TOKEN) {
                const authHeader = req.headers.authorization;
                if (!authHeader || authHeader !== `Bearer ${API_AUTH_TOKEN}`) {
                    return res.status(401).json({
                        error: 'Authentication required for UPDATE queries',
                        detail: 'Provide a valid Bearer token in the Authorization header'
                    });
                }
            }
        }

        const startTime = Date.now();

        // Construct triplestore-specific endpoint paths
        let sparqlEndpoint, updateEndpoint;
        if (type === 'graphdb') {
            // GraphDB uses /repositories/{repo} for queries and /repositories/{repo}/statements for updates
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
            updateEndpoint = db ? `${base}/repositories/${db}/statements` : `${base}/statements`;
        } else {
            // Fuseki and Stardog use /{db}/query and /{db}/update
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
            updateEndpoint = db ? `${base}/${db}/update` : `${base}/update`;
        }

        if (queryType === 'update') {
            // Execute UPDATE query
            await executeSparqlUpdate(updateEndpoint, query, auth);
            const duration = Date.now() - startTime;

            res.json({
                success: true,
                queryType: 'update',
                message: 'Update query executed successfully',
                duration
            });
        } else {
            // Execute SELECT query
            const result = await executeSparqlSelect(sparqlEndpoint, query, auth);
            const duration = Date.now() - startTime;

            res.json({
                success: true,
                queryType: 'select',
                results: result.results,
                head: result.head,
                duration,
                rowCount: result.results.bindings.length
            });
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// ========== BACKUP AND RESTORE API ==========

// Clean up old backups (older than BACKUP_RETENTION_DAYS)
function cleanupOldBackups() {
    const now = Date.now();
    const maxAge = BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000;

    try {
        const files = fs.readdirSync(BACKUP_DIR);

        // Clean up old ZIP files (self-contained backups)
        for (const file of files) {
            if (file.endsWith('.zip') && file.startsWith('backup_')) {
                const filePath = path.join(BACKUP_DIR, file);
                const stats = fs.statSync(filePath);
                if (now - stats.mtimeMs > maxAge) {
                    fs.unlinkSync(filePath);
                    console.log(`Cleaned up old backup: ${file}`);
                }
            }
        }

        // Also clean up any legacy .json and .nt files (older than maxAge)
        for (const file of files) {
            if ((file.endsWith('.json') || file.endsWith('.nt')) && !file.startsWith('temp_')) {
                const filePath = path.join(BACKUP_DIR, file);
                const stats = fs.statSync(filePath);
                if (now - stats.mtimeMs > maxAge) {
                    fs.unlinkSync(filePath);
                    console.log(`Cleaned up legacy backup file: ${file}`);
                }
            }
        }
    } catch (error) {
        console.error('Error cleaning up old backups:', error);
    }
}

// Run cleanup on startup and every hour
cleanupOldBackups();
setInterval(cleanupOldBackups, 60 * 60 * 1000);

// Create backup before deletion (requires auth to prevent data exfiltration)
app.post('/api/backup/create', requireDestructiveAccess, async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, cubeUri, username, password, type, includeMetadata, includeOrphans } = req.body;

        // Validate URI parameters to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        validateUriParam(cubeUri, 'cubeUri');
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });
        const auth = { username, password };
        const shouldIncludeMetadata = includeMetadata !== false; // Default to true
        const shouldIncludeOrphans = includeOrphans !== false; // Default to true

        // Construct triplestore-specific query endpoint
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }

        // Build query based on includeMetadata flag
        let query;
        if (shouldIncludeMetadata) {
            // Full query with metadata (cube properties, SHACL shapes, etc.)
            query = `
                PREFIX cube: <https://cube.link/>
                PREFIX sh: <http://www.w3.org/ns/shacl#>
                PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

                CONSTRUCT {
                    ?s ?p ?o .
                }
                WHERE {
                    GRAPH <${graphUri}> {
                        {
                            # Cube direct properties (metadata)
                            <${cubeUri}> ?p ?o .
                            BIND(<${cubeUri}> AS ?s)
                        }
                        UNION
                        {
                            # Blank node properties attached to cube (metadata)
                            <${cubeUri}> ?p1 ?bn .
                            FILTER(isBlank(?bn))
                            ?bn ?p ?o .
                            BIND(?bn AS ?s)
                        }
                        UNION
                        {
                            # SHACL NodeShape (observationConstraint - metadata)
                            <${cubeUri}> cube:observationConstraint ?shape .
                            ?shape ?p ?o .
                            BIND(?shape AS ?s)
                        }
                        UNION
                        {
                            # SHACL PropertyShapes (metadata)
                            <${cubeUri}> cube:observationConstraint ?shape .
                            ?shape sh:property ?propShape .
                            ?propShape ?p ?o .
                            BIND(?propShape AS ?s)
                        }
                        UNION
                        {
                            # RDF Lists in property shapes (sh:in values - metadata)
                            <${cubeUri}> cube:observationConstraint ?shape .
                            ?shape sh:property ?propShape .
                            ?propShape sh:in ?list .
                            ?list rdf:rest*/rdf:first ?item .
                            ?list ?p ?o .
                            BIND(?list AS ?s)
                        }
                        UNION
                        {
                            # Observation set (links cube to observations)
                            <${cubeUri}> cube:observationSet ?obsSet .
                            ?obsSet ?p ?o .
                            BIND(?obsSet AS ?s)
                        }
                        UNION
                        {
                            # Observations (the actual data)
                            <${cubeUri}> cube:observationSet ?obsSet .
                            ?obsSet cube:observation ?obs .
                            ?obs ?p ?o .
                            BIND(?obs AS ?s)
                        }
                    }
                }
            `;
        } else {
            // Observations-only query (no metadata)
            query = `
                PREFIX cube: <https://cube.link/>

                CONSTRUCT {
                    ?s ?p ?o .
                }
                WHERE {
                    GRAPH <${graphUri}> {
                        {
                            # Observation set only (needed to link observations back to cube)
                            <${cubeUri}> cube:observationSet ?obsSet .
                            ?obsSet ?p ?o .
                            BIND(?obsSet AS ?s)
                        }
                        UNION
                        {
                            # Observations only (the actual data)
                            <${cubeUri}> cube:observationSet ?obsSet .
                            ?obsSet cube:observation ?obs .
                            ?obs ?p ?o .
                            BIND(?obs AS ?s)
                        }
                    }
                }
            `;
        }

        const headers = {
            'Accept': 'application/n-triples',
            'Content-Type': 'application/x-www-form-urlencoded',
            ...buildAuthHeaders(auth.username, auth.password)
        };

        const response = await fetch(sparqlEndpoint, {
            method: 'POST',
            headers: headers,
            body: `query=${encodeURIComponent(query)}`
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Backup query failed: ${response.status} - ${text}`);
        }

        const triples = await response.text();
        const tripleCount = triples.split('\n').filter(line => line.trim()).length;

        // Fetch orphan triples if requested
        let orphanTriples = '';
        let orphanStats = { totalCount: 0, types: {} };
        if (shouldIncludeOrphans) {
            try {
                // Get orphan summary first
                const summaryQuery = findOrphansSummaryQuery(graphUri);
                const summaryResult = await executeSparqlSelect(sparqlEndpoint, summaryQuery, auth);
                const bindings = summaryResult.results?.bindings || [];
                
                bindings.forEach(binding => {
                    const type = binding.orphanType?.value;
                    const count = parseInt(binding.count?.value) || 0;
                    if (type) {
                        orphanStats.types[type] = count;
                        orphanStats.totalCount += count;
                    }
                });

                // Get orphan triples if any exist
                if (orphanStats.totalCount > 0) {
                    const orphanObsQuery = constructOrphanObservationSetsQuery(graphUri);
                    const orphanShapesQuery = constructOrphanShapesQuery(graphUri);
                    
                    const [obsResult, shapesResult] = await Promise.all([
                        executeSparqlConstruct(sparqlEndpoint, orphanObsQuery, auth),
                        executeSparqlConstruct(sparqlEndpoint, orphanShapesQuery, auth)
                    ]);
                    
                    orphanTriples = [obsResult, shapesResult].filter(t => t.trim()).join('\n');
                }
            } catch (orphanError) {
                console.warn('Failed to fetch orphan triples:', orphanError.message);
                // Continue without orphans
            }
        }

        // Generate backup metadata
        const metadata = {
            cubeUri: cubeUri,
            graphUri: graphUri,
            endpoint: base,
            dataset: db,
            type: triplestoreType,
            tripleCount: tripleCount,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString()
        };

        // Create self-contained ZIP backup (manifest inside ZIP) with orphan options
        const zipOptions = {
            includeMetadata: shouldIncludeMetadata,
            includeOrphans: shouldIncludeOrphans && orphanTriples.length > 0,
            orphanTriples: orphanTriples,
            orphanStats: orphanStats
        };
        const zipInfo = await createZipBackup(triples, metadata, zipOptions);

        res.json({
            success: true,
            backupId: zipInfo.backupId,
            tripleCount: tripleCount,
            orphanCount: orphanStats.totalCount,
            includesMetadata: shouldIncludeMetadata,
            includesOrphans: shouldIncludeOrphans && orphanTriples.length > 0,
            expiresAt: metadata.expiresAt,
            zipFilename: zipInfo.zipFilename,
            zipFileSize: zipInfo.compressedSize
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Create a consolidated backup for MULTIPLE cubes (all in ONE ZIP file)
// Used before batch deletion to create a single restorable backup (requires auth)
app.post('/api/backup/create-multi', requireDestructiveAccess, async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, cubeUris, username, password, type, includeMetadata, includeOrphans } = req.body;

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        // Validate all cube URIs
        if (cubeUris && Array.isArray(cubeUris)) {
            cubeUris.forEach((uri, index) => validateUriParam(uri, `cubeUris[${index}]`));
        }
        const shouldIncludeMetadata = includeMetadata !== false; // Default to true
        const shouldIncludeOrphans = includeOrphans !== false; // Default to true
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });
        const auth = { username, password };

        if (!cubeUris || !Array.isArray(cubeUris) || cubeUris.length === 0) {
            return res.status(400).json({ error: 'cubeUris must be a non-empty array' });
        }

        // Construct triplestore-specific query endpoint
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }

        const headers = {
            'Accept': 'application/n-triples',
            'Content-Type': 'application/x-www-form-urlencoded',
            ...buildAuthHeaders(auth.username, auth.password)
        };

        // Fetch triples for all cubes - track failures explicitly
        const cubesData = [];
        const failedCubes = [];
        let totalTripleCount = 0;

        for (const cubeUri of cubeUris) {
            // Build query based on includeMetadata flag
            let query;
            if (shouldIncludeMetadata) {
                // Full query with metadata (cube properties, SHACL shapes, etc.)
                query = `
                    PREFIX cube: <https://cube.link/>
                    PREFIX sh: <http://www.w3.org/ns/shacl#>
                    PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>

                    CONSTRUCT {
                        ?s ?p ?o .
                    }
                    WHERE {
                        GRAPH <${graphUri}> {
                            {
                                # Cube direct properties (metadata)
                                <${cubeUri}> ?p ?o .
                                BIND(<${cubeUri}> AS ?s)
                            }
                            UNION
                            {
                                # Blank node properties attached to cube (metadata)
                                <${cubeUri}> ?p1 ?bn .
                                FILTER(isBlank(?bn))
                                ?bn ?p ?o .
                                BIND(?bn AS ?s)
                            }
                            UNION
                            {
                                # SHACL NodeShape (observationConstraint - metadata)
                                <${cubeUri}> cube:observationConstraint ?shape .
                                ?shape ?p ?o .
                                BIND(?shape AS ?s)
                            }
                            UNION
                            {
                                # SHACL PropertyShapes (metadata)
                                <${cubeUri}> cube:observationConstraint ?shape .
                                ?shape sh:property ?propShape .
                                ?propShape ?p ?o .
                                BIND(?propShape AS ?s)
                            }
                            UNION
                            {
                                # RDF Lists in property shapes (sh:in values - metadata)
                                <${cubeUri}> cube:observationConstraint ?shape .
                                ?shape sh:property ?propShape .
                                ?propShape sh:in ?list .
                                ?list rdf:rest*/rdf:first ?item .
                                ?list ?p ?o .
                                BIND(?list AS ?s)
                            }
                            UNION
                            {
                                # Observation set (links cube to observations)
                                <${cubeUri}> cube:observationSet ?obsSet .
                                ?obsSet ?p ?o .
                                BIND(?obsSet AS ?s)
                            }
                            UNION
                            {
                                # Observations (the actual data)
                                <${cubeUri}> cube:observationSet ?obsSet .
                                ?obsSet cube:observation ?obs .
                                ?obs ?p ?o .
                                BIND(?obs AS ?s)
                            }
                        }
                    }
                `;
            } else {
                // Observations-only query (no metadata)
                query = `
                    PREFIX cube: <https://cube.link/>

                    CONSTRUCT {
                        ?s ?p ?o .
                    }
                    WHERE {
                        GRAPH <${graphUri}> {
                            {
                                # Observation set only (needed to link observations back to cube)
                                <${cubeUri}> cube:observationSet ?obsSet .
                                ?obsSet ?p ?o .
                                BIND(?obsSet AS ?s)
                            }
                            UNION
                            {
                                # Observations only (the actual data)
                                <${cubeUri}> cube:observationSet ?obsSet .
                                ?obsSet cube:observation ?obs .
                                ?obs ?p ?o .
                                BIND(?obs AS ?s)
                            }
                        }
                    }
                `;
            }

            const response = await fetch(sparqlEndpoint, {
                method: 'POST',
                headers: headers,
                body: `query=${encodeURIComponent(query)}`
            });

            if (!response.ok) {
                const text = await response.text();
                console.error(`Backup query failed for ${cubeUri}: ${response.status} - ${text}`);
                failedCubes.push(cubeUri);
                continue; // Skip this cube but continue with others
            }

            // Use arrayBuffer -> Buffer to avoid the V8 ~512MB string length limit
            // when backing up many large cubes at once
            const tripleBuf = Buffer.from(await response.arrayBuffer());
            let tripleCount = 0;
            for (let i = 0; i < tripleBuf.length; i++) {
                if (tripleBuf[i] === 0x0A) tripleCount++; // count newline bytes
            }
            totalTripleCount += tripleCount;

            cubesData.push({
                cubeUri: cubeUri,
                triples: tripleBuf,
                tripleCount: tripleCount
            });
        }

        if (cubesData.length === 0) {
            return res.status(500).json({ error: 'Failed to backup any cubes' });
        }

        // Fetch orphan triples if requested
        let orphanTriples = '';
        let orphanStats = { totalCount: 0, types: {} };
        if (shouldIncludeOrphans) {
            try {
                // Get orphan summary first
                const summaryQuery = findOrphansSummaryQuery(graphUri);
                const summaryResult = await executeSparqlSelect(sparqlEndpoint, summaryQuery, auth);
                const bindings = summaryResult.results?.bindings || [];
                
                bindings.forEach(binding => {
                    const type = binding.orphanType?.value;
                    const count = parseInt(binding.count?.value) || 0;
                    if (type) {
                        orphanStats.types[type] = count;
                        orphanStats.totalCount += count;
                    }
                });

                // Get orphan triples if any exist
                if (orphanStats.totalCount > 0) {
                    const orphanObsQuery = constructOrphanObservationSetsQuery(graphUri);
                    const orphanShapesQuery = constructOrphanShapesQuery(graphUri);
                    
                    const [obsResult, shapesResult] = await Promise.all([
                        executeSparqlConstruct(sparqlEndpoint, orphanObsQuery, auth),
                        executeSparqlConstruct(sparqlEndpoint, orphanShapesQuery, auth)
                    ]);
                    
                    orphanTriples = [obsResult, shapesResult].filter(t => t.trim()).join('\n');
                }
            } catch (orphanError) {
                console.warn('Failed to fetch orphan triples:', orphanError.message);
                // Continue without orphans
            }
        }

        // Generate backup metadata
        const metadata = {
            graphUri: graphUri,
            endpoint: base,
            dataset: db,
            type: triplestoreType,
            tripleCount: totalTripleCount,
            createdAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString(),
            deletionContext: {
                reason: 'Pre-deletion backup of multiple cube versions',
                cubeCount: cubesData.length,
                deletedAt: new Date().toISOString(),
                includeMetadata: shouldIncludeMetadata,
                includeOrphans: shouldIncludeOrphans
            }
        };

        // Create consolidated ZIP backup with all cubes and orphans
        const zipOptions = {
            includeMetadata: shouldIncludeMetadata,
            includeOrphans: shouldIncludeOrphans && orphanTriples.length > 0,
            orphanTriples: orphanTriples,
            orphanStats: orphanStats
        };
        const zipInfo = await createZipBackup(cubesData, metadata, zipOptions);

        const responseStatus = failedCubes.length > 0 ? 207 : 200;
        res.status(responseStatus).json({
            success: failedCubes.length === 0,
            partial: failedCubes.length > 0,
            backupId: zipInfo.backupId,
            cubeCount: cubesData.length,
            totalTripleCount: totalTripleCount,
            orphanCount: orphanStats.totalCount,
            includesMetadata: shouldIncludeMetadata,
            includesOrphans: shouldIncludeOrphans && orphanTriples.length > 0,
            expiresAt: metadata.expiresAt,
            zipFilename: zipInfo.zipFilename,
            zipFileSize: zipInfo.compressedSize,
            cubesBackedUp: cubesData.map(c => ({ uri: c.cubeUri, tripleCount: c.tripleCount })),
            cubesNotBackedUp: failedCubes
        });
    } catch (error) {
        console.error('Multi-cube backup error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Orphan detection endpoint - includes both general orphan summary and shape-specific counts
app.post('/api/orphans/detect', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, username, password, type } = req.body;

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });
        const auth = { username, password };

        // Construct triplestore-specific query endpoint
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }

        // Run both the general summary and shape-specific count in parallel
        const summaryQuery = findOrphansSummaryQuery(graphUri);
        const shapeCountQuery = countOrphanShapesQuery(graphUri);

        const [summaryResult, shapeCountResult] = await Promise.all([
            executeSparqlSelect(sparqlEndpoint, summaryQuery, auth),
            executeSparqlSelect(sparqlEndpoint, shapeCountQuery, auth)
        ]);

        // Parse general orphan summary
        const bindings = summaryResult.results?.bindings || [];
        const summary = {};
        let totalCount = 0;

        bindings.forEach(binding => {
            const type = binding.orphanType?.value;
            const count = parseInt(binding.count?.value) || 0;
            if (type) {
                summary[type] = count;
                totalCount += count;
            }
        });

        // Parse orphan shape-specific counts (query 14 results)
        const shapeBindings = shapeCountResult.results?.bindings || [];
        let orphanShapeCount = 0;
        let orphanShapeTriples = 0;
        if (shapeBindings.length > 0) {
            orphanShapeCount = parseInt(shapeBindings[0].orphanShapeCount?.value) || 0;
            orphanShapeTriples = parseInt(shapeBindings[0].totalOrphanTriples?.value) || 0;
        }

        res.json({
            success: true,
            totalCount: totalCount,
            summary: summary,
            graphUri: graphUri,
            // Shape-specific details from query 14
            shapes: {
                orphanShapeCount: orphanShapeCount,
                orphanShapeTriples: orphanShapeTriples
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Orphan shapes count endpoint - returns precise shape and triple counts (query 14)
app.post('/api/orphans/shapes/count', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, username, password, type } = req.body;

        validateUriParam(graphUri, 'graphUri');
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });
        const auth = { username, password };

        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }

        const query = countOrphanShapesQuery(graphUri);
        const result = await executeSparqlSelect(sparqlEndpoint, query, auth);

        const bindings = result.results?.bindings || [];
        let orphanShapeCount = 0;
        let totalOrphanTriples = 0;
        if (bindings.length > 0) {
            orphanShapeCount = parseInt(bindings[0].orphanShapeCount?.value) || 0;
            totalOrphanTriples = parseInt(bindings[0].totalOrphanTriples?.value) || 0;
        }

        res.json({
            success: true,
            orphanShapeCount: orphanShapeCount,
            totalOrphanTriples: totalOrphanTriples,
            graphUri: graphUri
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Orphan shapes list endpoint - returns individual orphan shapes with details (query 11)
app.post('/api/orphans/shapes/list', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, username, password, type } = req.body;

        validateUriParam(graphUri, 'graphUri');
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });
        const auth = { username, password };

        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }

        const query = findOrphanShapesQuery(graphUri);
        const result = await executeSparqlSelect(sparqlEndpoint, query, auth);

        const bindings = result.results?.bindings || [];
        const shapes = bindings.map(binding => ({
            shape: binding.shape?.value || '',
            shapeType: binding.shapeType?.value || '',
            propertyShapeCount: parseInt(binding.propertyShapeCount?.value) || 0,
            estimatedTriples: parseInt(binding.estimatedTriples?.value) || 0
        }));

        res.json({
            success: true,
            shapes: shapes,
            count: shapes.length,
            graphUri: graphUri
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Orphan shapes preview endpoint - returns CONSTRUCT triples for preview (query 12)
app.post('/api/orphans/shapes/preview', async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, username, password, type } = req.body;

        validateUriParam(graphUri, 'graphUri');
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });
        const auth = { username, password };

        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }

        const query = constructOrphanShapesQuery(graphUri);
        const triples = await executeSparqlConstruct(sparqlEndpoint, query, auth);

        const tripleCount = triples ? triples.split('\n').filter(line => line.trim()).length : 0;

        res.json({
            success: true,
            triples: triples,
            tripleCount: tripleCount,
            graphUri: graphUri
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Orphan cleanup endpoint - deletes orphan observation sets and shapes,
// then verifies cleanup with shape-specific count (query 14)
app.post('/api/orphans/cleanup', requireDestructiveAccess, async (req, res) => {
    try {
        const { endpoint, baseUrl, dataset, database, repository, graphUri, username, password, type } = req.body;

        // Validate URI parameter to prevent SPARQL injection
        validateUriParam(graphUri, 'graphUri');
        const base = endpoint || baseUrl;
        const triplestoreType = type || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository });
        const auth = { username, password };

        // Construct triplestore-specific query endpoint for counting
        let sparqlEndpoint;
        if (triplestoreType === 'graphdb') {
            sparqlEndpoint = db ? `${base}/repositories/${db}` : base;
        } else {
            sparqlEndpoint = db ? `${base}/${db}/query` : `${base}/query`;
        }

        // Construct triplestore-specific update endpoint
        let updateEndpoint;
        if (triplestoreType === 'graphdb') {
            updateEndpoint = db ? `${base}/repositories/${db}/statements` : `${base}/statements`;
        } else {
            updateEndpoint = db ? `${base}/${db}/update` : `${base}/update`;
        }

        // Count orphans before deletion (general summary + shape-specific)
        const countQuery = findOrphansSummaryQuery(graphUri);
        const shapeCountQuery = countOrphanShapesQuery(graphUri);
        const [beforeResult, beforeShapeResult] = await Promise.all([
            executeSparqlSelect(sparqlEndpoint, countQuery, auth),
            executeSparqlSelect(sparqlEndpoint, shapeCountQuery, auth)
        ]);

        const beforeBindings = beforeResult.results?.bindings || [];
        const beforeSummary = {};
        let beforeTotal = 0;
        beforeBindings.forEach(binding => {
            const orphanType = binding.orphanType?.value;
            const count = parseInt(binding.count?.value) || 0;
            if (orphanType) {
                beforeSummary[orphanType] = count;
                beforeTotal += count;
            }
        });

        const beforeShapeBindings = beforeShapeResult.results?.bindings || [];
        let beforeShapeCount = 0;
        let beforeShapeTriples = 0;
        if (beforeShapeBindings.length > 0) {
            beforeShapeCount = parseInt(beforeShapeBindings[0].orphanShapeCount?.value) || 0;
            beforeShapeTriples = parseInt(beforeShapeBindings[0].totalOrphanTriples?.value) || 0;
        }

        // Delete orphan observation sets first
        const obsQuery = deleteOrphanObservationSetsQuery(graphUri);
        await executeSparqlUpdate(updateEndpoint, obsQuery, auth);

        // Delete orphan shapes (comprehensive query matching query 13)
        const shapesQuery = deleteOrphanShapesQuery(graphUri);
        await executeSparqlUpdate(updateEndpoint, shapesQuery, auth);

        // Count orphans after deletion to calculate removed counts and verify
        const [afterResult, afterShapeResult] = await Promise.all([
            executeSparqlSelect(sparqlEndpoint, countQuery, auth),
            executeSparqlSelect(sparqlEndpoint, shapeCountQuery, auth)
        ]);

        const afterBindings = afterResult.results?.bindings || [];
        const afterSummary = {};
        let afterTotal = 0;
        afterBindings.forEach(binding => {
            const orphanType = binding.orphanType?.value;
            const count = parseInt(binding.count?.value) || 0;
            if (orphanType) {
                afterSummary[orphanType] = count;
                afterTotal += count;
            }
        });

        const afterShapeBindings = afterShapeResult.results?.bindings || [];
        let afterShapeCount = 0;
        let afterShapeTriples = 0;
        if (afterShapeBindings.length > 0) {
            afterShapeCount = parseInt(afterShapeBindings[0].orphanShapeCount?.value) || 0;
            afterShapeTriples = parseInt(afterShapeBindings[0].totalOrphanTriples?.value) || 0;
        }

        // Calculate removed counts per type
        const removed = {};
        for (const orphanType of Object.keys(beforeSummary)) {
            removed[orphanType] = (beforeSummary[orphanType] || 0) - (afterSummary[orphanType] || 0);
        }
        const totalRemoved = beforeTotal - afterTotal;

        res.json({
            success: true,
            message: 'Orphan triples cleaned up successfully',
            removed: removed,
            totalRemoved: totalRemoved,
            // Shape-specific verification (should be 0 after successful cleanup)
            verification: {
                remainingOrphanShapes: afterShapeCount,
                remainingOrphanShapeTriples: afterShapeTriples,
                shapesRemoved: beforeShapeCount - afterShapeCount,
                shapeTriplesCleaned: beforeShapeTriples - afterShapeTriples
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Download a backup ZIP file directly
app.get('/api/backup/download/:backupId', (req, res) => {
    try {
        const { backupId } = req.params;

        // Validate backup ID to prevent path traversal
        validateBackupId(backupId);

        const files = fs.readdirSync(BACKUP_DIR);
        const zipFile = files.find(f => f.endsWith('.zip') && f.includes(backupId));

        if (!zipFile) {
            return res.status(404).json({ error: 'Backup not found' });
        }

        const zipPath = path.join(BACKUP_DIR, zipFile);
        res.download(zipPath, zipFile);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// List all backups (reads from self-contained ZIP files)
app.get('/api/backup/list', (req, res) => {
    try {
        cleanupOldBackups(); // Clean up before listing

        const files = fs.readdirSync(BACKUP_DIR);
        const backups = [];

        for (const file of files) {
            // Only process ZIP files (self-contained backups)
            // Files are named: backup_${backupId}.zip
            if (file.endsWith('.zip') && file.startsWith('backup_')) {
                const zipPath = path.join(BACKUP_DIR, file);
                try {
                    // Read manifest from inside ZIP
                    const zip = new AdmZip(zipPath);
                    const manifestEntry = zip.getEntry('manifest.json');
                    if (manifestEntry) {
                        const manifest = JSON.parse(manifestEntry.getData().toString('utf8'));
                        const stats = fs.statSync(zipPath);

                        // Build backup info from manifest
                        const backupInfo = {
                            backupId: manifest.backupId || manifest.stats?.backupId || file.replace('.zip', ''),
                            cubeUri: manifest.cube?.uri || (manifest.cubes && manifest.cubes[0]?.uri) || '',
                            graphUri: manifest.graph?.uri || '',
                            endpoint: manifest.source?.endpoint || '',
                            dataset: manifest.source?.dataset || '',
                            type: manifest.source?.triplestoreType || 'fuseki',
                            tripleCount: manifest.stats?.totalTripleCount || manifest.cube?.tripleCount || 0,
                            createdAt: manifest.createdAt || stats.birthtime.toISOString(),
                            expiresAt: manifest.expiresAt || new Date(stats.birthtime.getTime() + BACKUP_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString(),
                            zipFilename: file,
                            zipFileSize: stats.size,
                            hasZip: true,
                            formatVersion: manifest.formatVersion || '3.0',
                            // Multi-cube support
                            cubes: manifest.cubes || (manifest.cube ? [manifest.cube] : []),
                            cubeCount: manifest.stats?.cubeCount || (manifest.cubes?.length) || 1,
                            // Metadata and orphan flags
                            includesMetadata: manifest.stats?.includesMetadata ?? true,
                            includesOrphans: manifest.stats?.includesOrphans || false,
                            orphanTripleCount: manifest.stats?.orphanTripleCount || manifest.orphans?.tripleCount || 0
                        };

                        backups.push(backupInfo);
                    }
                } catch (zipError) {
                    console.error(`Failed to read backup ${file}:`, zipError.message);
                }
            }
        }

        // Sort by creation date (newest first)
        backups.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        res.json({ backups: backups });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get backup details (reads from self-contained ZIP file)
app.get('/api/backup/:backupId', (req, res) => {
    try {
        const { backupId } = req.params;

        // Validate backup ID to prevent path traversal
        validateBackupId(backupId);

        // Find the ZIP file for this backup
        const files = fs.readdirSync(BACKUP_DIR);
        const zipFile = files.find(f => f.endsWith('.zip') && f.includes(backupId));

        if (!zipFile) {
            return res.status(404).json({ error: 'Backup not found' });
        }

        const zipPath = path.join(BACKUP_DIR, zipFile);
        const zip = new AdmZip(zipPath);
        const manifestEntry = zip.getEntry('manifest.json');

        if (!manifestEntry) {
            return res.status(500).json({ error: 'Invalid backup: missing manifest' });
        }

        const manifest = JSON.parse(manifestEntry.getData().toString('utf8'));
        const stats = fs.statSync(zipPath);

        // Build response with all backup details
        const metadata = {
            backupId: manifest.backupId || backupId,
            cubeUri: manifest.cube?.uri || (manifest.cubes && manifest.cubes[0]?.uri) || '',
            graphUri: manifest.graph?.uri || '',
            endpoint: manifest.source?.endpoint || '',
            dataset: manifest.source?.dataset || '',
            type: manifest.source?.triplestoreType || 'fuseki',
            tripleCount: manifest.stats?.totalTripleCount || manifest.cube?.tripleCount || 0,
            createdAt: manifest.createdAt || stats.birthtime.toISOString(),
            expiresAt: manifest.expiresAt,
            zipFilename: zipFile,
            zipFileSize: stats.size,
            formatVersion: manifest.formatVersion || '3.0',
            cubes: manifest.cubes || (manifest.cube ? [manifest.cube] : []),
            cubeCount: manifest.stats?.cubeCount || 1,
            restore: manifest.restore
        };

        res.json(metadata);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Restore from backup (reads from self-contained ZIP file)
app.post('/api/backup/restore', requireDestructiveAccess, async (req, res) => {
    try {
        const { backupId, endpoint, baseUrl, dataset, database, repository, username, password, type } = req.body;

        // Validate backup ID to prevent path traversal
        validateBackupId(backupId);

        // Find the ZIP file for this backup
        const files = fs.readdirSync(BACKUP_DIR);
        const zipFile = files.find(f => f.endsWith('.zip') && f.includes(backupId));

        if (!zipFile) {
            return res.status(404).json({ error: 'Backup not found' });
        }

        const zipPath = path.join(BACKUP_DIR, zipFile);
        const zip = new AdmZip(zipPath);

        // Read manifest
        const manifestEntry = zip.getEntry('manifest.json');
        if (!manifestEntry) {
            return res.status(500).json({ error: 'Invalid backup: missing manifest' });
        }
        const manifest = JSON.parse(manifestEntry.getData().toString('utf8'));

        // Read triples (support both single and multi-cube formats)
        let triples = '';
        let totalTripleCount = 0;

        if (manifest.cubes && manifest.cubes.length > 0) {
            // Multi-cube format: read all data files
            for (const cube of manifest.cubes) {
                const dataEntry = zip.getEntry(cube.dataFile || 'data.nt');
                if (dataEntry) {
                    triples += dataEntry.getData().toString('utf8') + '\n';
                    totalTripleCount += cube.tripleCount || 0;
                }
            }
        } else {
            // Single cube format
            const dataEntry = zip.getEntry('data.nt');
            if (!dataEntry) {
                return res.status(500).json({ error: 'Invalid backup: missing data file' });
            }
            triples = dataEntry.getData().toString('utf8');
            totalTripleCount = manifest.cube?.tripleCount || manifest.stats?.totalTripleCount || 0;
        }

        // Use provided values or fall back to manifest
        const base = endpoint || baseUrl || manifest.source?.endpoint || '';
        const triplestoreType = type || manifest.source?.triplestoreType || 'fuseki';
        const db = resolveDbName({ type: triplestoreType, dataset, database, repository }) || manifest.source?.dataset || '';
        const graphUri = manifest.graph?.uri || manifest.restore?.targetGraph || '';
        const auth = { username, password };

        // Construct triplestore-specific data endpoint
        let dataEndpoint;
        if (triplestoreType === 'graphdb') {
            dataEndpoint = `${base}/repositories/${db}/statements?context=${encodeURIComponent('<' + graphUri + '>')}`;
        } else if (triplestoreType === 'stardog') {
            dataEndpoint = `${base}/${db}?graph=${encodeURIComponent(graphUri)}`;
        } else {
            dataEndpoint = `${base}/${db}/data?graph=${encodeURIComponent(graphUri)}`;
        }

        const response = await fetch(dataEndpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/n-triples',
                ...buildAuthHeaders(auth.username, auth.password)
            },
            body: triples
        });

        if (!response.ok) {
            const text = await response.text();
            throw new Error(`Restore failed: ${response.status} - ${text}`);
        }

        res.json({
            success: true,
            restoredTriples: totalTripleCount,
            cubeUri: manifest.cube?.uri || (manifest.cubes && manifest.cubes[0]?.uri) || '',
            graphUri: graphUri,
            cubeCount: manifest.cubes?.length || 1
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Export backup as downloadable ZIP file (self-contained with manifest and data)
app.get('/api/backup/:backupId/export', async (req, res) => {
    try {
        const { backupId } = req.params;

        // Validate backup ID to prevent path traversal
        validateBackupId(backupId);

        // Find the ZIP file for this backup
        const files = fs.readdirSync(BACKUP_DIR);
        const zipFile = files.find(f => f.endsWith('.zip') && f.includes(backupId));

        if (!zipFile) {
            return res.status(404).json({ error: 'Backup not found' });
        }

        const zipPath = path.join(BACKUP_DIR, zipFile);

        // Serve the self-contained ZIP file
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${zipFile}"`);
        return fs.createReadStream(zipPath).pipe(res);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Upload and import backup file (supports ZIP and JSON formats, requires auth)
app.post('/api/backup/upload', requireDestructiveAccess, upload.single('file'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        let parsed;
        const isZip = req.file.originalname.endsWith('.zip') ||
                      req.file.mimetype === 'application/zip' ||
                      req.file.mimetype === 'application/x-zip-compressed';

        if (isZip) {
            // Parse ZIP backup file
            parsed = parseZipBackup(req.file.path);
        } else {
            // Parse JSON or N-Triples content
            const content = fs.readFileSync(req.file.path, 'utf8');
            parsed = parseImportPackage(content);
        }

        // Clean up uploaded file
        fs.unlinkSync(req.file.path);

        // Generate a single tempId for both the response and file storage
        const tempId = Date.now().toString();

        // Store in temp storage for import step (using same tempId)
        const tempPath = path.join(EXPORT_DIR, `temp_${tempId}.json`);
        fs.writeFileSync(tempPath, JSON.stringify(parsed));

        // Return parsed content and metadata for user to review before import
        res.json({
            success: true,
            isPackage: parsed.isPackage,
            isZip: parsed.isZip || false,
            packageVersion: parsed.packageVersion,
            metadata: parsed.metadata,
            restore: parsed.restore,
            tripleCount: parsed.triples.split('\n').filter(line => line.trim()).length,
            format: parsed.format,
            // Store triples temporarily for the actual import step
            tempId: tempId
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Import uploaded file to triplestore (supports both temp file and direct ZIP upload)
app.post('/api/backup/import', requireDestructiveAccess, async (req, res) => {
    try {
        const {
            tempId,
            type, mode, baseUrl, dataset, database, repository, username, password,
            graphUri,
            overrideGraph
        } = req.body;

        // Find temp file
        const tempFiles = fs.readdirSync(EXPORT_DIR).filter(f => f.startsWith('temp_'));
        let parsed = null;
        let tempPath = null;

        for (const file of tempFiles) {
            const filePath = path.join(EXPORT_DIR, file);
            try {
                const content = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                // Use the most recent temp file or match by tempId
                if (!parsed || file.includes(tempId)) {
                    parsed = content;
                    tempPath = filePath;
                }
            } catch (e) {
                // Skip invalid files
            }
        }

        if (!parsed) {
            return res.status(400).json({ error: 'No uploaded file found. Please upload a file first.' });
        }

        // Get triples - handle different parsed formats (ZIP vs JSON)
        let triples = '';
        if (parsed.triples) {
            triples = parsed.triples;
        } else if (parsed.dataFiles) {
            // Multi-cube ZIP format: combine all data files
            const dataFileNames = Object.keys(parsed.dataFiles).sort();
            for (const fileName of dataFileNames) {
                if (triples) triples += '\n';
                triples += parsed.dataFiles[fileName];
            }
        }

        // Include orphan triples if present (from ZIP backup with orphans)
        let orphanTriples = '';
        let orphanTripleCount = 0;
        if (parsed.orphanTriples && parsed.orphanTriples.trim().length > 0) {
            orphanTriples = parsed.orphanTriples;
            triples += '\n' + orphanTriples;
            orphanTripleCount = orphanTriples.split('\n').filter(line => line.trim()).length;
        }

        if (!triples || triples.trim().length === 0) {
            return res.status(400).json({ error: 'No triples found in the uploaded file' });
        }

        // Determine target graph
        const targetGraph = overrideGraph || graphUri ||
            (parsed.metadata?.graphUri) ||
            (parsed.manifest?.graph?.uri) ||
            (parsed.restore?.targetGraph);

        if (!targetGraph) {
            return res.status(400).json({ error: 'No target graph specified' });
        }

        // Import to triplestore
        const config = { type: type || 'fuseki', mode: mode || 'local', baseUrl, dataset, database, repository, username, password };
        await importData(config, targetGraph, triples);

        // Clean up temp file
        if (tempPath && fs.existsSync(tempPath)) {
            fs.unlinkSync(tempPath);
        }

        // Also clean up old temp files (older than 1 hour)
        const maxAge = 60 * 60 * 1000;
        const now = Date.now();
        for (const file of tempFiles) {
            const filePath = path.join(EXPORT_DIR, file);
            try {
                const stats = fs.statSync(filePath);
                if (now - stats.mtimeMs > maxAge) {
                    fs.unlinkSync(filePath);
                }
            } catch (e) {
                // Skip errors
            }
        }

        const tripleCount = triples.split('\n').filter(line => line.trim()).length;
        res.json({
            success: true,
            importedTriples: tripleCount,
            graphUri: targetGraph,
            metadata: parsed.metadata,
            cubeCount: parsed.cubeCount || (parsed.cubes?.length) || 1,
            orphanTriples: orphanTripleCount > 0 ? orphanTripleCount : undefined
        });
    } catch (error) {
        console.error('Import error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Restore backup to a specified triplestore (reads from self-contained ZIP)
// Supports selective restore: pass selectedCubes array with cube URIs to restore only specific cubes
app.post('/api/backup/restore-to', requireDestructiveAccess, async (req, res) => {
    try {
        const {
            backupId,
            type, mode, baseUrl, dataset, database, repository, username, password,
            graphUri,
            selectedCubes, // Optional: array of cube URIs to restore (if empty, restore all)
            includeOrphans // Optional: restore orphan triples if present (default: true)
        } = req.body;

        // Validate backup ID to prevent path traversal
        validateBackupId(backupId);

        // Find the ZIP file for this backup
        const files = fs.readdirSync(BACKUP_DIR);
        const zipFile = files.find(f => f.endsWith('.zip') && f.includes(backupId));

        if (!zipFile) {
            return res.status(404).json({ error: 'Backup not found' });
        }

        const zipPath = path.join(BACKUP_DIR, zipFile);
        const zip = new AdmZip(zipPath);

        // Read manifest
        const manifestEntry = zip.getEntry('manifest.json');
        if (!manifestEntry) {
            return res.status(500).json({ error: 'Invalid backup: missing manifest' });
        }
        const manifest = JSON.parse(manifestEntry.getData().toString('utf8'));

        // Check if backup includes orphans
        const shouldRestoreOrphans = includeOrphans !== false; // Default to true
        const hasOrphans = manifest.stats?.includesOrphans || manifest.orphans?.included || false;

        // Read triples (support both single and multi-cube formats)
        let triples = '';
        let totalTripleCount = 0;
        let restoredCubes = [];

        if (manifest.cubes && manifest.cubes.length > 0) {
            // Multi-cube format: read selected data files or all if none specified
            const cubesToRestore = selectedCubes && selectedCubes.length > 0
                ? manifest.cubes.filter(c => selectedCubes.includes(c.uri))
                : manifest.cubes;

            for (const cube of cubesToRestore) {
                const dataEntry = zip.getEntry(cube.dataFile || 'data.nt');
                if (dataEntry) {
                    triples += dataEntry.getData().toString('utf8') + '\n';
                    totalTripleCount += cube.tripleCount || 0;
                    restoredCubes.push({
                        uri: cube.uri,
                        name: cube.name,
                        tripleCount: cube.tripleCount
                    });
                }
            }
        } else {
            // Single cube format
            const dataEntry = zip.getEntry('data.nt');
            if (!dataEntry) {
                return res.status(500).json({ error: 'Invalid backup: missing data file' });
            }
            triples = dataEntry.getData().toString('utf8');
            totalTripleCount = manifest.cube?.tripleCount || manifest.stats?.totalTripleCount || 0;
            restoredCubes.push({
                uri: manifest.cube?.uri,
                name: manifest.cube?.name,
                tripleCount: totalTripleCount
            });
        }

        if (triples.trim().length === 0) {
            return res.status(400).json({ error: 'No cubes selected or no data found for selected cubes' });
        }

        // Read and add orphan triples if present and requested
        let orphanTriples = '';
        let orphanTripleCount = 0;
        if (shouldRestoreOrphans && hasOrphans) {
            const orphanEntry = zip.getEntry('orphans.nt');
            if (orphanEntry) {
                orphanTriples = orphanEntry.getData().toString('utf8');
                orphanTripleCount = orphanTriples.split('\n').filter(line => line.trim()).length;
                if (orphanTriples.trim().length > 0) {
                    triples += '\n' + orphanTriples;
                    totalTripleCount += orphanTripleCount;
                }
            }
        }

        // Use provided graph or original from manifest
        const targetGraph = graphUri || manifest.graph?.uri || manifest.restore?.targetGraph || '';

        // Import to specified triplestore
        const config = { type: type || 'fuseki', mode: mode || 'local', baseUrl, dataset, database, repository, username, password };
        await importData(config, targetGraph, triples);

        res.json({
            success: true,
            restoredTriples: totalTripleCount,
            cubeUri: manifest.cube?.uri || (manifest.cubes && manifest.cubes[0]?.uri) || '',
            graphUri: targetGraph,
            cubeCount: restoredCubes.length,
            totalCubesInBackup: manifest.cubes?.length || 1,
            restoredCubes: restoredCubes,
            restoredOrphans: shouldRestoreOrphans && hasOrphans ? {
                tripleCount: orphanTripleCount
            } : null
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete a backup (deletes self-contained ZIP file)
app.delete('/api/backup/:backupId', requireDestructiveAccess, (req, res) => {
    try {
        const { backupId } = req.params;

        // Validate backup ID to prevent path traversal
        validateBackupId(backupId);

        // Find the ZIP file for this backup
        const files = fs.readdirSync(BACKUP_DIR);
        const zipFile = files.find(f => f.endsWith('.zip') && f.includes(backupId));

        if (!zipFile) {
            return res.status(404).json({ error: 'Backup not found' });
        }

        const zipPath = path.join(BACKUP_DIR, zipFile);
        fs.unlinkSync(zipPath);

        res.json({ success: true, message: 'Backup deleted' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`LINDAS Cube Cleanup Demo Server running on http://localhost:${PORT}`);
    console.log(`Fuseki expected at: ${DEFAULT_FUSEKI_ENDPOINT}`);
    console.log(`LINDAS endpoint: ${LINDAS_ENDPOINT}`);
    console.log(`Backup directory: ${BACKUP_DIR}`);
    console.log(`Backup retention: ${BACKUP_RETENTION_DAYS} days`);
});

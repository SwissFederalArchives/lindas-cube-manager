// ============================================================================
// LINDAS Cube Manager - Application
// Version: 2.0
// ============================================================================

// Triplestore configuration defaults
const TRIPLESTORE_DEFAULTS = {
    fuseki: {
        local: { baseUrl: 'http://localhost:3030', port: 3030 },
        remote: { baseUrl: 'https://lindas.admin.ch' }
    },
    stardog: {
        local: { baseUrl: 'http://localhost:5820', port: 5820, username: 'admin', password: 'admin' },
        remote: { baseUrl: 'https://sd-xxxxx.stardog.cloud:5820' }
    },
    graphdb: {
        local: { baseUrl: 'http://localhost:7200', port: 7200 },
        remote: { baseUrl: 'https://your-instance.graphdb.cloud' }
    }
};

// LINDAS environment URLs
const LINDAS_ENVIRONMENTS = {
    'https://lindas.admin.ch': { name: 'Production', env: 'PROD' },
    'https://int.lindas.admin.ch': { name: 'Integration', env: 'INT' },
    'https://test.lindas.admin.ch': { name: 'Test', env: 'TEST' }
};

// Application State
const state = {
    mode: 'dryrun', // 'dryrun' or 'execute'
    triplestoreType: 'fuseki',
    connectionMode: 'local', // 'local' or 'remote'
    connected: false,

    // Connection config
    endpointUrl: 'http://localhost:3030',
    fusekiDataset: 'lindas',
    stardogDatabase: 'lindas',
    graphdbRepository: 'test',
    authUsername: '',
    authPassword: '',

    // LINDAS download config
    lindasEnv: 'https://lindas.admin.ch',
    downloadGraph: 'https://lindas.admin.ch/sfoe/cube',

    // Wizard state
    wizardStep: 1,
    wizardGraph: 'https://lindas.admin.ch/sfoe/cube',
    allVersions: [],
    multiVersionCubes: [],
    cubesToDelete: [],
    cubesToKeep: [],
    versionsToKeep: 2, // Number of newest versions to keep (configurable)
    selectedCubesForDeletion: new Set(), // Tracks which cubes are selected for deletion (base URIs)

    // Deletion results
    deletionResults: {
        deletedCubes: [],
        keptCubes: [],
        totalTriplesDeleted: 0,
        backupIds: [],
        orphanShapesCleaned: 0,
        orphanShapeTriplesCleaned: 0,
        orphanCleanupPerformed: false
    },

    // Query editor
    queryGraph: 'https://lindas.admin.ch/sfoe/cube',
    queryCube: '',

    // Backups
    backups: [],
    selectedBackupId: null,
    selectedCubesToRestore: [], // For selective restore of multi-cube backups
    uploadedFileData: null
};

// ============================================================================
// Safe DOM Manipulation Helpers
// ============================================================================

function createTextElement(tag, text, className) {
    const el = document.createElement(tag);
    el.textContent = text;
    if (className) el.className = className;
    return el;
}

function createElementWithChildren(tag, children, className) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    children.forEach(child => {
        if (typeof child === 'string') {
            el.appendChild(document.createTextNode(child));
        } else {
            el.appendChild(child);
        }
    });
    return el;
}

function clearElement(el) {
    while (el.firstChild) {
        el.removeChild(el.firstChild);
    }
}

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initModeToggle();
    initConnectionSection();
    initDownloadSection();
    initWizard();
    initQueryEditor();
    initBackupsSection();
    initDocumentation();
    // Load initial state
    updateModeUI();
    updateConnectionUI();
    // Service-deployment mode (must run after other inits)
    initServiceMode();
});

// ============================================================================
// Service-Deployment Mode
// When the server is running with STORE_QUERY_ENDPOINT set, it returns
// serviceMode:true from /api/config. The UI hides the connection form and
// shows a locked-connection banner instead.
// ============================================================================

let currentAuthToken = null;

function setAuthToken(token) {
    currentAuthToken = token;
}

function scheduleTokenRenewal(mgr) {
    mgr.events.addUserLoaded(user => setAuthToken(user.access_token));
    mgr.events.addAccessTokenExpiring(() => mgr.signinSilent().catch(console.error));
}

/**
 * Thin fetch wrapper that injects the Bearer token when an OIDC session is active.
 * Used in place of bare fetch() for all /api/* calls.
 */
function authFetch(url, options = {}) {
    if (currentAuthToken) {
        options.headers = {
            ...options.headers,
            Authorization: 'Bearer ' + currentAuthToken,
        };
    }
    return fetch(url, options);
}

async function initOidcAuth(authCfg) {
    const { issuer, clientId } = authCfg;
    if (typeof Oidc === 'undefined') {
        console.warn('oidc-client not loaded — auth skipped');
        return;
    }
    const mgr = new Oidc.UserManager({
        authority: issuer,
        client_id: clientId,
        redirect_uri: window.location.origin + '/',
        response_type: 'code',
        scope: 'openid profile email',
        automaticSilentRenew: true,
        userStore: new Oidc.WebStorageStateStore({ store: window.sessionStorage }),
    });

    // Handle authorization code callback
    if (window.location.search.includes('code=')) {
        try {
            const user = await mgr.signinRedirectCallback();
            window.history.replaceState({}, document.title, window.location.pathname);
            setAuthToken(user.access_token);
            scheduleTokenRenewal(mgr);
        } catch (err) {
            console.error('OIDC callback error:', err);
        }
        return;
    }

    // Check for an existing valid session
    const user = await mgr.getUser();
    if (user && !user.expired) {
        setAuthToken(user.access_token);
        scheduleTokenRenewal(mgr);
        return;
    }

    // No session found — redirect to Keycloak login
    await mgr.signinRedirect({ state: window.location.pathname });
}

async function initServiceMode() {
    try {
        const res = await authFetch('/api/config');
        const cfg = await res.json();
        if (!cfg.serviceMode) return;

        // Hide the manual connection form; show the locked-connection banner
        const connSection = document.getElementById('section-connection');
        if (connSection) {
            // Hide the intro text and the connection card (everything except the banner)
            const sectionIntro = connSection.querySelector('.section-intro');
            const modeInfoBanner = connSection.querySelector('#mode-info-banner');
            const card = connSection.querySelector('.card');
            const quickGrid = connSection.querySelector('.quick-setup-grid');
            if (sectionIntro) sectionIntro.style.display = 'none';
            if (modeInfoBanner) modeInfoBanner.style.display = 'none';
            if (card) card.style.display = 'none';
            if (quickGrid) quickGrid.style.display = 'none';
        }

        const indicator = document.getElementById('service-mode-indicator');
        if (indicator) {
            indicator.textContent =
                'Connected to ' + cfg.connection.database +
                ' (' + cfg.connection.type + ') - managed by environment';
            indicator.style.display = 'block';
        }

        // Pre-fill state so any remaining code that reads it still works
        state.triplestoreType = cfg.connection.type;
        state.endpointUrl = cfg.connection.baseUrl;
        state.fusekiDataset = cfg.connection.database;
        state.stardogDatabase = cfg.connection.database;
        state.graphdbRepository = cfg.connection.database;
        state.connected = true;

        // Update UI to reflect connected state
        updateConnectionUI();

        // Start OIDC flow if auth is enabled
        if (cfg.auth && cfg.auth.enabled) {
            await initOidcAuth(cfg.auth);
        }
    } catch (err) {
        console.warn('Could not fetch /api/config:', err);
    }
}

// ============================================================================
// Navigation
// ============================================================================

function initNavigation() {
    // Sidebar navigation
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const section = item.dataset.section;
            navigateToSection(section);
        });
    });

    // Sidebar toggle for mobile
    const sidebarToggle = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    if (sidebarToggle && sidebar) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
    }

    // Close sidebar on section click (mobile)
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            if (window.innerWidth <= 1024) {
                sidebar.classList.remove('open');
            }
        });
    });
}

function navigateToSection(sectionId) {
    // Update nav items
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.section === sectionId);
    });

    // Update sections
    const sections = document.querySelectorAll('.content-section');
    sections.forEach(section => {
        section.classList.toggle('active', section.id === 'section-' + sectionId);
    });

    // Update page title
    const titles = {
        'connection': 'Connection Setup',
        'download': 'Download Data',
        'wizard': 'Deletion Wizard',
        'query-editor': 'Query Editor',
        'backups': 'Backup Management',
        'documentation': 'Documentation'
    };
    const pageTitle = document.getElementById('page-title');
    if (pageTitle && titles[sectionId]) {
        pageTitle.textContent = titles[sectionId];
    }
}

// ============================================================================
// Mode Toggle (Offline/Online)
// ============================================================================

function initModeToggle() {
    const modeButtons = document.querySelectorAll('.mode-btn');
    modeButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const mode = btn.dataset.mode;
            setMode(mode);
        });
    });
}

function setMode(mode) {
    state.mode = mode;

    // Update buttons
    const modeButtons = document.querySelectorAll('.mode-btn');
    modeButtons.forEach(btn => {
        btn.classList.toggle('active', btn.dataset.mode === mode);
        if (btn.dataset.mode === 'execute' && mode === 'execute') {
            btn.classList.add('execute');
        } else {
            btn.classList.remove('execute');
        }
    });

    updateModeUI();
    updateConnectionUI();
}

function updateModeUI() {
    const mode = state.mode;

    // Update header mode badge
    const modeBadge = document.querySelector('.mode-badge');
    if (modeBadge) {
        modeBadge.textContent = mode === 'dryrun' ? 'DRY RUN' : 'EXECUTE';
        modeBadge.classList.toggle('dryrun', mode === 'dryrun');
        modeBadge.classList.toggle('execute', mode === 'execute');
    }

    // Update mode info banner
    const modeBanner = document.getElementById('mode-info-banner');
    if (modeBanner) {
        clearElement(modeBanner);

        const iconDiv = document.createElement('div');
        iconDiv.className = 'info-icon';
        iconDiv.textContent = mode === 'dryrun' ? '\u{1F50D}' : '\u26A1';

        const contentDiv = document.createElement('div');
        contentDiv.className = 'info-content';

        const strong = document.createElement('strong');
        strong.textContent = mode === 'dryrun' ? 'Dry Run Mode' : 'Execute Mode - CAUTION';
        contentDiv.appendChild(strong);

        const p = document.createElement('p');
        p.textContent = mode === 'dryrun'
            ? 'Preview what would be deleted without making any changes. Safe for testing and verification.'
            : 'Deletions will be executed for real. A backup will be created before deletion. Use with care!';
        contentDiv.appendChild(p);

        modeBanner.appendChild(iconDiv);
        modeBanner.appendChild(contentDiv);

        modeBanner.classList.toggle('execute', mode === 'execute');
    }
}

// ============================================================================
// Connection Section
// ============================================================================

function initConnectionSection() {
    // Triplestore type selector
    const typeSelect = document.getElementById('triplestore-type');
    if (typeSelect) {
        typeSelect.addEventListener('change', (e) => {
            // Explicitly update state when dropdown changes
            state.triplestoreType = e.target.value;
            updateConnectionState();
        });
    }

    // Connection mode selector
    const connectionMode = document.getElementById('connection-mode');
    if (connectionMode) {
        connectionMode.addEventListener('change', (e) => {
            state.connectionMode = e.target.value;
            updateConnectionState();
        });
    }

    // Endpoint URL input - track manual changes
    const endpointUrl = document.getElementById('endpoint-url');
    if (endpointUrl) {
        endpointUrl.addEventListener('input', () => {
            state.endpointUrl = endpointUrl.value.trim();
        });
    }

    // Database/dataset name inputs - track changes
    const datasetName = document.getElementById('dataset-name');
    if (datasetName) {
        datasetName.addEventListener('input', () => {
            state.fusekiDataset = datasetName.value.trim();
        });
    }

    const stardogDatabase = document.getElementById('stardog-database');
    if (stardogDatabase) {
        stardogDatabase.addEventListener('input', () => {
            state.stardogDatabase = stardogDatabase.value.trim();
        });
    }

    // Auth inputs - track changes
    const authUsername = document.getElementById('auth-username');
    if (authUsername) {
        authUsername.addEventListener('input', () => {
            state.authUsername = authUsername.value;
        });
    }

    const authPassword = document.getElementById('auth-password');
    if (authPassword) {
        authPassword.addEventListener('input', () => {
            state.authPassword = authPassword.value;
        });
    }

    // Test connection button
    const testBtn = document.getElementById('btn-test-connection');
    if (testBtn) {
        testBtn.addEventListener('click', testConnection);
    }

    // Create dataset button
    const createBtn = document.getElementById('btn-create-dataset');
    if (createBtn) {
        createBtn.addEventListener('click', createDataset);
    }

    // Quick setup preset buttons
    const presetButtons = document.querySelectorAll('[data-preset]');
    presetButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const preset = btn.dataset.preset;
            applyPreset(preset);
        });
    });
}

function updateConnectionState() {
    // Central function to update connection UI based on current state
    const typeSelect = document.getElementById('triplestore-type');
    const connectionMode = document.getElementById('connection-mode');
    const endpointUrl = document.getElementById('endpoint-url');
    const endpointHint = document.getElementById('endpoint-hint');

    if (!typeSelect || !connectionMode) return;

    // Sync DOM elements with state
    if (typeSelect.value !== state.triplestoreType) {
        typeSelect.value = state.triplestoreType;
    }
    if (connectionMode.value !== state.connectionMode) {
        connectionMode.value = state.connectionMode;
    }

    const type = state.triplestoreType;
    const mode = state.connectionMode;

    // Update endpoint URL and hint
    // Only set default URL if the current URL is empty or is a known placeholder
    const defaults = TRIPLESTORE_DEFAULTS[type][mode];
    if (defaults && endpointUrl) {
        const currentUrl = endpointUrl.value.trim();
        const knownDefaults = [
            '', // empty
            'http://localhost:3030',
            'http://localhost:5820',
            'http://localhost:7200',
            'https://lindas.admin.ch',
            'https://sd-xxxxx.stardog.cloud:5820',
            'https://your-instance.graphdb.cloud'
        ];
        // Only reset to default if current URL is empty or a known placeholder
        if (!currentUrl || knownDefaults.includes(currentUrl)) {
            endpointUrl.value = defaults.baseUrl;
            state.endpointUrl = defaults.baseUrl;
        } else {
            // Preserve user-entered custom URL
            state.endpointUrl = currentUrl;
        }
    }

    if (endpointHint) {
        const hints = {
            'fuseki-local': 'Default endpoint for Apache Fuseki local instance',
            'fuseki-remote': 'Enter the remote Fuseki server URL',
            'stardog-local': 'Default endpoint for local Stardog (requires license)',
            'stardog-remote': 'Enter your Stardog Cloud instance URL',
            'graphdb-local': 'Default endpoint for local GraphDB Free',
            'graphdb-remote': 'Enter your GraphDB Cloud instance URL'
        };
        endpointHint.textContent = hints[type + '-' + mode] || '';
    }

    // Show/hide dataset/database/repository rows
    const datasetRow = document.getElementById('dataset-row');
    const stardogRow = document.getElementById('stardog-row');
    const graphdbRow = document.getElementById('graphdb-row');
    const authRow = document.getElementById('auth-row');

    if (datasetRow) datasetRow.classList.toggle('hidden', type !== 'fuseki');
    if (stardogRow) stardogRow.classList.toggle('hidden', type !== 'stardog');
    if (graphdbRow) graphdbRow.classList.toggle('hidden', type !== 'graphdb');

    // Show auth for Stardog and GraphDB, or remote connections
    const needsAuth = type === 'stardog' || (type === 'graphdb' && mode === 'remote');
    if (authRow) authRow.classList.toggle('hidden', !needsAuth);

    // Auto-fill Stardog credentials for local
    if (type === 'stardog' && mode === 'local') {
        const usernameInput = document.getElementById('auth-username');
        const passwordInput = document.getElementById('auth-password');
        if (usernameInput && !usernameInput.value) usernameInput.value = 'admin';
        if (passwordInput && !passwordInput.value) passwordInput.value = 'admin';
    }
}

function applyPreset(preset) {
    // Update DOM elements directly without triggering events
    const typeSelect = document.getElementById('triplestore-type');
    const connectionMode = document.getElementById('connection-mode');

    if (typeSelect) {
        typeSelect.value = preset;
    }
    if (connectionMode) {
        connectionMode.value = 'local';
    }

    // Update state from DOM after setting values
    state.triplestoreType = preset;
    state.connectionMode = 'local';

    // Then update UI based on state - this will update endpoint URL, hints, visibility
    updateConnectionState();
}

function updateConnectionUI() {
    // Backward-compatible wrapper that syncs state from DOM then updates UI
    const typeSelect = document.getElementById('triplestore-type');
    const connectionMode = document.getElementById('connection-mode');

    // Sync state from DOM if elements exist
    if (typeSelect) {
        state.triplestoreType = typeSelect.value;
    }
    if (connectionMode) {
        state.connectionMode = connectionMode.value;
    }

    // Update UI based on state
    updateConnectionState();
}

async function testConnection() {
    const resultBox = document.getElementById('connection-result');
    const btn = document.getElementById('btn-test-connection');

    if (!resultBox) return;

    resultBox.classList.remove('hidden', 'success', 'error');
    resultBox.textContent = 'Testing connection...';
    btn.disabled = true;

    try {
        const config = getConnectionConfig();
        const response = await authFetch('/api/triplestore/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        const result = await response.json();

        if (result.connected) {
            resultBox.classList.add('success');
            resultBox.textContent = 'Connected successfully! ' + (result.message || '');
            state.connected = true;
            updateSidebarConnectionStatus(true);
            updateHeaderTriplestoreInfo(config.type);
        } else {
            throw new Error(result.error || 'Connection failed');
        }
    } catch (error) {
        resultBox.classList.add('error');
        resultBox.textContent = 'Connection failed: ' + error.message;
        state.connected = false;
        updateSidebarConnectionStatus(false);
    } finally {
        btn.disabled = false;
    }
}

async function createDataset() {
    const resultBox = document.getElementById('connection-result');
    const btn = document.getElementById('btn-create-dataset');

    if (!resultBox) return;

    resultBox.classList.remove('hidden', 'success', 'error');
    resultBox.textContent = 'Creating dataset...';
    btn.disabled = true;

    try {
        const config = getConnectionConfig();
        const response = await authFetch('/api/triplestore/create-dataset', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        const result = await response.json();

        if (result.success) {
            resultBox.classList.add('success');
            resultBox.textContent = 'Dataset created successfully!';
        } else {
            throw new Error(result.error || 'Failed to create dataset');
        }
    } catch (error) {
        resultBox.classList.add('error');
        resultBox.textContent = 'Failed to create dataset: ' + error.message;
    } finally {
        btn.disabled = false;
    }
}

function getConnectionConfig() {
    return {
        type: state.triplestoreType,
        mode: state.connectionMode,
        baseUrl: document.getElementById('endpoint-url')?.value || state.endpointUrl,
        dataset: document.getElementById('fuseki-dataset')?.value || state.fusekiDataset,
        database: document.getElementById('stardog-database')?.value || state.stardogDatabase,
        repository: document.getElementById('graphdb-repository')?.value || state.graphdbRepository,
        username: document.getElementById('auth-username')?.value || '',
        password: document.getElementById('auth-password')?.value || ''
    };
}

function updateSidebarConnectionStatus(connected) {
    const statusDot = document.querySelector('.status-dot');
    const statusLabel = document.querySelector('.status-label');

    if (statusDot) {
        statusDot.classList.toggle('connected', connected);
        statusDot.classList.toggle('disconnected', !connected);
    }

    if (statusLabel) {
        statusLabel.textContent = connected ? 'Connected' : 'Disconnected';
    }
}

function updateHeaderTriplestoreInfo(type) {
    const info = document.querySelector('.triplestore-type');
    if (info) {
        const names = { fuseki: 'Apache Fuseki', stardog: 'Stardog', graphdb: 'GraphDB' };
        info.textContent = names[type] || type;
    }
}

// ============================================================================
// Download Section (Offline Mode)
// ============================================================================

function initDownloadSection() {
    // LINDAS environment selection
    const envOptions = document.querySelectorAll('input[name="lindas-env"]');
    envOptions.forEach(opt => {
        opt.addEventListener('change', onLindasEnvChange);
    });

    // Custom URL input
    const customUrlInput = document.getElementById('custom-lindas-url');
    if (customUrlInput) {
        customUrlInput.addEventListener('input', () => {
            state.lindasEnv = customUrlInput.value;
        });
    }

    // Load graphs button
    const loadGraphsBtn = document.getElementById('btn-load-graphs');
    if (loadGraphsBtn) {
        loadGraphsBtn.addEventListener('click', loadLindasGraphs);
    }

    // Graph select
    const graphSelect = document.getElementById('download-graph-select');
    if (graphSelect) {
        graphSelect.addEventListener('change', () => {
            if (graphSelect.value) {
                document.getElementById('download-graph-manual').value = graphSelect.value;
                state.downloadGraph = graphSelect.value;
            }
        });
    }

    // Manual graph input
    const manualGraphInput = document.getElementById('download-graph-manual');
    if (manualGraphInput) {
        manualGraphInput.addEventListener('input', () => {
            state.downloadGraph = manualGraphInput.value;
        });
    }

    // Download buttons
    const downloadAllBtn = document.getElementById('btn-download-all');
    if (downloadAllBtn) {
        downloadAllBtn.addEventListener('click', downloadAllCubes);
    }

    const downloadSampleBtn = document.getElementById('btn-download-sample');
    if (downloadSampleBtn) {
        downloadSampleBtn.addEventListener('click', downloadSampleData);
    }

    // Go to wizard button
    const goToWizardBtn = document.getElementById('btn-go-to-wizard');
    if (goToWizardBtn) {
        goToWizardBtn.addEventListener('click', () => {
            navigateToSection('wizard');
        });
    }
}

function onLindasEnvChange(e) {
    const value = e.target.value;
    const customInput = document.getElementById('custom-lindas-url');

    if (value === 'custom') {
        if (customInput) {
            customInput.disabled = false;
            customInput.focus();
        }
    } else {
        if (customInput) {
            customInput.disabled = true;
        }
        state.lindasEnv = value;
    }
}

async function loadLindasGraphs() {
    const graphSelect = document.getElementById('download-graph-select');
    const btn = document.getElementById('btn-load-graphs');

    if (!graphSelect) return;

    btn.disabled = true;
    clearElement(graphSelect);
    const loadingOpt = document.createElement('option');
    loadingOpt.value = '';
    loadingOpt.textContent = 'Loading graphs...';
    graphSelect.appendChild(loadingOpt);

    try {
        const response = await authFetch('/api/lindas/all-graphs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ lindasEndpoint: state.lindasEnv })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to load graphs');
        }

        clearElement(graphSelect);
        const defaultOpt = document.createElement('option');
        defaultOpt.value = '';
        defaultOpt.textContent = '-- Select a graph --';
        graphSelect.appendChild(defaultOpt);

        if (result.graphs && result.graphs.length > 0) {
            result.graphs.forEach(graph => {
                const opt = document.createElement('option');
                opt.value = graph.uri;
                opt.textContent = graph.uri;
                graphSelect.appendChild(opt);
            });
        } else {
            const noGraphOpt = document.createElement('option');
            noGraphOpt.value = '';
            noGraphOpt.textContent = 'No graphs found';
            graphSelect.appendChild(noGraphOpt);
        }
    } catch (error) {
        clearElement(graphSelect);
        const errorOpt = document.createElement('option');
        errorOpt.value = '';
        errorOpt.textContent = 'Error loading graphs';
        graphSelect.appendChild(errorOpt);
        console.error('Error loading graphs:', error);
    } finally {
        btn.disabled = false;
    }
}

async function downloadAllCubes() {
    const progressContainer = document.getElementById('download-progress');
    const summaryBox = document.getElementById('download-summary');
    const btn = document.getElementById('btn-download-all');

    if (!progressContainer) return;

    progressContainer.classList.remove('hidden');
    summaryBox.classList.add('hidden');
    btn.disabled = true;

    try {
        // First, get list of cubes
        updateDownloadProgress('Fetching cube list...', 0, 0, 0);

        const cubesResponse = await authFetch('/api/lindas/cubes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                lindasEndpoint: state.lindasEnv,
                graphUri: state.downloadGraph
            })
        });

        const cubesResult = await cubesResponse.json();

        if (!cubesResult.cubes || cubesResult.cubes.length === 0) {
            throw new Error('No cubes found in the selected graph');
        }

        const cubes = cubesResult.cubes;
        const total = cubes.length;
        let downloaded = 0;
        let errors = 0;
        let totalTriples = 0;

        const config = getConnectionConfig();

        // Download each cube with rate limiting
        for (let i = 0; i < cubes.length; i++) {
            const cube = cubes[i];
            updateDownloadProgress('Downloading cubes...', i + 1, total, downloaded);
            updateDownloadCurrent(cube.cube);

            try {
                // Show rate limit notice
                if (i > 0) {
                    showRateLimitNotice(true);
                    await sleep(500); // Rate limiting
                    showRateLimitNotice(false);
                }

                // Download cube data from LINDAS
                const downloadResponse = await authFetch('/api/lindas/download-cube', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        lindasEndpoint: state.lindasEnv,
                        graphUri: state.downloadGraph,
                        cubeUri: cube.cube
                    })
                });

                const downloadResult = await downloadResponse.json();

                if (!downloadResponse.ok || !downloadResult.triples) {
                    throw new Error('Failed to download cube data');
                }

                // Import to local triplestore
                const importResponse = await authFetch('/api/triplestore/import', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ...config,
                        triples: downloadResult.triples,
                        graphUri: state.downloadGraph
                    })
                });

                const importResult = await importResponse.json();

                if (importResponse.ok) {
                    downloaded++;
                    totalTriples += downloadResult.tripleCount || 0;
                } else {
                    errors++;
                }

            } catch (err) {
                console.error('Error downloading cube:', cube.cube, err);
                errors++;
            }
        }

        // Show summary
        progressContainer.classList.add('hidden');
        summaryBox.classList.remove('hidden');

        document.getElementById('summary-downloaded').textContent = downloaded;
        document.getElementById('summary-triples').textContent = totalTriples.toLocaleString();
        document.getElementById('summary-errors').textContent = errors;

    } catch (error) {
        updateDownloadProgress('Error: ' + error.message, 0, 0, 0);
        progressContainer.classList.add('hidden');
        console.error('Download error:', error);
    } finally {
        btn.disabled = false;
    }
}

async function downloadSampleData() {
    const progressContainer = document.getElementById('download-progress');
    const summaryBox = document.getElementById('download-summary');
    const btn = document.getElementById('btn-download-sample');

    if (!progressContainer) return;

    progressContainer.classList.remove('hidden');
    summaryBox.classList.add('hidden');
    btn.disabled = true;

    try {
        updateDownloadProgress('Downloading sample data (co2wirkung)...', 0, 1, 0);

        const config = getConnectionConfig();
        const graphUri = 'https://lindas.admin.ch/sfoe/cube';
        const sampleCube = 'https://energy.ld.admin.ch/sfoe/bfe_ogd18_gebaeudeprogramm_co2wirkung';

        // Download all versions of the sample cube
        const response = await authFetch('/api/lindas/download-graph', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                lindasEndpoint: state.lindasEnv,
                graphUri: graphUri,
                cubeBaseUri: sampleCube
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to download sample data');
        }

        // Import to local triplestore
        const importResponse = await authFetch('/api/triplestore/import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...config,
                ntriples: result.ntriples,
                graphUri: graphUri
            })
        });

        if (!importResponse.ok) {
            const importError = await importResponse.json();
            throw new Error(importError.error || 'Failed to import data');
        }

        progressContainer.classList.add('hidden');
        summaryBox.classList.remove('hidden');

        document.getElementById('summary-downloaded').textContent = result.cubeCount || 7;
        document.getElementById('summary-triples').textContent = (result.tripleCount || 0).toLocaleString();
        document.getElementById('summary-errors').textContent = '0';

    } catch (error) {
        updateDownloadProgress('Error: ' + error.message, 0, 0, 0);
        console.error('Sample download error:', error);
    } finally {
        btn.disabled = false;
    }
}

function updateDownloadProgress(step, current, total, downloaded) {
    const stepEl = document.getElementById('download-step');
    const counterEl = document.getElementById('download-counter');
    const progressFill = document.getElementById('download-progress-fill');
    const statusEl = document.getElementById('download-status');

    if (stepEl) stepEl.textContent = step;
    if (counterEl && total > 0) counterEl.textContent = current + ' / ' + total;
    if (progressFill && total > 0) progressFill.style.width = (current / total * 100) + '%';
    if (statusEl) statusEl.textContent = 'Downloaded: ' + downloaded + ' cubes';
}

function updateDownloadCurrent(cubeUri) {
    const currentEl = document.getElementById('download-current');
    if (currentEl) currentEl.textContent = cubeUri;
}

function showRateLimitNotice(show) {
    const notice = document.getElementById('download-rate-limit');
    if (notice) notice.classList.toggle('hidden', !show);
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// Deletion Wizard
// ============================================================================

function initWizard() {
    // Step navigation
    const backBtns = document.querySelectorAll('[id^="btn-wizard-back"]');
    backBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const currentStep = state.wizardStep;
            if (currentStep > 1) {
                goToWizardStep(currentStep - 1);
            }
        });
    });

    // Step 1: Load graph
    const loadGraphBtn = document.getElementById('btn-wizard-load-graph');
    if (loadGraphBtn) {
        loadGraphBtn.addEventListener('click', wizardLoadGraph);
    }

    // Versions to keep setting
    const versionsToKeepInput = document.getElementById('versions-to-keep');
    if (versionsToKeepInput) {
        versionsToKeepInput.value = state.versionsToKeep;
        versionsToKeepInput.addEventListener('change', () => {
            const value = parseInt(versionsToKeepInput.value, 10);
            if (value >= 1 && value <= 10) {
                state.versionsToKeep = value;
                // Update the display text
                const displayEl = document.getElementById('versions-to-keep-display');
                if (displayEl) displayEl.textContent = value;
            }
        });
    }

    // Step 2: Continue to preview
    const nextBtn2 = document.getElementById('btn-wizard-next-2');
    if (nextBtn2) {
        nextBtn2.addEventListener('click', () => {
            wizardPreviewDeletions();
        });
    }

    // Step 3: Proceed to deletion
    const nextBtn3 = document.getElementById('btn-wizard-next-3');
    if (nextBtn3) {
        nextBtn3.addEventListener('click', () => {
            goToWizardStep(4);
        });
    }

    // Step 4: Confirm checkbox
    const confirmCheckbox = document.getElementById('confirm-deletion');
    const executeBtn = document.getElementById('btn-execute-deletion');
    if (confirmCheckbox && executeBtn) {
        confirmCheckbox.addEventListener('change', () => {
            executeBtn.disabled = !confirmCheckbox.checked;
        });
    }

    // Step 4: Execute deletion
    if (executeBtn) {
        executeBtn.addEventListener('click', wizardExecuteDeletion);
    }

    // Metadata checkbox
    const includeMetadataBackupCheckbox = document.getElementById('include-metadata-backup');
    if (includeMetadataBackupCheckbox) {
        includeMetadataBackupCheckbox.addEventListener('change', () => {
            state.includeMetadataInBackup = includeMetadataBackupCheckbox.checked;
        });
    }

    // Orphan checkboxes
    const includeOrphansBackupCheckbox = document.getElementById('include-orphans-backup');
    if (includeOrphansBackupCheckbox) {
        includeOrphansBackupCheckbox.addEventListener('change', () => {
            state.includeOrphansInBackup = includeOrphansBackupCheckbox.checked;
        });
    }

    const cleanupOrphansCheckbox = document.getElementById('cleanup-orphans');
    if (cleanupOrphansCheckbox) {
        cleanupOrphansCheckbox.addEventListener('change', () => {
            state.cleanupOrphansAfterDeletion = cleanupOrphansCheckbox.checked;
        });
    }

    // Step 5: Restart
    const restartBtn = document.getElementById('btn-wizard-restart');
    if (restartBtn) {
        restartBtn.addEventListener('click', () => {
            resetWizard();
        });
    }

    // Step 5: Export report
    const exportReportBtn = document.getElementById('btn-wizard-export-report');
    if (exportReportBtn) {
        exportReportBtn.addEventListener('click', exportDeletionReport);
    }

    // Step 5: View backups link
    const viewBackupsLink = document.getElementById('view-backups-link');
    if (viewBackupsLink) {
        viewBackupsLink.addEventListener('click', (e) => {
            e.preventDefault();
            navigateToSection('backups');
            loadBackupList();
        });
    }

    // Toggle all versions table
    const toggleBtn = document.querySelector('.toggle-btn');
    if (toggleBtn) {
        toggleBtn.addEventListener('click', () => {
            const container = document.getElementById('wizard-all-versions');
            if (container) {
                container.classList.toggle('collapsed');
                toggleBtn.textContent = container.classList.contains('collapsed') ? 'Show All' : 'Hide';
            }
        });
    }
}

function goToWizardStep(step) {
    state.wizardStep = step;

    // Update step indicators
    const steps = document.querySelectorAll('.wizard-step');
    steps.forEach((stepEl, index) => {
        const stepNum = index + 1;
        stepEl.classList.remove('active', 'completed');
        if (stepNum === step) {
            stepEl.classList.add('active');
        } else if (stepNum < step) {
            stepEl.classList.add('completed');
        }
    });

    // Update panels
    const panels = document.querySelectorAll('.wizard-panel');
    panels.forEach((panel, index) => {
        panel.classList.toggle('active', index + 1 === step);
    });
}

function resetWizard() {
    state.wizardStep = 1;
    state.allVersions = [];
    state.selectedCubesForDeletion = new Set();
    state.multiVersionCubes = [];
    state.cubesToDelete = [];
    state.cubesToKeep = [];
    state.deletionResults = {
        deletedCubes: [],
        keptCubes: [],
        totalTriplesDeleted: 0,
        backupIds: [],
        orphanShapesCleaned: 0,
        orphanShapeTriplesCleaned: 0,
        orphanCleanupPerformed: false
    };

    // Reset confirm checkbox
    const confirmCheckbox = document.getElementById('confirm-deletion');
    if (confirmCheckbox) confirmCheckbox.checked = false;

    // Reset metadata checkbox to default (checked)
    const includeMetadataBackupCheckbox = document.getElementById('include-metadata-backup');
    if (includeMetadataBackupCheckbox) includeMetadataBackupCheckbox.checked = true;

    // Reset orphan checkboxes to default (checked)
    const includeOrphansBackupCheckbox = document.getElementById('include-orphans-backup');
    if (includeOrphansBackupCheckbox) includeOrphansBackupCheckbox.checked = true;

    const cleanupOrphansCheckbox = document.getElementById('cleanup-orphans');
    if (cleanupOrphansCheckbox) cleanupOrphansCheckbox.checked = true;

    const executeBtn = document.getElementById('btn-execute-deletion');
    if (executeBtn) executeBtn.disabled = true;

    goToWizardStep(1);
}

async function wizardLoadGraph() {
    const graphInput = document.getElementById('wizard-graph');
    const infoBox = document.getElementById('wizard-graph-info');
    const btn = document.getElementById('btn-wizard-load-graph');

    if (!graphInput || !infoBox) return;

    state.wizardGraph = graphInput.value;
    btn.disabled = true;
    infoBox.classList.remove('hidden');
    infoBox.textContent = 'Loading graph data...';

    try {
        const config = getConnectionConfig();

        // Query for all cube versions
        const response = await authFetch('/api/cubes/list-versions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...config,
                graphUri: state.wizardGraph
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to load cubes');
        }

        state.allVersions = result.versions || [];

        if (state.allVersions.length === 0) {
            clearElement(infoBox);
            const warningSpan = document.createElement('span');
            warningSpan.className = 'text-warning';
            warningSpan.textContent = 'No cubes found in this graph. Make sure you have downloaded data first.';
            infoBox.appendChild(warningSpan);
            return;
        }

        // Count unique base cubes and versions
        const baseCubes = new Set(state.allVersions.map(v => v.baseCube));
        clearElement(infoBox);
        const successSpan = document.createElement('span');
        successSpan.className = 'text-success';
        successSpan.textContent = 'Found ' + state.allVersions.length + ' cube versions across ' + baseCubes.size + ' base cubes.';
        infoBox.appendChild(successSpan);

        // Move to step 2
        setTimeout(() => {
            goToWizardStep(2);
            renderWizardStep2();
        }, 500);

    } catch (error) {
        clearElement(infoBox);
        const errorSpan = document.createElement('span');
        errorSpan.className = 'text-danger';
        errorSpan.textContent = 'Error: ' + error.message;
        infoBox.appendChild(errorSpan);
        console.error('Wizard load error:', error);
    } finally {
        btn.disabled = false;
    }
}

function renderWizardStep2() {
    // Calculate statistics
    const baseCubes = {};
    state.allVersions.forEach(v => {
        if (!baseCubes[v.baseCube]) {
            baseCubes[v.baseCube] = [];
        }
        baseCubes[v.baseCube].push(v);
    });

    const totalCubes = Object.keys(baseCubes).length;
    const multiVersion = Object.entries(baseCubes).filter(([_, versions]) => versions.length > state.versionsToKeep);
    state.multiVersionCubes = multiVersion.map(([base, versions]) => ({
        baseCube: base,
        versions: versions.sort((a, b) => b.version - a.version)
    }));

    const toDelete = multiVersion.reduce((count, [_, versions]) => count + versions.length - state.versionsToKeep, 0);

    // Render summary stats safely
    const summaryEl = document.getElementById('wizard-cubes-summary');
    if (summaryEl) {
        clearElement(summaryEl);

        const stats = [
            { value: totalCubes, label: 'Base Cubes' },
            { value: state.allVersions.length, label: 'Total Versions' },
            { value: multiVersion.length, label: 'Need Cleanup' },
            { value: toDelete, label: 'Versions to Delete' }
        ];

        stats.forEach(stat => {
            const div = document.createElement('div');
            div.className = 'stat';

            const valueSpan = document.createElement('span');
            valueSpan.className = 'stat-value';
            valueSpan.textContent = stat.value;
            div.appendChild(valueSpan);

            const labelSpan = document.createElement('span');
            labelSpan.className = 'stat-label';
            labelSpan.textContent = stat.label;
            div.appendChild(labelSpan);

            summaryEl.appendChild(div);
        });
    }

    // Render multi-version table safely
    const multiVersionTable = document.getElementById('multi-version-table');
    if (multiVersionTable) {
        clearElement(multiVersionTable);

        if (state.multiVersionCubes.length === 0) {
            const p = document.createElement('p');
            p.className = 'text-muted';
            p.textContent = 'No cubes need cleanup (all have 2 or fewer versions).';
            multiVersionTable.appendChild(p);
        } else {
            const table = document.createElement('table');
            table.className = 'data-table';

            // Header
            const thead = document.createElement('thead');
            const headerRow = document.createElement('tr');
            ['Base Cube', 'Versions', 'To Delete'].forEach(text => {
                const th = document.createElement('th');
                th.textContent = text;
                headerRow.appendChild(th);
            });
            thead.appendChild(headerRow);
            table.appendChild(thead);

            // Body
            const tbody = document.createElement('tbody');
            state.multiVersionCubes.forEach(cube => {
                const tr = document.createElement('tr');

                const tdCube = document.createElement('td');
                tdCube.className = 'mono';
                tdCube.textContent = getShortUri(cube.baseCube);
                tr.appendChild(tdCube);

                const tdVersions = document.createElement('td');
                tdVersions.textContent = cube.versions.map(v => v.version).join(', ');
                tr.appendChild(tdVersions);

                const tdDelete = document.createElement('td');
                tdDelete.className = 'text-danger';
                tdDelete.textContent = cube.versions.length - state.versionsToKeep;
                tr.appendChild(tdDelete);

                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            multiVersionTable.appendChild(table);
        }
    }

    // Render all versions table safely
    const allVersionsTable = document.getElementById('all-versions-table');
    if (allVersionsTable) {
        clearElement(allVersionsTable);

        const table = document.createElement('table');
        table.className = 'data-table';

        const thead = document.createElement('thead');
        const headerRow = document.createElement('tr');
        ['Cube URI', 'Version'].forEach(text => {
            const th = document.createElement('th');
            th.textContent = text;
            headerRow.appendChild(th);
        });
        thead.appendChild(headerRow);
        table.appendChild(thead);

        const tbody = document.createElement('tbody');
        state.allVersions.slice(0, 50).forEach(v => {
            const tr = document.createElement('tr');

            const tdUri = document.createElement('td');
            tdUri.className = 'mono';
            tdUri.textContent = getShortUri(v.cube);
            tr.appendChild(tdUri);

            const tdVersion = document.createElement('td');
            tdVersion.textContent = v.version;
            tr.appendChild(tdVersion);

            tbody.appendChild(tr);
        });

        if (state.allVersions.length > 50) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 2;
            td.className = 'text-muted';
            td.textContent = '... and ' + (state.allVersions.length - 50) + ' more';
            tr.appendChild(td);
            tbody.appendChild(tr);
        }

        table.appendChild(tbody);
        allVersionsTable.appendChild(table);
    }
}

async function wizardPreviewDeletions() {
    const previewTable = document.getElementById('deletion-preview-table');
    const statsGrid = document.getElementById('wizard-deletion-stats');

    if (!previewTable) return;

    previewTable.textContent = 'Calculating deletions...';

    try {
        const config = getConnectionConfig();

        // Get deletion preview from server
        const response = await authFetch('/api/cubes/identify-deletions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...config,
                graphUri: state.wizardGraph,
                versionsToKeep: state.versionsToKeep || 2
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to identify deletions');
        }

        state.cubesToDelete = result.toDelete || [];
        state.cubesToKeep = result.toKeep || [];

        // Group by base cube URI (without version number)
        const cubeGroups = {};

        state.cubesToDelete.forEach(v => {
            const baseUri = getBaseCubeUri(v.cube);
            if (!cubeGroups[baseUri]) {
                cubeGroups[baseUri] = { toDelete: [], toKeep: [] };
            }
            cubeGroups[baseUri].toDelete.push(v);
        });

        state.cubesToKeep.forEach(v => {
            const baseUri = getBaseCubeUri(v.cube);
            if (!cubeGroups[baseUri]) {
                cubeGroups[baseUri] = { toDelete: [], toKeep: [] };
            }
            cubeGroups[baseUri].toKeep.push(v);
        });

        // Select all cubes by default
        state.selectedCubesForDeletion = new Set(Object.keys(cubeGroups));

        // Render preview as cube cards with checkboxes
        clearElement(previewTable);

        Object.entries(cubeGroups).forEach(([baseUri, versions]) => {
            const cubeRow = document.createElement('div');
            cubeRow.className = 'cube-row';
            cubeRow.dataset.baseUri = baseUri;

            // Checkbox
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.className = 'cube-checkbox';
            checkbox.checked = true;
            checkbox.dataset.baseUri = baseUri;
            checkbox.addEventListener('change', (e) => {
                if (e.target.checked) {
                    state.selectedCubesForDeletion.add(baseUri);
                } else {
                    state.selectedCubesForDeletion.delete(baseUri);
                }
                updateSelectionCount();
                updateSelectAllCheckbox();
            });
            cubeRow.appendChild(checkbox);

            // Cube info
            const cubeInfo = document.createElement('div');
            cubeInfo.className = 'cube-info';

            const cubeName = document.createElement('div');
            cubeName.className = 'cube-name';
            cubeName.textContent = getShortUri(baseUri);
            cubeInfo.appendChild(cubeName);

            const cubeVersions = document.createElement('div');
            cubeVersions.className = 'cube-versions';

            const deleteVersions = versions.toDelete.map(v => v.version).join(', ');
            const keepVersions = versions.toKeep.map(v => v.version).join(', ');

            if (deleteVersions) {
                const deleteSpan = document.createElement('span');
                deleteSpan.className = 'to-delete';
                deleteSpan.textContent = 'Delete: v' + deleteVersions;
                cubeVersions.appendChild(deleteSpan);
            }
            if (deleteVersions && keepVersions) {
                cubeVersions.appendChild(document.createTextNode(' | '));
            }
            if (keepVersions) {
                const keepSpan = document.createElement('span');
                keepSpan.className = 'to-keep';
                keepSpan.textContent = 'Keep: v' + keepVersions;
                cubeVersions.appendChild(keepSpan);
            }

            cubeInfo.appendChild(cubeVersions);
            cubeRow.appendChild(cubeInfo);

            previewTable.appendChild(cubeRow);
        });

        // Set up select all checkbox (clone to remove old listeners)
        const selectAllCheckbox = document.getElementById('select-all-cubes');
        if (selectAllCheckbox) {
            const newCheckbox = selectAllCheckbox.cloneNode(true);
            selectAllCheckbox.parentNode.replaceChild(newCheckbox, selectAllCheckbox);
            newCheckbox.checked = true;
            newCheckbox.addEventListener('change', (e) => {
                const checkboxes = previewTable.querySelectorAll('.cube-checkbox');
                checkboxes.forEach(cb => {
                    cb.checked = e.target.checked;
                    if (e.target.checked) {
                        state.selectedCubesForDeletion.add(cb.dataset.baseUri);
                    } else {
                        state.selectedCubesForDeletion.delete(cb.dataset.baseUri);
                    }
                });
                updateSelectionCount();
            });
        }

        updateSelectionCount();

        // Update stats safely
        if (statsGrid) {
            clearElement(statsGrid);

            const keepStat = document.createElement('div');
            keepStat.className = 'stat';
            const keepValue = document.createElement('span');
            keepValue.className = 'stat-value text-success';
            keepValue.textContent = state.cubesToKeep.length;
            keepStat.appendChild(keepValue);
            const keepLabel = document.createElement('span');
            keepLabel.className = 'stat-label';
            keepLabel.textContent = 'Versions to Keep';
            keepStat.appendChild(keepLabel);
            statsGrid.appendChild(keepStat);

            const deleteStat = document.createElement('div');
            deleteStat.className = 'stat';
            const deleteValue = document.createElement('span');
            deleteValue.className = 'stat-value text-danger';
            deleteValue.textContent = state.cubesToDelete.length;
            deleteStat.appendChild(deleteValue);
            const deleteLabel = document.createElement('span');
            deleteLabel.className = 'stat-label';
            deleteLabel.textContent = 'Versions to Delete';
            deleteStat.appendChild(deleteLabel);
            statsGrid.appendChild(deleteStat);

            const cubesStat = document.createElement('div');
            cubesStat.className = 'stat';
            const cubesValue = document.createElement('span');
            cubesValue.className = 'stat-value';
            cubesValue.textContent = Object.keys(cubeGroups).length;
            cubesStat.appendChild(cubesValue);
            const cubesLabel = document.createElement('span');
            cubesLabel.className = 'stat-label';
            cubesLabel.textContent = 'Base Cubes';
            cubesStat.appendChild(cubesLabel);
            statsGrid.appendChild(cubesStat);
        }

        // Update versions to keep display
        const previewVersionsKeep = document.getElementById('preview-versions-keep');
        if (previewVersionsKeep) {
            previewVersionsKeep.textContent = state.versionsToKeep;
        }

        goToWizardStep(3);

    } catch (error) {
        clearElement(previewTable);
        const errorP = document.createElement('p');
        errorP.className = 'text-danger';
        errorP.textContent = 'Error: ' + error.message;
        previewTable.appendChild(errorP);
        console.error('Preview error:', error);
    }
}

function getBaseCubeUri(cubeUri) {
    // Extract base URI by removing version number at the end
    // e.g., "https://example.org/cube/1" -> "https://example.org/cube"
    const match = cubeUri.match(/^(.+)\/\d+$/);
    return match ? match[1] : cubeUri;
}

function updateSelectionCount() {
    const countEl = document.getElementById('selected-count');
    const previewTable = document.getElementById('deletion-preview-table');
    if (countEl && previewTable) {
        const totalCubes = previewTable.querySelectorAll('.cube-checkbox').length;
        const selectedCubes = state.selectedCubesForDeletion.size;
        countEl.textContent = selectedCubes + ' of ' + totalCubes + ' cubes selected';
    }
}

function updateSelectAllCheckbox() {
    const selectAllCheckbox = document.getElementById('select-all-cubes');
    const previewTable = document.getElementById('deletion-preview-table');
    if (selectAllCheckbox && previewTable) {
        const totalCubes = previewTable.querySelectorAll('.cube-checkbox').length;
        const selectedCubes = state.selectedCubesForDeletion.size;
        selectAllCheckbox.checked = selectedCubes === totalCubes;
        selectAllCheckbox.indeterminate = selectedCubes > 0 && selectedCubes < totalCubes;
    }
}

async function wizardExecuteDeletion() {
    const progressContainer = document.getElementById('deletion-progress');
    const logContainer = document.getElementById('deletion-log');
    const logContent = document.getElementById('log-content');
    const queueList = document.getElementById('deletion-queue-list');
    const btn = document.getElementById('btn-execute-deletion');

    if (!progressContainer || !logContainer) return;

    progressContainer.classList.remove('hidden');
    logContainer.classList.remove('hidden');
    btn.disabled = true;

    try {

    const isDryRun = state.mode === 'dryrun';

    // Filter cubes to delete based on selection
    const selectedCubesToDelete = state.cubesToDelete.filter(cube => {
        const baseUri = getBaseCubeUri(cube.cube);
        return state.selectedCubesForDeletion.has(baseUri);
    });

    if (selectedCubesToDelete.length === 0) {
        alert('No cubes selected for deletion. Please select at least one cube.');
        btn.disabled = false;
        return;
    }

    // Render deletion queue safely
    if (queueList) {
        clearElement(queueList);
        selectedCubesToDelete.forEach((cube, i) => {
            const div = document.createElement('div');
            div.className = 'queue-item';
            div.id = 'queue-item-' + i;

            const infoDiv = document.createElement('div');
            infoDiv.className = 'queue-item-info';

            const title = document.createElement('div');
            title.className = 'queue-item-title';
            title.textContent = getShortUri(cube.cube);
            infoDiv.appendChild(title);

            const meta = document.createElement('div');
            meta.className = 'queue-item-meta';
            meta.textContent = 'Version ' + cube.version;
            infoDiv.appendChild(meta);

            div.appendChild(infoDiv);

            const status = document.createElement('div');
            status.className = 'queue-item-status';
            status.textContent = 'Pending';
            div.appendChild(status);

            queueList.appendChild(div);
        });
    }

    const logs = [];
    const addLog = (msg) => {
        const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
        logs.push('[' + timestamp + '] ' + msg);
        if (logContent) logContent.textContent = logs.join('\n');
    };

    if (isDryRun) {
        addLog('=== DRY RUN MODE ===');
        addLog('No actual changes will be made.');
        addLog('');
    }

    addLog('Starting ' + (isDryRun ? 'dry run' : 'deletion') + ' process...');
    addLog('Selected cubes: ' + selectedCubesToDelete.length);

    const total = selectedCubesToDelete.length;
    let deleted = 0;
    let errors = 0;
    let totalTriples = 0;

    const config = getConnectionConfig();

    // Get backup options from checkboxes
    const includeMetadataInBackup = document.getElementById('include-metadata-backup')?.checked !== false;
    const includeOrphansInBackup = document.getElementById('include-orphans-backup')?.checked !== false;
    const cleanupOrphansAfter = document.getElementById('cleanup-orphans')?.checked !== false;

    // STEP 0: Create ONE consolidated backup of ALL selected cubes before deletion
    if (!isDryRun) {
        addLog('');
        addLog('Creating consolidated backup of all ' + total + ' cube versions...');
        if (includeMetadataInBackup) {
            addLog('  (Including metadata: cube properties, SHACL shapes)');
        } else {
            addLog('  (Metadata excluded: backing up observations only)');
        }
        if (includeOrphansInBackup) {
            addLog('  (Including orphan triples in backup)');
        }
        updateDeletionProgress('Creating backup...', 0, total);

        let consolidatedBackupId = null;
        try {
            const cubeUris = selectedCubesToDelete.map(c => c.cube);
            const backupResponse = await authFetch('/api/backup/create-multi', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ...config,
                    cubeUris: cubeUris,
                    graphUri: state.wizardGraph,
                    includeMetadata: includeMetadataInBackup,
                    includeOrphans: includeOrphansInBackup
                })
            });

            if (!backupResponse.ok) {
                const errBody = await backupResponse.json().catch(() => ({}));
                throw new Error(errBody.error || ('Backup request failed with status ' + backupResponse.status));
            }
            const backupResult = await backupResponse.json();
            if (backupResult.success && backupResult.backupId) {
                consolidatedBackupId = backupResult.backupId;
                state.deletionResults.backupIds.push(backupResult.backupId);
                addLog('Consolidated backup created: ' + backupResult.backupId);
                addLog('  - Cubes backed up: ' + backupResult.cubeCount);
                addLog('  - Total triples: ' + backupResult.totalTripleCount);
                if (backupResult.orphanCount > 0) {
                    addLog('  - Orphan triples: ' + backupResult.orphanCount);
                }
                addLog('  - File size: ' + formatBytes(backupResult.zipFileSize));

                // Store backup info for auto-download later
                state.deletionResults.consolidatedBackupId = consolidatedBackupId;
                state.deletionResults.consolidatedBackupFilename = backupResult.zipFilename;
            } else {
                addLog('ERROR: Backup failed - ' + (backupResult.error || 'Unknown error'));
                addLog('ABORTING deletion to prevent data loss.');
                btn.disabled = false;
                return;
            }
        } catch (backupError) {
            addLog('ERROR: Backup error - ' + backupError.message);
            addLog('ABORTING deletion to prevent data loss.');
            btn.disabled = false;
            return;
        }
    } else {
        addLog('');
        addLog('[DRY RUN] Would create backup of ' + total + ' cube versions');
        if (includeMetadataInBackup) {
            addLog('[DRY RUN] (Would include metadata)');
        } else {
            addLog('[DRY RUN] (Would exclude metadata - observations only)');
        }
        if (includeOrphansInBackup) {
            addLog('[DRY RUN] (Would include orphan triples)');
        }
    }

    addLog('');
    addLog('Starting cube ' + (isDryRun ? 'analysis' : 'deletions') + '...');

    // Now delete each cube (backup already done)
    for (let i = 0; i < selectedCubesToDelete.length; i++) {
        const cube = selectedCubesToDelete[i];
        const queueItem = document.getElementById('queue-item-' + i);

        // Update queue item
        if (queueItem) {
            queueItem.classList.add('processing');
            const statusEl = queueItem.querySelector('.queue-item-status');
            if (statusEl) statusEl.textContent = isDryRun ? 'Analyzing...' : 'Deleting...';
        }

        updateDeletionProgress(isDryRun ? 'Analyzing cubes...' : 'Deleting cubes...', i + 1, total);
        addLog('Processing: ' + cube.cube);

        try {
            if (isDryRun) {
                // In dry run mode, just simulate the deletion
                addLog('  [DRY RUN] Would delete observations');
                addLog('  [DRY RUN] Would delete observation links');
                addLog('  [DRY RUN] Would delete metadata');
                deleted++;
                state.deletionResults.deletedCubes.push(cube);
                addLog('  [DRY RUN] Would be deleted');
            } else {
                // Actually delete in execute mode

                // Step 2: Delete observations
                addLog('  Deleting observations...');
                const obsResponse = await authFetch('/api/cubes/delete-observations', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ...config,
                        cubeUri: cube.cube,
                        graphUri: state.wizardGraph,
                        backupId: state.deletionResults.consolidatedBackupId
                    })
                });

                if (!obsResponse.ok) {
                    const errBody = await obsResponse.json().catch(() => ({}));
                    throw new Error(errBody.error || ('Delete observations failed with status ' + obsResponse.status));
                }
                const obsResult = await obsResponse.json();
                totalTriples += obsResult.triplesDeleted || 0;

                // Step 3: Delete observation links
                addLog('  Deleting observation links...');
                const linksResponse = await authFetch('/api/cubes/delete-observation-links', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ...config,
                        cubeUri: cube.cube,
                        graphUri: state.wizardGraph,
                        backupId: state.deletionResults.consolidatedBackupId
                    })
                });

                if (!linksResponse.ok) {
                    const errBody = await linksResponse.json().catch(() => ({}));
                    throw new Error(errBody.error || ('Delete observation links failed with status ' + linksResponse.status));
                }
                const linksResult = await linksResponse.json();
                totalTriples += linksResult.triplesDeleted || 0;

                // Step 4: Delete metadata
                addLog('  Deleting metadata...');
                const metaResponse = await authFetch('/api/cubes/delete-metadata', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ...config,
                        cubeUri: cube.cube,
                        graphUri: state.wizardGraph,
                        backupId: state.deletionResults.consolidatedBackupId
                    })
                });

                if (!metaResponse.ok) {
                    const errBody = await metaResponse.json().catch(() => ({}));
                    throw new Error(errBody.error || ('Delete metadata failed with status ' + metaResponse.status));
                }
                const metaResult = await metaResponse.json();
                totalTriples += metaResult.triplesDeleted || 0;

                deleted++;
                state.deletionResults.deletedCubes.push(cube);
                addLog('  Deleted successfully');
            }

            if (queueItem) {
                queueItem.classList.remove('processing');
                queueItem.classList.add('completed');
                const statusEl = queueItem.querySelector('.queue-item-status');
                if (statusEl) statusEl.textContent = isDryRun ? 'Would Delete' : 'Deleted';
            }

        } catch (error) {
            errors++;
            addLog('  ERROR: ' + error.message);

            if (queueItem) {
                queueItem.classList.remove('processing');
                const statusEl = queueItem.querySelector('.queue-item-status');
                if (statusEl) statusEl.textContent = 'Failed';
            }
        }

        // Small delay between deletions
        await sleep(100);
    }

    state.deletionResults.keptCubes = state.cubesToKeep;
    state.deletionResults.totalTriplesDeleted = totalTriples;

    addLog('');
    if (isDryRun) {
        addLog('=== DRY RUN COMPLETE ===');
        addLog('Would delete: ' + deleted + ' cubes');
        addLog('Errors: ' + errors);
        addLog('');
        addLog('Switch to Execute mode and run again to perform actual deletions.');
    } else {
        addLog('=== DELETION COMPLETE ===');
        addLog('Deleted: ' + deleted + ' cubes');
        addLog('Errors: ' + errors);
        addLog('Total triples removed: ' + totalTriples);

        // Orphan detection and optional cleanup after deletion
        if (cleanupOrphansAfter) {
            addLog('');
            addLog('--- ORPHAN SHAPE CLEANUP ---');
            addLog('Detecting orphan triples (observation sets and SHACL shapes)...');
            try {
                const detectResponse = await authFetch('/api/orphans/detect', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        ...config,
                        graphUri: state.wizardGraph
                    })
                });

                if (detectResponse.ok) {
                    const detectData = await detectResponse.json();
                    const summary = detectData.summary || {};
                    const totalCount = detectData.totalCount || 0;
                    const shapes = detectData.shapes || {};

                    if (totalCount > 0) {
                        // Show orphan counts in the log
                        addLog('Found orphan triples:');
                        if (summary.ObservationSet) addLog('  - Orphan observation sets: ' + summary.ObservationSet);
                        if (summary.NodeShape) addLog('  - Orphan node shapes: ' + summary.NodeShape);
                        if (summary.PropertyShape) addLog('  - Orphan property shapes: ' + summary.PropertyShape);
                        addLog('  Total orphan entities: ' + totalCount);

                        // Show shape-specific details if available
                        if (shapes.orphanShapeCount > 0) {
                            addLog('');
                            addLog('Orphan shape details (comprehensive analysis):');
                            addLog('  - Orphan SHACL shapes: ' + shapes.orphanShapeCount);
                            addLog('  - Total triples to clean (shapes + property shapes + RDF lists): ' + shapes.orphanShapeTriples);
                        }

                        addLog('');
                        addLog('Use the buttons below to preview, clean up, or skip.');

                        // Show the orphan cleanup buttons
                        const orphanActions = document.getElementById('orphan-cleanup-actions');
                        if (orphanActions) {
                            orphanActions.classList.remove('hidden');
                        }

                        // Wait for user decision via buttons
                        const userChoice = await waitForOrphanCleanupDecision();

                        // Hide the buttons after decision
                        if (orphanActions) {
                            orphanActions.classList.add('hidden');
                        }

                        if (userChoice === 'preview') {
                            // User chose to preview first - fetch the CONSTRUCT preview
                            addLog('');
                            addLog('Fetching orphan shape triple preview...');
                            try {
                                const previewResponse = await authFetch('/api/orphans/shapes/preview', {
                                    method: 'POST',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({
                                        ...config,
                                        graphUri: state.wizardGraph
                                    })
                                });

                                if (previewResponse.ok) {
                                    const previewData = await previewResponse.json();
                                    addLog('Preview: ' + previewData.tripleCount + ' triples would be deleted from orphan shapes.');

                                    // Show first few triples as sample
                                    if (previewData.triples) {
                                        const lines = previewData.triples.split('\n').filter(function(l) { return l.trim(); });
                                        const sampleSize = Math.min(lines.length, 10);
                                        if (sampleSize > 0) {
                                            addLog('Sample triples (first ' + sampleSize + ' of ' + lines.length + '):');
                                            for (var pi = 0; pi < sampleSize; pi++) {
                                                addLog('  ' + lines[pi]);
                                            }
                                            if (lines.length > sampleSize) {
                                                addLog('  ... and ' + (lines.length - sampleSize) + ' more triples');
                                            }
                                        }
                                    }
                                } else {
                                    addLog('WARNING: Preview failed - continuing to cleanup decision.');
                                }
                            } catch (previewError) {
                                addLog('WARNING: Preview error - ' + previewError.message);
                            }

                            addLog('');
                            addLog('Proceed with cleanup? Use the buttons below.');

                            // Show cleanup buttons again for final decision
                            if (orphanActions) {
                                orphanActions.classList.remove('hidden');
                                // Hide preview button since we already previewed
                                var previewBtn = document.getElementById('btn-preview-orphans');
                                if (previewBtn) previewBtn.classList.add('hidden');
                            }

                            const finalChoice = await waitForOrphanCleanupDecision();

                            if (orphanActions) {
                                orphanActions.classList.add('hidden');
                                // Restore preview button visibility for next run
                                if (previewBtn) previewBtn.classList.remove('hidden');
                            }

                            if (finalChoice === 'cleanup') {
                                await performOrphanCleanup(config, addLog);
                            } else {
                                addLog('Orphan cleanup skipped by user after preview.');
                            }
                        } else if (userChoice === 'cleanup') {
                            await performOrphanCleanup(config, addLog);
                        } else {
                            addLog('Orphan cleanup skipped by user.');
                        }
                    } else {
                        addLog('No orphan triples found - graph is clean.');
                    }
                } else {
                    const detectError = await detectResponse.json();
                    addLog('WARNING: Orphan detection failed - ' + (detectError.error || 'Unknown error'));
                }
            } catch (cleanupError) {
                addLog('WARNING: Orphan detection error - ' + cleanupError.message);
            }
        }

        // Auto-download the consolidated backup ZIP
        if (state.deletionResults.consolidatedBackupId) {
            addLog('');
            addLog('Downloading backup file...');
            try {
                // Trigger download via browser
                const downloadUrl = '/api/backup/download/' + encodeURIComponent(state.deletionResults.consolidatedBackupId);
                const link = document.createElement('a');
                link.href = downloadUrl;
                link.download = state.deletionResults.consolidatedBackupFilename || ('backup_' + state.deletionResults.consolidatedBackupId + '.zip');
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                addLog('Backup downloaded: ' + (state.deletionResults.consolidatedBackupFilename || state.deletionResults.consolidatedBackupId));
            } catch (downloadError) {
                addLog('WARNING: Auto-download failed - ' + downloadError.message);
                addLog('You can manually download from the Backups section.');
            }
        }
    }

    if (deleted === 0 && errors > 0) {
        addLog('ERROR: All deletions failed. No cubes were deleted.');
    }

    // Move to summary step
    setTimeout(() => {
        goToWizardStep(5);
        renderWizardSummary(isDryRun);
    }, 1000);

    } finally {
        btn.disabled = false;
    }
}

function waitForOrphanCleanupDecision() {
    return new Promise((resolve) => {
        const cleanupBtn = document.getElementById('btn-cleanup-orphans');
        const skipBtn = document.getElementById('btn-skip-orphan-cleanup');
        const previewBtn = document.getElementById('btn-preview-orphans');

        // If no buttons exist in the DOM, resolve immediately with 'skip'
        if (!cleanupBtn && !skipBtn && !previewBtn) {
            resolve('skip');
            return;
        }

        let timer = null;

        function cleanup() {
            if (timer) clearTimeout(timer);
            if (cleanupBtn) cleanupBtn.removeEventListener('click', onCleanup);
            if (skipBtn) skipBtn.removeEventListener('click', onSkip);
            if (previewBtn) previewBtn.removeEventListener('click', onPreview);
        }

        function onCleanup() {
            cleanup();
            resolve('cleanup');
        }

        function onSkip() {
            cleanup();
            resolve('skip');
        }

        function onPreview() {
            cleanup();
            resolve('preview');
        }

        if (cleanupBtn) cleanupBtn.addEventListener('click', onCleanup);
        if (skipBtn) skipBtn.addEventListener('click', onSkip);
        if (previewBtn) previewBtn.addEventListener('click', onPreview);

        // Safety timeout: auto-skip after 5 minutes to prevent permanent hang
        timer = setTimeout(() => {
            cleanup();
            resolve('skip');
        }, 300000);
    });
}

/**
 * Performs the actual orphan cleanup: calls the cleanup API, logs results,
 * runs verification via shape count, and stores results in state.
 */
async function performOrphanCleanup(config, addLog) {
    addLog('');
    addLog('Cleaning up orphan triples (observation sets + SHACL shapes)...');
    try {
        const cleanupResponse = await authFetch('/api/orphans/cleanup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...config,
                graphUri: state.wizardGraph
            })
        });

        if (cleanupResponse.ok) {
            const cleanupData = await cleanupResponse.json();
            const removed = cleanupData.removed || {};
            const totalRemoved = cleanupData.totalRemoved || 0;
            const verification = cleanupData.verification || {};

            addLog('Orphan cleanup completed:');
            for (const [type, count] of Object.entries(removed)) {
                if (count > 0) addLog('  - Removed ' + count + ' ' + type);
            }
            addLog('  Total removed: ' + totalRemoved + ' orphan triples');

            // Show shape-specific verification results
            if (verification.shapesRemoved !== undefined) {
                addLog('');
                addLog('Shape cleanup verification:');
                addLog('  - Shapes removed: ' + verification.shapesRemoved);
                addLog('  - Shape triples cleaned: ' + verification.shapeTriplesCleaned);
                addLog('  - Remaining orphan shapes: ' + verification.remainingOrphanShapes);
                addLog('  - Remaining orphan shape triples: ' + verification.remainingOrphanShapeTriples);

                if (verification.remainingOrphanShapes === 0) {
                    addLog('  Verification: PASSED - all orphan shapes cleaned successfully.');
                } else {
                    addLog('  Verification: WARNING - ' + verification.remainingOrphanShapes + ' orphan shapes still remain.');
                    addLog('  This may require manual review in the Query Editor.');
                }
            }

            // Store results in state for summary
            state.deletionResults.orphanCleanupPerformed = true;
            state.deletionResults.orphanShapesCleaned = verification.shapesRemoved || 0;
            state.deletionResults.orphanShapeTriplesCleaned = verification.shapeTriplesCleaned || totalRemoved;
        } else {
            const cleanupError = await cleanupResponse.json();
            addLog('WARNING: Orphan cleanup failed - ' + (cleanupError.error || 'Unknown error'));
        }
    } catch (cleanupError) {
        addLog('WARNING: Orphan cleanup error - ' + cleanupError.message);
    }
}

function updateDeletionProgress(step, current, total) {
    const stepEl = document.getElementById('deletion-step');
    const counterEl = document.getElementById('deletion-counter');
    const progressFill = document.getElementById('deletion-progress-fill');

    if (stepEl) stepEl.textContent = step;
    if (counterEl) counterEl.textContent = current + ' / ' + total;
    if (progressFill) progressFill.style.width = (current / total * 100) + '%';
}

function renderWizardSummary(isDryRun = false) {
    const timestampEl = document.getElementById('summary-timestamp');
    const statsGrid = document.getElementById('wizard-summary-stats');
    const deletedList = document.getElementById('summary-deleted-list');
    const keptList = document.getElementById('summary-kept-list');

    if (timestampEl) {
        timestampEl.textContent = (isDryRun ? 'Dry Run ' : '') + 'Completed at ' + new Date().toLocaleString();
    }

    if (statsGrid) {
        clearElement(statsGrid);

        const stats = isDryRun ? [
            { value: state.deletionResults.deletedCubes.length, label: 'Would Delete', className: 'text-warning' },
            { value: state.deletionResults.keptCubes.length, label: 'Would Keep', className: 'text-success' },
            { value: '-', label: 'Triples (N/A)', className: '' },
            { value: '0', label: 'Backups (Dry Run)', className: '' }
        ] : [
            { value: state.deletionResults.deletedCubes.length, label: 'Versions Deleted', className: 'text-danger' },
            { value: state.deletionResults.keptCubes.length, label: 'Versions Preserved', className: 'text-success' },
            { value: state.deletionResults.totalTriplesDeleted.toLocaleString(), label: 'Triples Removed', className: '' },
            { value: state.deletionResults.backupIds.length, label: 'Backups Created', className: '' },
            { value: state.deletionResults.orphanCleanupPerformed
                ? state.deletionResults.orphanShapesCleaned
                : 'N/A',
              label: 'Orphan Shapes Cleaned', className: state.deletionResults.orphanCleanupPerformed ? 'text-success' : '' },
            { value: state.deletionResults.orphanCleanupPerformed
                ? state.deletionResults.orphanShapeTriplesCleaned.toLocaleString()
                : 'Skipped',
              label: 'Orphan Triples Removed', className: '' }
        ];

        stats.forEach(stat => {
            const div = document.createElement('div');
            div.className = 'stat';

            const valueSpan = document.createElement('span');
            valueSpan.className = 'stat-value ' + stat.className;
            valueSpan.textContent = stat.value;
            div.appendChild(valueSpan);

            const labelSpan = document.createElement('span');
            labelSpan.className = 'stat-label';
            labelSpan.textContent = stat.label;
            div.appendChild(labelSpan);

            statsGrid.appendChild(div);
        });
    }

    if (deletedList) {
        clearElement(deletedList);
        const ul = document.createElement('ul');
        ul.className = 'detail-list';
        state.deletionResults.deletedCubes.forEach(c => {
            const li = document.createElement('li');
            li.textContent = getShortUri(c.cube) + ' (v' + c.version + ')';
            ul.appendChild(li);
        });
        deletedList.appendChild(ul);
    }

    if (keptList) {
        clearElement(keptList);
        const ul = document.createElement('ul');
        ul.className = 'detail-list';
        state.deletionResults.keptCubes.forEach(c => {
            const li = document.createElement('li');
            li.textContent = getShortUri(c.cube) + ' (v' + c.version + ')';
            ul.appendChild(li);
        });
        keptList.appendChild(ul);
    }
}

function exportDeletionReport() {
    const report = {
        exportedAt: new Date().toISOString(),
        graph: state.wizardGraph,
        deletedCubes: state.deletionResults.deletedCubes,
        keptCubes: state.deletionResults.keptCubes,
        totalTriplesDeleted: state.deletionResults.totalTriplesDeleted,
        backupIds: state.deletionResults.backupIds,
        orphanCleanup: {
            performed: state.deletionResults.orphanCleanupPerformed,
            shapesCleaned: state.deletionResults.orphanShapesCleaned,
            shapeTriplesCleaned: state.deletionResults.orphanShapeTriplesCleaned
        }
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'deletion-report-' + new Date().toISOString().split('T')[0] + '.json';
    a.click();
    URL.revokeObjectURL(url);
}

// ============================================================================
// Query Editor
// ============================================================================

function initQueryEditor() {
    // Template selector
    const templateSelect = document.getElementById('query-template');
    if (templateSelect) {
        templateSelect.addEventListener('change', loadQueryTemplate);
    }

    // Load template button
    const loadTemplateBtn = document.getElementById('btn-load-template');
    if (loadTemplateBtn) {
        loadTemplateBtn.addEventListener('click', loadQueryTemplate);
    }

    // Execute button
    const executeBtn = document.getElementById('btn-execute-query');
    if (executeBtn) {
        executeBtn.addEventListener('click', executeQuery);
    }

    // Clear button
    const clearBtn = document.getElementById('btn-clear-query');
    if (clearBtn) {
        clearBtn.addEventListener('click', clearQuery);
    }

    // Graph browse button
    const browseGraphsBtn = document.getElementById('btn-browse-graphs');
    if (browseGraphsBtn) {
        browseGraphsBtn.addEventListener('click', browseGraphs);
    }

    // Cube browse button
    const browseCubesBtn = document.getElementById('btn-browse-cubes');
    if (browseCubesBtn) {
        browseCubesBtn.addEventListener('click', browseCubes);
    }

    // Graph dropdown
    const graphDropdown = document.getElementById('query-graph-dropdown');
    if (graphDropdown) {
        graphDropdown.addEventListener('change', () => {
            const graphInput = document.getElementById('query-graph-uri');
            if (graphInput && graphDropdown.value) {
                graphInput.value = graphDropdown.value;
                state.queryGraph = graphDropdown.value;
            }
            graphDropdown.classList.add('hidden');
        });
    }

    // Cube dropdown
    const cubeDropdown = document.getElementById('query-cube-dropdown');
    if (cubeDropdown) {
        cubeDropdown.addEventListener('change', () => {
            const cubeInput = document.getElementById('query-cube-uri');
            if (cubeInput && cubeDropdown.value) {
                cubeInput.value = cubeDropdown.value;
                state.queryCube = cubeDropdown.value;
            }
            cubeDropdown.classList.add('hidden');
        });
    }
}

function loadQueryTemplate() {
    const templateSelect = document.getElementById('query-template');
    const queryText = document.getElementById('query-text');
    const graphUri = document.getElementById('query-graph-uri')?.value || state.queryGraph;
    const cubeUri = document.getElementById('query-cube-uri')?.value || state.queryCube;

    if (!templateSelect || !queryText) return;

    const template = templateSelect.value;
    // Pass triplestore type to get appropriate query syntax
    const templates = getQueryTemplates(graphUri, cubeUri, state.triplestoreType);

    if (templates[template]) {
        queryText.value = templates[template].query;

        // Set query type radio
        const queryTypeRadios = document.querySelectorAll('input[name="query-type"]');
        queryTypeRadios.forEach(radio => {
            radio.checked = radio.value === templates[template].type;
        });
    }
}

function getQueryTemplates(graphUri, cubeUri, triplestoreType = 'fuseki') {
    // Base templates that work on all triplestores
    const templates = {
        'list-cubes': {
            type: 'select',
            query: 'PREFIX cube: <https://cube.link/>\n\nSELECT ?cube ?version\nWHERE {\n  GRAPH <' + graphUri + '> {\n    ?cube a cube:Cube .\n    BIND(REPLACE(STR(?cube), "^.*/([0-9]+)/?$", "$1") AS ?version)\n  }\n}\nORDER BY ?cube'
        },
        'count-triples': {
            type: 'select',
            query: 'SELECT (COUNT(*) as ?count)\nWHERE {\n  GRAPH <' + graphUri + '> {\n    ?s ?p ?o\n  }\n}'
        },
        'preview-single': {
            type: 'select',
            query: 'PREFIX cube: <https://cube.link/>\n\nSELECT ?p ?o\nWHERE {\n  GRAPH <' + graphUri + '> {\n    <' + (cubeUri || 'ENTER_CUBE_URI') + '> ?p ?o\n  }\n}\nLIMIT 100'
        },
        'preview-deletions': {
            type: 'select',
            query: 'PREFIX cube: <https://cube.link/>\nPREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n\nSELECT ?baseCube ?cube ?version ?rank\n       (IF(?rank <= 2, "KEEP", "DELETE") AS ?action)\nWHERE {\n  {\n    SELECT ?baseCube ?cube ?version\n           (COUNT(?higherVersion) + 1 AS ?rank)\n    WHERE {\n      GRAPH <' + graphUri + '> {\n        ?cube a cube:Cube .\n        BIND(REPLACE(STR(?cube), "^(.*/[^/]+)/[0-9]+/?$", "$1") AS ?baseCube)\n        BIND(xsd:integer(REPLACE(STR(?cube), "^.*/([0-9]+)/?$", "$1")) AS ?version)\n\n        OPTIONAL {\n          ?otherCube a cube:Cube .\n          BIND(REPLACE(STR(?otherCube), "^(.*/[^/]+)/[0-9]+/?$", "$1") AS ?otherBase)\n          BIND(xsd:integer(REPLACE(STR(?otherCube), "^.*/([0-9]+)/?$", "$1")) AS ?higherVersion)\n          FILTER(?otherBase = ?baseCube && ?higherVersion > ?version)\n        }\n      }\n    }\n    GROUP BY ?baseCube ?cube ?version\n  }\n}\nORDER BY ?baseCube DESC(?version)'
        },
        'find-orphans-summary': {
            type: 'select',
            query: 'PREFIX cube: <https://cube.link/>\n\nSELECT ?type (COUNT(*) AS ?count)\nWHERE {\n  GRAPH <' + graphUri + '> {\n    {\n      ?obs a cube:Observation .\n      FILTER NOT EXISTS { ?set cube:observation ?obs }\n      BIND("Orphan Observation" AS ?type)\n    }\n    UNION\n    {\n      ?set a cube:ObservationSet .\n      FILTER NOT EXISTS { ?cube cube:observationSet ?set }\n      BIND("Orphan ObservationSet" AS ?type)\n    }\n  }\n}\nGROUP BY ?type'
        },
        'find-orphan-observations': {
            type: 'select',
            query: 'PREFIX cube: <https://cube.link/>\n\nSELECT ?obs\nWHERE {\n  GRAPH <' + graphUri + '> {\n    ?obs a cube:Observation .\n    FILTER NOT EXISTS { ?set cube:observation ?obs }\n  }\n}\nLIMIT 100'
        },
        'find-orphan-sets': {
            type: 'select',
            query: 'PREFIX cube: <https://cube.link/>\n\nSELECT ?set\nWHERE {\n  GRAPH <' + graphUri + '> {\n    ?set a cube:ObservationSet .\n    FILTER NOT EXISTS { ?cube cube:observationSet ?set }\n  }\n}\nLIMIT 100'
        },
        'delete-orphans': {
            type: 'update',
            query: 'PREFIX cube: <https://cube.link/>\n\n# Delete orphan observations\nDELETE {\n  GRAPH <' + graphUri + '> {\n    ?obs ?p ?o\n  }\n}\nWHERE {\n  GRAPH <' + graphUri + '> {\n    ?obs a cube:Observation .\n    ?obs ?p ?o .\n    FILTER NOT EXISTS { ?set cube:observation ?obs }\n  }\n}'
        },
        'count-orphan-shapes': {
            type: 'select',
            query: 'PREFIX cube: <https://cube.link/>\nPREFIX sh: <http://www.w3.org/ns/shacl#>\nPREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n\n# Query 14: Count orphan shapes - impact assessment\nSELECT\n  (COUNT(DISTINCT ?orphanShape) AS ?orphanShapeCount)\n  (COUNT(DISTINCT ?triple) AS ?totalOrphanTriples)\nWHERE {\n  GRAPH <' + graphUri + '> {\n    ?orphanShape a sh:NodeShape .\n    FILTER NOT EXISTS {\n      ?anyCube cube:observationConstraint ?orphanShape .\n      ?anyCube a cube:Cube .\n    }\n\n    {\n      ?orphanShape ?sp ?so .\n      BIND(CONCAT(STR(?orphanShape), "|", STR(?sp), "|", STR(?so)) AS ?triple)\n    }\n    UNION\n    {\n      ?inS ?inP ?orphanShape .\n      BIND(CONCAT(STR(?inS), "|", STR(?inP), "|", STR(?orphanShape)) AS ?triple)\n    }\n    UNION\n    {\n      ?orphanShape sh:property ?ps .\n      ?ps ?psp ?pso .\n      BIND(CONCAT(STR(?ps), "|", STR(?psp), "|", STR(?pso)) AS ?triple)\n    }\n    UNION\n    {\n      ?orphanShape sh:property ?ps .\n      ?ps sh:in ?list .\n      ?list rdf:rest*/rdf:first ?item .\n      ?list ?lp ?lo .\n      BIND(CONCAT(STR(?list), "|", STR(?lp), "|", STR(?lo)) AS ?triple)\n    }\n  }\n}'
        },
        'find-orphan-shapes': {
            type: 'select',
            query: 'PREFIX cube: <https://cube.link/>\nPREFIX sh: <http://www.w3.org/ns/shacl#>\nPREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\nPREFIX schema: <http://schema.org/>\n\n# Query 11: Find individual orphan shapes with details\nSELECT\n  ?shape\n  ?shapeType\n  (COUNT(DISTINCT ?propShape) AS ?propertyShapeCount)\n  (COUNT(DISTINCT ?allTriple) AS ?estimatedTriples)\nWHERE {\n  GRAPH <' + graphUri + '> {\n    ?shape a sh:NodeShape .\n    FILTER NOT EXISTS {\n      ?anyCube cube:observationConstraint ?shape .\n      ?anyCube a cube:Cube .\n    }\n    OPTIONAL { ?shape rdf:type ?shapeType }\n    OPTIONAL { ?shape sh:property ?propShape }\n    OPTIONAL {\n      {\n        ?shape ?sp ?so .\n        BIND(CONCAT(STR(?shape), "|", STR(?sp), "|", STR(?so)) AS ?allTriple)\n      }\n      UNION\n      {\n        ?shape sh:property ?ps .\n        ?ps ?psp ?pso .\n        BIND(CONCAT(STR(?ps), "|", STR(?psp), "|", STR(?pso)) AS ?allTriple)\n      }\n    }\n  }\n}\nGROUP BY ?shape ?shapeType\nORDER BY ?shape'
        },
        'delete-orphan-shapes': {
            type: 'update',
            query: 'PREFIX cube: <https://cube.link/>\nPREFIX sh: <http://www.w3.org/ns/shacl#>\nPREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n\n# Query 13: Delete orphan shapes (comprehensive)\n# WARNING: This is a destructive operation!\nDELETE {\n  GRAPH <' + graphUri + '> {\n    ?s ?p ?o .\n  }\n}\nWHERE {\n  GRAPH <' + graphUri + '> {\n    ?orphanShape a sh:NodeShape .\n    FILTER NOT EXISTS {\n      ?anyCube cube:observationConstraint ?orphanShape .\n      ?anyCube a cube:Cube .\n    }\n\n    {\n      ?orphanShape ?p ?o .\n      BIND(?orphanShape AS ?s)\n    }\n    UNION\n    {\n      ?s ?p ?orphanShape .\n      BIND(?orphanShape AS ?o)\n    }\n    UNION\n    {\n      ?orphanShape sh:property ?propShape .\n      ?propShape ?p ?o .\n      BIND(?propShape AS ?s)\n    }\n    UNION\n    {\n      ?orphanShape sh:property ?propShape .\n      ?propShape sh:in ?list .\n      ?list rdf:rest*/rdf:first ?item .\n      ?list ?p ?o .\n      BIND(?list AS ?s)\n    }\n  }\n}'
        }
    };

    // Triplestore-specific DELETE queries
    // Stardog requires explicit DELETE and WHERE clauses (no DELETE WHERE shorthand with FILTER)
    // GraphDB and Fuseki support standard SPARQL 1.1 UPDATE

    // Universal delete queries using BIND pattern (works on all triplestores)
    // Uses bidirectional matching and handles SHACL shapes + blank nodes.
    // See: docs/sparql-query-review-2026-02-02.md
    const deleteSingleQuery = '# WARNING: This will delete a single cube version and all related data\n# Works on: Stardog, GraphDB, Fuseki\n# Uses BIND pattern for Stardog compatibility + bidirectional matching\n#\nPREFIX cube: <https://cube.link/>\nPREFIX sh: <http://www.w3.org/ns/shacl#>\nPREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n\nDELETE {\n  GRAPH <' + graphUri + '> {\n    ?s ?p ?o .\n  }\n}\nWHERE {\n  GRAPH <' + graphUri + '> {\n    VALUES ?targetCube { <' + (cubeUri || 'ENTER_CUBE_URI') + '> }\n\n    {\n      # Cube outgoing triples\n      ?targetCube ?p ?o .\n      BIND(?targetCube AS ?s)\n    }\n    UNION\n    {\n      # Cube incoming triples\n      ?s ?p ?targetCube .\n      BIND(?targetCube AS ?o)\n    }\n    UNION\n    {\n      # Blank node metadata\n      ?targetCube ?p1 ?bn .\n      FILTER(isBlank(?bn))\n      ?bn ?p ?o .\n      BIND(?bn AS ?s)\n    }\n    UNION\n    {\n      # SHACL NodeShape outgoing\n      ?targetCube cube:observationConstraint ?shape .\n      ?shape ?p ?o .\n      BIND(?shape AS ?s)\n    }\n    UNION\n    {\n      # SHACL NodeShape incoming\n      ?targetCube cube:observationConstraint ?shape .\n      ?s ?p ?shape .\n      BIND(?shape AS ?o)\n    }\n    UNION\n    {\n      # SHACL PropertyShape\n      ?targetCube cube:observationConstraint ?shape .\n      ?shape sh:property ?propShape .\n      ?propShape ?p ?o .\n      BIND(?propShape AS ?s)\n    }\n    UNION\n    {\n      # RDF Lists in PropertyShapes\n      ?targetCube cube:observationConstraint ?shape .\n      ?shape sh:property ?propShape .\n      ?propShape sh:in ?list .\n      ?list rdf:rest*/rdf:first ?item .\n      ?list ?p ?o .\n      BIND(?list AS ?s)\n    }\n    UNION\n    {\n      # ObservationSet outgoing\n      ?targetCube cube:observationSet ?obsSet .\n      ?obsSet ?p ?o .\n      BIND(?obsSet AS ?s)\n    }\n    UNION\n    {\n      # ObservationSet incoming\n      ?targetCube cube:observationSet ?obsSet .\n      ?s ?p ?obsSet .\n      BIND(?obsSet AS ?o)\n    }\n    UNION\n    {\n      # Observations outgoing\n      ?targetCube cube:observationSet ?obsSet .\n      ?obsSet cube:observation ?obs .\n      ?obs ?p ?o .\n      BIND(?obs AS ?s)\n    }\n    UNION\n    {\n      # Observations incoming\n      ?targetCube cube:observationSet ?obsSet .\n      ?obsSet cube:observation ?obs .\n      ?s ?p ?obs .\n      BIND(?obs AS ?o)\n    }\n  }\n}';

    const deleteOldVersionsQuery = '# WARNING: This will delete all cube versions ranked > 2 (keeps newest 2)\n# Works on: Stardog, GraphDB, Fuseki\n# Uses BIND pattern for Stardog compatibility + bidirectional matching\n# For safe deletion with backups, use the Deletion Wizard instead.\n\nPREFIX cube: <https://cube.link/>\nPREFIX sh: <http://www.w3.org/ns/shacl#>\nPREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\nPREFIX xsd: <http://www.w3.org/2001/XMLSchema#>\n\nDELETE {\n  GRAPH <' + graphUri + '> {\n    ?s ?p ?o .\n  }\n}\nWHERE {\n  GRAPH <' + graphUri + '> {\n    # Subquery: find cubes ranked > 2\n    {\n      SELECT ?cube (COUNT(DISTINCT ?newerCube) AS ?newerCount)\n      WHERE {\n        ?cube a cube:Cube .\n        BIND(REPLACE(STR(?cube), "^(.*/[^/]+)/[0-9]+/?$", "$1") AS ?baseCube)\n        BIND(xsd:integer(REPLACE(STR(?cube), "^.*/([0-9]+)/?$", "$1")) AS ?version)\n        OPTIONAL {\n          ?newerCube a cube:Cube .\n          BIND(REPLACE(STR(?newerCube), "^(.*/[^/]+)/[0-9]+/?$", "$1") AS ?newerBase)\n          BIND(xsd:integer(REPLACE(STR(?newerCube), "^.*/([0-9]+)/?$", "$1")) AS ?newerVersion)\n          FILTER(?newerBase = ?baseCube && ?newerVersion > ?version)\n        }\n      }\n      GROUP BY ?cube\n      HAVING (COUNT(DISTINCT ?newerCube) >= 2)\n    }\n\n    # Delete all related triples\n    {\n      ?cube ?p ?o .\n      BIND(?cube AS ?s)\n    }\n    UNION\n    {\n      ?s ?p ?cube .\n      BIND(?cube AS ?o)\n    }\n    UNION\n    {\n      ?cube ?p1 ?bn .\n      FILTER(isBlank(?bn))\n      ?bn ?p ?o .\n      BIND(?bn AS ?s)\n    }\n    UNION\n    {\n      ?cube cube:observationConstraint ?shape .\n      ?shape ?p ?o .\n      BIND(?shape AS ?s)\n    }\n    UNION\n    {\n      ?cube cube:observationConstraint ?shape .\n      ?s ?p ?shape .\n      BIND(?shape AS ?o)\n    }\n    UNION\n    {\n      ?cube cube:observationConstraint ?shape .\n      ?shape sh:property ?propShape .\n      ?propShape ?p ?o .\n      BIND(?propShape AS ?s)\n    }\n    UNION\n    {\n      ?cube cube:observationSet ?obsSet .\n      ?obsSet ?p ?o .\n      BIND(?obsSet AS ?s)\n    }\n    UNION\n    {\n      ?cube cube:observationSet ?obsSet .\n      ?s ?p ?obsSet .\n      BIND(?obsSet AS ?o)\n    }\n    UNION\n    {\n      ?cube cube:observationSet ?obsSet .\n      ?obsSet cube:observation ?obs .\n      ?obs ?p ?o .\n      BIND(?obs AS ?s)\n    }\n    UNION\n    {\n      ?cube cube:observationSet ?obsSet .\n      ?obsSet cube:observation ?obs .\n      ?s ?p ?obs .\n      BIND(?obs AS ?o)\n    }\n  }\n}';

    // All triplestores now use the same universal query (BIND works everywhere)
    templates['delete-single'] = {
        type: 'update',
        query: deleteSingleQuery
    };

    templates['delete-old-versions'] = {
        type: 'update',
        query: deleteOldVersionsQuery
    };

    return templates;
}

async function executeQuery() {
    const queryText = document.getElementById('query-text');
    const statusBox = document.getElementById('query-status');
    const resultsCard = document.getElementById('query-results-card');
    const resultsCount = document.getElementById('results-count');
    const resultsTime = document.getElementById('results-time');
    const resultsContainer = document.getElementById('query-results');
    const executeBtn = document.getElementById('btn-execute-query');

    if (!queryText || !statusBox) return;

    const query = queryText.value.trim();
    if (!query) {
        statusBox.classList.remove('hidden', 'success');
        statusBox.classList.add('error');
        statusBox.textContent = 'Please enter a query';
        return;
    }

    const queryType = document.querySelector('input[name="query-type"]:checked')?.value || 'select';

    statusBox.classList.remove('hidden', 'success', 'error');
    statusBox.classList.add('loading');
    statusBox.textContent = 'Executing query...';
    executeBtn.disabled = true;

    const startTime = Date.now();

    try {
        const config = getConnectionConfig();
        const response = await authFetch('/api/query/execute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...config,
                triplestoreType: config.type,
                query: query,
                queryType: queryType
            })
        });

        const result = await response.json();
        const elapsed = Date.now() - startTime;

        if (!response.ok) {
            throw new Error(result.error || 'Query failed');
        }

        statusBox.classList.remove('loading');
        statusBox.classList.add('success');
        statusBox.textContent = 'Query executed successfully';

        if (queryType === 'select' && result.results) {
            resultsCard.style.display = 'block';
            const bindings = result.results.bindings || [];
            resultsCount.textContent = bindings.length + ' results';
            resultsTime.textContent = elapsed + 'ms';

            clearElement(resultsContainer);

            if (bindings.length > 0) {
                const vars = result.results.head?.vars || Object.keys(bindings[0]);
                const table = document.createElement('table');

                const thead = document.createElement('thead');
                const headerRow = document.createElement('tr');
                vars.forEach(v => {
                    const th = document.createElement('th');
                    th.textContent = v;
                    headerRow.appendChild(th);
                });
                thead.appendChild(headerRow);
                table.appendChild(thead);

                const tbody = document.createElement('tbody');
                bindings.forEach(row => {
                    const tr = document.createElement('tr');
                    vars.forEach(v => {
                        const td = document.createElement('td');
                        if (row[v]) {
                            if (row[v].type === 'uri') {
                                const span = document.createElement('span');
                                span.className = 'mono';
                                span.title = row[v].value;
                                span.textContent = getShortUri(row[v].value);
                                td.appendChild(span);
                            } else {
                                td.textContent = row[v].value;
                            }
                        }
                        tr.appendChild(td);
                    });
                    tbody.appendChild(tr);
                });
                table.appendChild(tbody);
                resultsContainer.appendChild(table);
            } else {
                const p = document.createElement('p');
                p.className = 'text-muted';
                p.textContent = 'No results found';
                resultsContainer.appendChild(p);
            }
        } else if (queryType === 'update') {
            resultsCard.style.display = 'block';
            resultsCount.textContent = 'Update complete';
            resultsTime.textContent = elapsed + 'ms';

            clearElement(resultsContainer);
            const p = document.createElement('p');
            p.textContent = 'Update query executed successfully.';
            resultsContainer.appendChild(p);

            if (result.message) {
                const msg = document.createElement('p');
                msg.textContent = result.message;
                resultsContainer.appendChild(msg);
            }
        }

    } catch (error) {
        statusBox.classList.remove('loading');
        statusBox.classList.add('error');
        statusBox.textContent = 'Query failed: ' + error.message;
        resultsCard.style.display = 'none';
    } finally {
        executeBtn.disabled = false;
    }
}

function clearQuery() {
    const queryText = document.getElementById('query-text');
    const statusBox = document.getElementById('query-status');
    const resultsCard = document.getElementById('query-results-card');
    const templateSelect = document.getElementById('query-template');

    if (queryText) queryText.value = '';
    if (statusBox) statusBox.classList.add('hidden');
    if (resultsCard) resultsCard.style.display = 'none';
    if (templateSelect) templateSelect.value = 'custom';
}

async function browseGraphs() {
    const dropdown = document.getElementById('query-graph-dropdown');
    const btn = document.getElementById('btn-browse-graphs');

    if (!dropdown) return;

    btn.disabled = true;
    dropdown.classList.remove('hidden');

    clearElement(dropdown);
    const loadingOpt = document.createElement('option');
    loadingOpt.value = '';
    loadingOpt.textContent = 'Loading...';
    dropdown.appendChild(loadingOpt);

    try {
        const config = getConnectionConfig();
        const response = await authFetch('/api/query/graphs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });

        const result = await response.json();

        clearElement(dropdown);
        const defaultOpt = document.createElement('option');
        defaultOpt.value = '';
        defaultOpt.textContent = '-- Select a graph --';
        dropdown.appendChild(defaultOpt);

        if (result.graphs && result.graphs.length > 0) {
            result.graphs.forEach(graph => {
                const opt = document.createElement('option');
                opt.value = graph;
                opt.textContent = graph;
                dropdown.appendChild(opt);
            });
        }
    } catch (error) {
        clearElement(dropdown);
        const errorOpt = document.createElement('option');
        errorOpt.value = '';
        errorOpt.textContent = 'Error loading graphs';
        dropdown.appendChild(errorOpt);
    } finally {
        btn.disabled = false;
    }
}

async function browseCubes() {
    const dropdown = document.getElementById('query-cube-dropdown');
    const btn = document.getElementById('btn-browse-cubes');
    const graphUri = document.getElementById('query-graph-uri')?.value || state.queryGraph;

    if (!dropdown) return;

    btn.disabled = true;
    dropdown.classList.remove('hidden');

    clearElement(dropdown);
    const loadingOpt = document.createElement('option');
    loadingOpt.value = '';
    loadingOpt.textContent = 'Loading...';
    dropdown.appendChild(loadingOpt);

    try {
        const config = getConnectionConfig();
        const response = await authFetch('/api/query/cubes', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...config,
                graphUri: graphUri
            })
        });

        const result = await response.json();

        clearElement(dropdown);
        const defaultOpt = document.createElement('option');
        defaultOpt.value = '';
        defaultOpt.textContent = '-- Select a cube --';
        dropdown.appendChild(defaultOpt);

        if (result.cubes && result.cubes.length > 0) {
            result.cubes.forEach(cube => {
                const opt = document.createElement('option');
                opt.value = cube;
                opt.textContent = getShortUri(cube);
                dropdown.appendChild(opt);
            });
        }
    } catch (error) {
        clearElement(dropdown);
        const errorOpt = document.createElement('option');
        errorOpt.value = '';
        errorOpt.textContent = 'Error loading cubes';
        dropdown.appendChild(errorOpt);
    } finally {
        btn.disabled = false;
    }
}

// ============================================================================
// Backups Section
// ============================================================================

function initBackupsSection() {
    // Refresh backups button
    const refreshBtn = document.getElementById('btn-refresh-backups');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadBackupList);
    }

    // Restore backup button
    const restoreBtn = document.getElementById('btn-restore-backup');
    if (restoreBtn) {
        restoreBtn.addEventListener('click', restoreBackup);
    }

    // Export backup button
    const exportBtn = document.getElementById('btn-export-backup');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportBackup);
    }

    // Delete backup button
    const deleteBtn = document.getElementById('btn-delete-backup');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', deleteBackup);
    }

    // File upload
    const selectFileBtn = document.getElementById('btn-select-backup-file');
    const fileInput = document.getElementById('backup-file-input');
    const uploadArea = document.getElementById('backup-upload-area');

    if (selectFileBtn && fileInput) {
        selectFileBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', handleBackupFileSelect);
    }

    if (uploadArea) {
        uploadArea.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadArea.classList.add('dragover');
        });
        uploadArea.addEventListener('dragleave', () => {
            uploadArea.classList.remove('dragover');
        });
        uploadArea.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadArea.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                handleBackupFileUpload(e.dataTransfer.files[0]);
            }
        });
    }

    // Import backup button
    const importBtn = document.getElementById('btn-import-backup');
    if (importBtn) {
        importBtn.addEventListener('click', importBackupFile);
    }

    // Cancel import button
    const cancelBtn = document.getElementById('btn-cancel-import');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', cancelBackupImport);
    }
}

async function loadBackupList() {
    const listContainer = document.getElementById('backup-list');
    const previewCard = document.getElementById('backup-preview-card');

    if (!listContainer) return;

    clearElement(listContainer);
    const loadingP = document.createElement('p');
    loadingP.className = 'placeholder-text';
    loadingP.textContent = 'Loading backups...';
    listContainer.appendChild(loadingP);

    if (previewCard) previewCard.style.display = 'none';

    try {
        const response = await authFetch('/api/backup/list');
        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to load backups');
        }

        state.backups = result.backups || [];

        clearElement(listContainer);

        if (state.backups.length === 0) {
            const p = document.createElement('p');
            p.className = 'placeholder-text';
            p.textContent = 'No backups found';
            listContainer.appendChild(p);
            return;
        }

        state.backups.forEach(backup => {
            const div = document.createElement('div');
            div.className = 'backup-item';
            div.dataset.backupId = backup.backupId;

            const infoDiv = document.createElement('div');
            infoDiv.className = 'backup-info';

            const title = document.createElement('div');
            title.className = 'backup-title';
            // Support multi-cube backups
            if (backup.cubes && backup.cubes.length > 1) {
                title.textContent = `${backup.cubes.length} cubes`;
            } else {
                title.textContent = getShortUri(backup.cubeUri || (backup.cubes && backup.cubes[0]?.uri));
            }
            infoDiv.appendChild(title);

            const meta = document.createElement('div');
            meta.className = 'backup-meta';
            meta.textContent = new Date(backup.createdAt).toLocaleString();
            infoDiv.appendChild(meta);

            div.appendChild(infoDiv);

            const sizeSpan = document.createElement('div');
            sizeSpan.className = 'backup-size';
            // Use zipFileSize if available, otherwise fileSize
            const size = backup.zipFileSize || backup.fileSize || 0;
            sizeSpan.textContent = formatBytes(size);
            div.appendChild(sizeSpan);

            div.addEventListener('click', () => selectBackup(backup.backupId));
            listContainer.appendChild(div);
        });

    } catch (error) {
        clearElement(listContainer);
        const p = document.createElement('p');
        p.className = 'placeholder-text text-danger';
        p.textContent = 'Error: ' + error.message;
        listContainer.appendChild(p);
    }
}

function selectBackup(backupId) {
    state.selectedBackupId = backupId;
    state.selectedCubesToRestore = []; // Reset cube selection

    // Update selection UI
    const items = document.querySelectorAll('.backup-item');
    items.forEach(item => {
        item.classList.toggle('selected', item.dataset.backupId === backupId);
    });

    // Show preview card
    const previewCard = document.getElementById('backup-preview-card');
    const previewInfo = document.getElementById('backup-preview-info');

    if (previewCard) previewCard.style.display = 'block';

    const backup = state.backups.find(b => b.backupId === backupId);
    if (previewInfo && backup) {
        clearElement(previewInfo);

        const size = backup.zipFileSize || backup.fileSize || 0;
        const hasMutipleCubes = backup.cubes && backup.cubes.length > 1;

        // Basic info fields
        const fields = [
            { label: 'Graph', value: backup.graphUri },
            { label: 'Created', value: new Date(backup.createdAt).toLocaleString() },
            { label: 'Size', value: formatBytes(size) },
            { label: 'Triples', value: backup.tripleCount?.toLocaleString() || '0' },
            { label: 'Metadata', value: backup.includesMetadata !== false ? 'Included' : 'Excluded' }
        ];

        // Show cube info (simple version for single cube)
        if (!hasMutipleCubes) {
            const cubeValue = backup.cubeUri || (backup.cubes && backup.cubes[0]?.uri) || '';
            fields.unshift({ label: 'Cube', value: cubeValue });
        }

        // Add orphan info if present
        if (backup.includesOrphans && backup.orphanTripleCount > 0) {
            fields.push({ label: 'Orphan Triples', value: backup.orphanTripleCount.toLocaleString() });
        }

        fields.forEach(field => {
            const p = document.createElement('p');
            const strong = document.createElement('strong');
            strong.textContent = field.label + ': ';
            p.appendChild(strong);
            p.appendChild(document.createTextNode(field.value));
            previewInfo.appendChild(p);
        });

        // For multi-cube backups, show a list with checkboxes for selective restore
        if (hasMutipleCubes) {
            const cubesSection = document.createElement('div');
            cubesSection.className = 'backup-cubes-section';

            const cubesHeader = document.createElement('p');
            const cubesHeaderStrong = document.createElement('strong');
            cubesHeaderStrong.textContent = 'Cubes in this backup (' + backup.cubes.length + '):';
            cubesHeader.appendChild(cubesHeaderStrong);
            cubesSection.appendChild(cubesHeader);

            const selectAllDiv = document.createElement('div');
            selectAllDiv.className = 'cube-select-all';
            const selectAllCheckbox = document.createElement('input');
            selectAllCheckbox.type = 'checkbox';
            selectAllCheckbox.id = 'backup-select-all-cubes';
            selectAllCheckbox.checked = true;
            selectAllCheckbox.addEventListener('change', (e) => {
                const cubeCheckboxes = document.querySelectorAll('.cube-checkbox');
                cubeCheckboxes.forEach(cb => {
                    cb.checked = e.target.checked;
                });
                updateSelectedCubes();
            });
            const selectAllLabel = document.createElement('label');
            selectAllLabel.htmlFor = 'backup-select-all-cubes';
            selectAllLabel.textContent = ' Select all / Deselect all';
            selectAllDiv.appendChild(selectAllCheckbox);
            selectAllDiv.appendChild(selectAllLabel);
            cubesSection.appendChild(selectAllDiv);

            const cubesList = document.createElement('div');
            cubesList.className = 'cubes-list';

            backup.cubes.forEach((cube, index) => {
                const cubeDiv = document.createElement('div');
                cubeDiv.className = 'cube-item';

                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.className = 'cube-checkbox';
                checkbox.id = 'cube-' + index;
                checkbox.value = cube.uri;
                checkbox.checked = true; // Selected by default
                checkbox.addEventListener('change', updateSelectedCubes);

                const label = document.createElement('label');
                label.htmlFor = 'cube-' + index;
                const cubeName = cube.name || cube.uri.split('/').pop();
                const tripleInfo = cube.tripleCount ? ' (' + cube.tripleCount + ' triples)' : '';
                label.textContent = ' ' + cubeName + tripleInfo;

                cubeDiv.appendChild(checkbox);
                cubeDiv.appendChild(label);
                cubesList.appendChild(cubeDiv);
            });

            cubesSection.appendChild(cubesList);
            previewInfo.appendChild(cubesSection);

            // Initialize selected cubes to all cubes
            state.selectedCubesToRestore = backup.cubes.map(c => c.uri);
        } else {
            // Single cube backup - select it by default
            const cubeUri = backup.cubeUri || (backup.cubes && backup.cubes[0]?.uri);
            if (cubeUri) {
                state.selectedCubesToRestore = [cubeUri];
            }
        }
    }
}

function updateSelectedCubes() {
    const checkboxes = document.querySelectorAll('.cube-checkbox:checked');
    state.selectedCubesToRestore = Array.from(checkboxes).map(cb => cb.value);

    // Update "Select All" checkbox state
    const allCheckboxes = document.querySelectorAll('.cube-checkbox');
    const selectAllCheckbox = document.getElementById('backup-select-all-cubes');
    if (selectAllCheckbox) {
        selectAllCheckbox.checked = checkboxes.length === allCheckboxes.length;
        selectAllCheckbox.indeterminate = checkboxes.length > 0 && checkboxes.length < allCheckboxes.length;
    }
}

async function restoreBackup() {
    if (!state.selectedBackupId) {
        alert('Please select a backup first');
        return;
    }

    // Check if any cubes are selected for multi-cube backups
    if (state.selectedCubesToRestore.length === 0) {
        alert('Please select at least one cube to restore');
        return;
    }

    const targetGraph = document.getElementById('restore-target-graph')?.value || '';
    const progressContainer = document.getElementById('restore-progress');
    const progressFill = document.getElementById('restore-progress-fill');
    const statusEl = document.getElementById('restore-status');

    if (progressContainer) progressContainer.classList.remove('hidden');
    if (progressFill) progressFill.style.width = '0%';
    if (statusEl) statusEl.textContent = 'Restoring backup...';

    try {
        const config = getConnectionConfig();
        const response = await authFetch('/api/backup/restore-to', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...config,
                backupId: state.selectedBackupId,
                graphUri: targetGraph,
                selectedCubes: state.selectedCubesToRestore // Pass selected cubes for selective restore
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Restore failed');
        }

        if (progressFill) progressFill.style.width = '100%';

        // Show detailed restore result
        const cubeCount = result.cubeCount || 1;
        const totalInBackup = result.totalCubesInBackup || 1;
        const tripleCount = result.restoredTriples || 0;
        let message = 'Restored ' + cubeCount + ' cube(s)';
        if (totalInBackup > cubeCount) {
            message += ' of ' + totalInBackup;
        }
        message += ' (' + tripleCount.toLocaleString() + ' triples)';
        if (statusEl) statusEl.textContent = message;

    } catch (error) {
        if (statusEl) statusEl.textContent = 'Restore failed: ' + error.message;
    }
}

async function exportBackup() {
    if (!state.selectedBackupId) {
        alert('Please select a backup first');
        return;
    }

    window.location.href = '/api/backup/' + encodeURIComponent(state.selectedBackupId) + '/export';
}

async function deleteBackup() {
    if (!state.selectedBackupId) {
        alert('Please select a backup first');
        return;
    }

    if (!confirm('Are you sure you want to delete this backup? This cannot be undone.')) {
        return;
    }

    try {
        const response = await authFetch('/api/backup/' + state.selectedBackupId, {
            method: 'DELETE'
        });

        if (!response.ok) {
            const result = await response.json();
            throw new Error(result.error || 'Delete failed');
        }

        state.selectedBackupId = null;
        loadBackupList();

    } catch (error) {
        alert('Failed to delete backup: ' + error.message);
    }
}

function handleBackupFileSelect(e) {
    if (e.target.files.length > 0) {
        handleBackupFileUpload(e.target.files[0]);
    }
}

async function handleBackupFileUpload(file) {
    const uploadPreview = document.getElementById('upload-preview');
    const previewInfo = document.getElementById('upload-preview-info');

    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await authFetch('/api/backup/upload', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Upload failed');
        }

        state.uploadedFileData = result;

        if (uploadPreview) uploadPreview.classList.remove('hidden');
        if (previewInfo) {
            clearElement(previewInfo);

            const fields = [
                { label: 'File', value: file.name },
                { label: 'Format', value: result.format || 'Unknown' }
            ];

            if (result.metadata) {
                fields.push({ label: 'Cube', value: result.metadata.cubeUri || 'Unknown' });
                fields.push({ label: 'Graph', value: result.metadata.graphUri || 'Unknown' });
                // Show orphan information if present
                if (result.metadata.includesOrphans) {
                    fields.push({
                        label: 'Orphan Triples',
                        value: (result.metadata.orphanTripleCount || 0) + ' (will be restored)'
                    });
                }
            }
            fields.push({ label: 'Triples', value: String(result.tripleCount || 0) });

            fields.forEach(field => {
                const p = document.createElement('p');
                const strong = document.createElement('strong');
                strong.textContent = field.label + ': ';
                p.appendChild(strong);
                p.appendChild(document.createTextNode(field.value));
                previewInfo.appendChild(p);
            });
        }

    } catch (error) {
        alert('Failed to upload file: ' + error.message);
    }
}

async function importBackupFile() {
    if (!state.uploadedFileData) {
        alert('No file uploaded');
        return;
    }

    const targetGraph = document.getElementById('import-target-graph')?.value || '';

    try {
        const config = getConnectionConfig();
        const response = await authFetch('/api/backup/import', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ...config,
                tempId: state.uploadedFileData.tempId,
                overrideGraph: targetGraph
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Import failed');
        }

        let message = 'Backup imported successfully!\n\n';
        message += 'Imported ' + result.importedTriples.toLocaleString() + ' triples';
        if (result.cubeCount > 1) {
            message += ' across ' + result.cubeCount + ' cubes';
        }
        if (result.orphanTriples) {
            message += ' (including ' + result.orphanTriples + ' orphan triples)';
        }
        message += '.';
        alert(message);
        cancelBackupImport();

    } catch (error) {
        alert('Import failed: ' + error.message);
    }
}

function cancelBackupImport() {
    state.uploadedFileData = null;
    const uploadPreview = document.getElementById('upload-preview');
    const fileInput = document.getElementById('backup-file-input');

    if (uploadPreview) uploadPreview.classList.add('hidden');
    if (fileInput) fileInput.value = '';
}

// ============================================================================
// Documentation Section
// ============================================================================

function initDocumentation() {
    const docNavBtns = document.querySelectorAll('.doc-nav-btn');
    docNavBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const docId = btn.dataset.doc;

            // Update nav buttons
            docNavBtns.forEach(b => b.classList.toggle('active', b === btn));

            // Update panels
            const panels = document.querySelectorAll('.doc-panel');
            panels.forEach(panel => {
                panel.classList.toggle('active', panel.id === 'doc-' + docId);
            });
        });
    });
}

// ============================================================================
// Utility Functions
// ============================================================================

function getShortUri(uri) {
    if (!uri) return '';
    // Get last 2-3 path segments
    const parts = uri.split('/');
    if (parts.length > 3) {
        return '.../' + parts.slice(-3).join('/');
    }
    return uri;
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

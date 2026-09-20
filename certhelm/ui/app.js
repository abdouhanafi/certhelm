// ===== VIEW SWITCHING (single source of truth, driven by data-view) =====
const VIEW_NAMES = ['dashboard', 'pipeline', 'compliance', 'agents', 'assignments', 'inventory', 'users', 'audit', 'settings'];

function switchView(viewName, opts) {
    opts = opts || {};
    if (VIEW_NAMES.indexOf(viewName) === -1) return;

    VIEW_NAMES.forEach(name => {
        const nav = document.getElementById('nav-' + name);
        const view = document.getElementById('view-' + name);
        if (nav) nav.classList.toggle('active', name === viewName);
        if (view) view.style.display = name === viewName ? 'block' : 'none';
    });

    // The top-bar search box only makes sense while browsing the dashboard's
    // certs/domains/orgs tables — hide it elsewhere instead of leaving a
    // control that silently does nothing.
    const searchBox = document.getElementById('search-box-wrapper');
    if (searchBox) searchBox.style.display = viewName === 'dashboard' ? 'flex' : 'none';

    // skipDataReload: used when we're just jumping to a view we already have fresh
    // data for (e.g. clicking an alert) — avoids an unnecessary reload/flicker.
    if (opts.skipDataReload) {
        if (viewName === 'dashboard') updateSearchPlaceholder();
    } else if (viewName === 'dashboard') {
        loadDashboard();
        updateSearchPlaceholder();
    } else if (viewName === 'pipeline') {
        if (window.lastData) renderPipeline(window.lastData.certs);
    } else if (viewName === 'compliance') {
        renderCompliance();
    } else if (viewName === 'agents') {
        renderAgents();
    } else if (viewName === 'assignments') {
        loadAssignments();
    } else if (viewName === 'inventory') {
        if (window.lastData) renderInventory(window.lastData.certs, window.lastData.organizations);
    } else if (viewName === 'users') {
        if (window.lastData) renderUsers(window.lastData.users);
    } else if (viewName === 'audit') {
        if (window.lastData) renderAudit(window.lastData.audit_logs);
    } else if (viewName === 'settings') {
        if (window.lastData && window.lastData.config) {
            const cfg = window.lastData.config;
            document.getElementById('setting-api-key').value = cfg.api_key_masked || '';
            document.getElementById('setting-api-key').placeholder = cfg.api_key_set ? 'Clé stockée dans Windows Credential Manager' : 'Entrez votre clé API DigiCert';
            document.getElementById('setting-notifications').checked = cfg.notifications_enabled !== false;
            document.getElementById('setting-alert-threshold').value = cfg.alert_threshold_days || DESKTOP_ALERT_THRESHOLD_DAYS;
            document.getElementById('setting-smtp-host').value = cfg.smtp_host || '';
            document.getElementById('setting-smtp-port').value = cfg.smtp_port || '';
            document.getElementById('setting-smtp-user').value = cfg.smtp_user || '';
            document.getElementById('setting-smtp-from').value = cfg.smtp_from || '';
            document.getElementById('setting-smtp-tls').checked = cfg.smtp_use_tls !== false;
            document.getElementById('setting-smtp-recipients').value = (cfg.smtp_recipients || []).join(', ');
            // Password is intentionally never pre-filled back from storage — only the placeholder hints at its state.
            document.getElementById('setting-smtp-password').placeholder = cfg.smtp_password_set ? 'Mot de passe enregistré (laisser vide pour le garder)' : '••••••••';
        }
        loadAgentSettingsInfo();
        loadRenewalSettings();
    }

    // Close the mobile/collapsed-sidebar overlay state if present
    if (window.closeMobileSidebar) window.closeMobileSidebar();
}

document.querySelectorAll('.menu-item[data-view]').forEach(item => {
    item.addEventListener('click', (e) => {
        e.preventDefault();
        switchView(item.dataset.view);
    });
});

window.showToast = function(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if(!container) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '<svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2.5" style="width:16px;height:16px;flex-shrink:0;"><polyline points="20 6 9 17 4 12"></polyline></svg>',
        error:   '<svg viewBox="0 0 24 24" fill="none" stroke="#ef4444" stroke-width="2.5" style="width:16px;height:16px;flex-shrink:0;"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>',
        warning: '<svg viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2.5" style="width:16px;height:16px;flex-shrink:0;"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
        info:    '<svg viewBox="0 0 24 24" fill="none" stroke="#009FDF" stroke-width="2.5" style="width:16px;height:16px;flex-shrink:0;"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>'
    };
    const icon = icons[type] || icons.info;
    toast.innerHTML = `<div class="toast-icon-row">${icon}<span>${message}</span></div><div class="toast-progress"></div>`;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.4s ease-in forwards';
        setTimeout(() => { if(container.contains(toast)) container.removeChild(toast); }, 400);
    }, 4000);
}

if (document.getElementById('settings-form')) {
    document.getElementById('settings-form').addEventListener('submit', (e) => {
        e.preventDefault();

        const thresholdVal = parseInt(document.getElementById('setting-alert-threshold').value, 10);
        DESKTOP_ALERT_THRESHOLD_DAYS = isNaN(thresholdVal) ? DESKTOP_ALERT_THRESHOLD_DAYS : thresholdVal;

        const recipients = document.getElementById('setting-smtp-recipients').value
            .split(',').map(s => s.trim()).filter(Boolean);

        let newConfig = {
            api_key: document.getElementById('setting-api-key').value,
            notifications_enabled: document.getElementById('setting-notifications').checked,
            alert_threshold_days: DESKTOP_ALERT_THRESHOLD_DAYS,
            smtp_host: document.getElementById('setting-smtp-host').value.trim(),
            smtp_port: document.getElementById('setting-smtp-port').value.trim(),
            smtp_user: document.getElementById('setting-smtp-user').value.trim(),
            smtp_password: document.getElementById('setting-smtp-password').value,
            smtp_from: document.getElementById('setting-smtp-from').value.trim(),
            smtp_use_tls: document.getElementById('setting-smtp-tls').checked,
            smtp_recipients: recipients
        };
        if (window.pywebview && window.pywebview.api) {
            window.pywebview.api.save_settings(newConfig).then(res => {
                showToast("Paramètres enregistrés avec succès", "success");
                document.getElementById('setting-smtp-password').value = '';
            });
        }
    });
}

if (document.getElementById('smtp-test-btn')) {
    document.getElementById('smtp-test-btn').addEventListener('click', async () => {
        const btn = document.getElementById('smtp-test-btn');
        const resultEl = document.getElementById('smtp-test-result');
        const recipients = document.getElementById('setting-smtp-recipients').value
            .split(',').map(s => s.trim()).filter(Boolean);

        const smtpConf = {
            smtp_host: document.getElementById('setting-smtp-host').value.trim(),
            smtp_port: document.getElementById('setting-smtp-port').value.trim(),
            smtp_user: document.getElementById('setting-smtp-user').value.trim(),
            smtp_password: document.getElementById('setting-smtp-password').value,
            smtp_from: document.getElementById('setting-smtp-from').value.trim(),
            smtp_use_tls: document.getElementById('setting-smtp-tls').checked,
            smtp_recipients: recipients
        };

        btn.disabled = true;
        const originalText = btn.innerText;
        btn.innerText = 'Envoi en cours...';
        if (resultEl) resultEl.style.display = 'none';

        try {
            const res = await window.pywebview.api.test_smtp_config(smtpConf);
            if (resultEl) {
                resultEl.style.display = 'block';
                resultEl.style.color = res.status === 'success' ? '#10b981' : '#ef4444';
                resultEl.innerText = res.message;
            }
            showToast(res.message, res.status === 'success' ? 'success' : 'error');
        } catch (e) {
            showToast('Erreur lors du test SMTP', 'error');
        }

        btn.disabled = false;
        btn.innerText = originalText;
    });
}

// Initialize Theme
initTheme();

// Screens/windows narrower than this collapse the sidebar by default so the
// data tables keep breathing room — but only as long as the user hasn't
// explicitly chosen a state themselves (their choice always wins after that,
// on any PC/screen, since it's stored per-browser-profile in localStorage).
// Must be declared before initSidebar() runs, since it's read synchronously below.
const SIDEBAR_AUTO_COLLAPSE_WIDTH = 1100;

// Initialize collapsible sidebar
initSidebar();

// Ask for native notification permission once, up front
initDesktopAlerts();

// Replace native <select> dropdowns with themed ones (WebView2 renders the
// native <option> list with the OS's own styling, which can't be themed)
initCustomSelects();

function initCustomSelects() {
    document.querySelectorAll('.custom-select').forEach(container => {
        const trigger = container.querySelector('.custom-select-trigger');
        const label = container.querySelector('.custom-select-label');
        const options = container.querySelectorAll('.custom-select-option');

        trigger.addEventListener('click', (e) => {
            e.stopPropagation();
            const wasOpen = container.classList.contains('open');
            document.querySelectorAll('.custom-select.open').forEach(cs => cs.classList.remove('open'));
            const notifDropdown = document.getElementById('notification-dropdown');
            if (notifDropdown) notifDropdown.classList.remove('active');
            if (!wasOpen) container.classList.add('open');
        });

        options.forEach(opt => {
            opt.addEventListener('click', (e) => {
                e.stopPropagation();
                options.forEach(o => o.classList.remove('active'));
                opt.classList.add('active');
                container.dataset.value = opt.dataset.value;
                label.textContent = opt.textContent;
                container.classList.remove('open');
                container.dispatchEvent(new Event('change'));
            });
        });
    });

    document.addEventListener('click', () => {
        document.querySelectorAll('.custom-select.open').forEach(cs => cs.classList.remove('open'));
    });
}

// ===== DESKTOP ALERTS (native Windows toast via the WebView2 Notification API) =====
// Fires once per certificate per day so it doesn't spam a toast on every refresh/tab switch.
// This only appears on screen if the app is actually running — the backend's own
// plyer-based notification (main.py) and the SMTP alert (also main.py) both cover
// the case where nobody has the window open, so all three layers complement each other.
let DESKTOP_ALERT_THRESHOLD_DAYS = 10; // overridden by saved settings (see settings-form submit / loadDashboard)

async function initDesktopAlerts() {
    if (!('Notification' in window)) return;
    if (Notification.permission === 'default') {
        try { await Notification.requestPermission(); } catch (e) { /* embedded webview may not support the prompt */ }
    }
}

function runDesktopAlertCheck(certs) {
    if (!('Notification' in window) || Notification.permission !== 'granted') return;
    if (!certs || certs.length === 0) return;

    const urgent = certs.filter(c =>
        c.status !== 'pending' &&
        c.days_left !== undefined && c.days_left !== null &&
        c.days_left <= DESKTOP_ALERT_THRESHOLD_DAYS && c.days_left >= 0
    );
    if (urgent.length === 0) return;

    const todayKey = new Date().toISOString().slice(0, 10);
    const sentStorageKey = 'desktop_alert_sent_' + todayKey;
    const alreadySent = new Set(JSON.parse(localStorage.getItem(sentStorageKey) || '[]'));
    const toNotify = urgent.filter(c => !alreadySent.has(c.domain));
    if (toNotify.length === 0) return;

    try {
        if (toNotify.length === 1) {
            const c = toNotify[0];
            new Notification('Certificat SSL à renouveler', {
                body: `${c.domain} expire dans ${c.days_left} jour${c.days_left > 1 ? 's' : ''}.`,
                tag: 'digicert-' + c.domain
            });
        } else {
            const preview = toNotify.slice(0, 5).map(c => `${c.domain} (${c.days_left}j)`).join('\n');
            const extra = toNotify.length > 5 ? `\n+ ${toNotify.length - 5} autre(s)` : '';
            new Notification(`${toNotify.length} certificats SSL à renouveler (≤ ${DESKTOP_ALERT_THRESHOLD_DAYS}j)`, {
                body: preview + extra,
                tag: 'digicert-batch'
            });
        }
    } catch (e) {
        console.warn('Notification desktop indisponible:', e);
        return;
    }

    toNotify.forEach(c => alreadySent.add(c.domain));
    localStorage.setItem(sentStorageKey, JSON.stringify([...alreadySent]));

    // Drop stale day-keys so localStorage doesn't grow forever
    Object.keys(localStorage).forEach(k => {
        if (k.startsWith('desktop_alert_sent_') && k !== sentStorageKey) localStorage.removeItem(k);
    });
}

// ===== COLLAPSIBLE SIDEBAR =====
function initSidebar() {
    const sidebar = document.getElementById('sidebar');
    const toggleBtn = document.getElementById('sidebar-toggle');
    if (!sidebar || !toggleBtn) return;

    function applyState() {
        const stored = localStorage.getItem('sidebar_collapsed');
        const collapsed = stored !== null ? (stored === 'true') : (window.innerWidth < SIDEBAR_AUTO_COLLAPSE_WIDTH);
        sidebar.classList.toggle('collapsed', collapsed);
    }

    applyState();
    window.addEventListener('resize', () => {
        // Only auto-react to resizes while the user hasn't set an explicit preference
        if (localStorage.getItem('sidebar_collapsed') === null) applyState();
    });

    toggleBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const isCollapsed = sidebar.classList.toggle('collapsed');
        localStorage.setItem('sidebar_collapsed', isCollapsed);
    });
}

// XSS Protection: Sanitize all dynamic content before HTML injection
function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

let allData = [];
let allDomains = [];
let allOrgs = [];
let currentFilterStatus = 'all';

// Avatars are drawn locally (initials on a colour derived from the name): no request ever
// leaves the machine, so user names are not sent to a third-party avatar service.
function generateAvatar(name) {
    const unassigned = !name || name === 'Non assigné';
    const label = unassigned ? 'NA'
        : (String(name).trim().split(/[\s@._-]+/).filter(Boolean).slice(0, 2)
            .map(p => (p.match(/[\p{L}\p{N}]/u) || [''])[0]).join('').toUpperCase() || '?');
    let hash = 0;
    for (const ch of String(name || '')) hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
    const bg = unassigned ? '#374151' : `hsl(${hash % 360}, 45%, 40%)`;
    const fg = unassigned ? '#9ca3af' : '#ffffff';
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32"><rect width="32" height="32" rx="16" fill="${bg}"/>` +
                `<text x="16" y="21" font-family="sans-serif" font-size="13" font-weight="600" text-anchor="middle" fill="${fg}">${label}</text></svg>`;
    return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
}

function updateApiBadge(status) {
    const badge = document.getElementById('api-status-badge');
    if (!badge) return;
    if (status === "Connected") {
        badge.innerText = 'API En Ligne';
        badge.style.background = 'rgba(16, 185, 129, 0.2)';
        badge.style.color = '#10b981';
    } else {
        badge.innerText = 'Erreur API';
        badge.style.background = 'rgba(239, 68, 68, 0.2)';
        badge.style.color = '#ef4444';
        console.error("API Error: ", status);
    }
}

async function loadDashboard() {
    if (!window.pywebview) return setTimeout(loadDashboard, 100);
    
    // Show skeleton while loading
    showSkeletonCerts();
    
    const hideSplash = () => {
        const splash = document.getElementById('splash-screen');
        if (splash && !splash.classList.contains('hidden')) {
            splash.classList.add('hidden');
            setTimeout(() => { if(splash.parentNode) splash.parentNode.removeChild(splash); }, 700);
        }
    };

    let data;
    try {
        data = await pywebview.api.get_dashboard_data();
    } catch (e) {
        // Never leave the splash screen up for ever: show the app so the error is visible.
        console.error('get_dashboard_data failed', e);
        hideSplash();
        showToast('Impossible de charger les données : ' + (e && e.message ? e.message : e), 'error');
        return;
    }

    // Hide splash screen on first load
    hideSplash();

    updateApiBadge(data.api_status);
    
    const balanceBadge = document.getElementById('balance-badge');
    if (balanceBadge) {
        if (data.balance && data.balance.balance !== undefined) {
            balanceBadge.style.display = 'inline-block';
            balanceBadge.innerText = `Solde: ${data.balance.balance} ${data.balance.currency || 'USD'}`;
        } else {
            balanceBadge.style.display = 'none';
        }
    }

    allData = data.certs || [];
    allDomains = data.domains || [];
    allOrgs = data.organizations || [];

    if (data.config && data.config.alert_threshold_days) {
        DESKTOP_ALERT_THRESHOLD_DAYS = data.config.alert_threshold_days;
    }

    // Count stats
    let totalCount = allData.length;
    let expiringCount = allData.filter(c => c.status !== 'pending' && c.days_left <= 30 && c.days_left > 7).length;
    let criticalCount = allData.filter(c => c.status !== 'pending' && c.days_left <= 7).length;
    let pendingCount = allData.filter(c => c.status === 'pending').length;
    let activeCount = totalCount - expiringCount - criticalCount - pendingCount;

    document.getElementById('stat-total').innerText = totalCount;
    if (document.getElementById('stat-expiring')) document.getElementById('stat-expiring').innerText = expiringCount;
    if (document.getElementById('stat-critical')) document.getElementById('stat-critical').innerText = criticalCount;
    if (document.getElementById('stat-pending')) document.getElementById('stat-pending').innerText = pendingCount;

    // Draw donut chart
    drawDonutChart(activeCount, expiringCount, criticalCount, pendingCount);

    renderDomains(data.domains);
    renderOrgs(data.organizations);
    // Respect any active search/status/team filter for whichever sub-tab is visible
    // (this re-renders that one sub-tab's container on top of the unfiltered pass above)
    applyFilters();
    renderInventory(data.certs, data.organizations);
    renderAudit(data.audit_logs);
    renderUsers(data.users);

    // Render timeline
    renderTimeline(allData);

    // Native desktop alert for certificates expiring soon (see DESKTOP_ALERT_THRESHOLD_DAYS)
    runDesktopAlertCheck(allData);

    window.lastData = data;

    // Refresh pipeline board only if it's the active view (avoids wasted work)
    if (document.getElementById('view-pipeline') && document.getElementById('view-pipeline').style.display !== 'none') {
        renderPipeline(allData);
    }

    // Setup sorting listeners if not already done
    if (!window.sortingInitialized) {
        setupSorting();
        window.sortingInitialized = true;
    }
    updateNotifications(data.notifications || [], data.alerts_generated_at);
}

function drawDonutChart(active, expiring, critical, pending) {
    const canvas = document.getElementById('donut-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const total = active + expiring + critical + pending || 1;
    const cx = 60, cy = 60, r = 45, lw = 14;
    
    ctx.clearRect(0, 0, 120, 120);
    
    const segments = [
        { value: active, color: '#10b981', label: 'Actifs' },
        { value: expiring, color: '#f59e0b', label: 'Expirent' },
        { value: critical, color: '#ef4444', label: 'Critiques' },
        { value: pending, color: '#6366f1', label: 'Pending' }
    ];
    
    let startAngle = -Math.PI / 2;
    segments.forEach(seg => {
        if (seg.value === 0) return;
        const sliceAngle = (seg.value / total) * 2 * Math.PI;
        ctx.beginPath();
        ctx.arc(cx, cy, r, startAngle, startAngle + sliceAngle);
        ctx.strokeStyle = seg.color;
        ctx.lineWidth = lw;
        ctx.lineCap = 'round';
        ctx.stroke();
        startAngle += sliceAngle + 0.04;
    });
    
    // Center text
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-bright').trim() || '#fff';
    ctx.font = 'bold 22px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, cx, cy - 5);
    ctx.font = '10px Inter';
    ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--text-muted').trim() || '#9ca3af';
    ctx.fillText('Total', cx, cy + 12);
    
    // Legend
    const legend = document.getElementById('chart-legend');
    if (legend) {
        legend.innerHTML = segments.map(s => 
            `<div class="legend-item"><span class="legend-dot" style="background:${s.color}"></span>${s.label}: ${s.value}</div>`
        ).join('');
    }
}

function renderTimeline(certs) {
    const track = document.getElementById('timeline-track');
    if (!track) return;
    track.innerHTML = '';
    
    const nonPending = certs.filter(c => c.status !== 'pending' && c.days_left <= 90 && c.days_left >= 0);
    if (nonPending.length === 0) return;
    
    nonPending.forEach(cert => {
        const pct = Math.max(0, Math.min(100, (cert.days_left / 90) * 100));
        let color = '#10b981';
        if (cert.days_left <= 7) color = '#ef4444';
        else if (cert.days_left <= 30) color = '#f59e0b';
        
        const dot = document.createElement('div');
        dot.className = 'timeline-dot';
        dot.style.left = pct + '%';
        dot.style.background = color;
        dot.innerHTML = `<div class="timeline-tooltip">${escapeHtml(cert.domain)} — ${cert.days_left}j</div>`;
        track.appendChild(dot);
    });
}

document.querySelectorAll('.main-tab').forEach(btn => {
    btn.addEventListener('click', (e) => {
        document.querySelectorAll('.main-tab').forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');

        document.querySelectorAll('.view-section').forEach(v => v.style.display = 'none');
        document.getElementById(e.target.dataset.target).style.display = 'block';

        updateSearchPlaceholder();
        applyFilters();
    });
});

// Which certs/domains/orgs sub-tab is currently visible under the Dashboard
function getActiveSubTab() {
    const activeTab = document.querySelector('.main-tab.active');
    return activeTab ? activeTab.dataset.target : 'certs-view';
}

function updateSearchPlaceholder() {
    const input = document.getElementById('search-input');
    if (!input) return;
    const labels = { 'certs-view': 'Rechercher un domaine...', 'domains-view': 'Rechercher un domaine ou une organisation...', 'orgs-view': 'Rechercher une organisation...' };
    input.placeholder = labels[getActiveSubTab()] || 'Rechercher...';
}

document.getElementById('bell-icon').addEventListener('click', (e) => {
    e.stopPropagation();
    document.querySelectorAll('.custom-select.open').forEach(cs => cs.classList.remove('open'));
    document.getElementById('notification-dropdown').classList.toggle('active');
});
document.addEventListener('click', (e) => {
    const wrapper = document.getElementById('notification-wrapper');
    if (wrapper && !wrapper.contains(e.target)) {
        document.getElementById('notification-dropdown').classList.remove('active');
    }
});

// ===== ALERT CENTRE (the bell) =====
// Alerts are built server-side (alerts.py) as {category, type, title, message, target} and
// cover DigiCert expiries, certificates found installed on servers, agents that went
// offline, failed renewals and broken connections. The bell refreshes itself every minute
// so an agent dropping off shows up without reloading the dashboard.

const ALERT_CATEGORY_LABELS = {
    certificate: 'Certificat', domain: 'Domaine', organization: 'Organisation', server: 'Serveur',
    agent: 'Agent', renewal: 'Renouvellement', connection: 'Connexion', discovery: 'Découverte'
};
const ALERT_TYPE_LABELS = { critical: 'critique(s)', warning: 'avertissement(s)', info: 'info(s)' };
const ALERT_ACTION_LABELS = {
    cert: 'Voir le détail', domain: 'Voir dans le tableau', org: 'Voir dans le tableau',
    agent: 'Ouvrir Agents & Découverte', settings: 'Ouvrir les Paramètres'
};

let _lastNotifications = [];
let _alertFilter = 'all';
let _alertsGeneratedAt = null;
let _alertsTimer = null;
let pendingAgentFocus = null;

function updateNotifications(alerts, generatedAt) {
    _lastNotifications = Array.isArray(alerts) ? alerts : [];
    if (generatedAt) _alertsGeneratedAt = generatedAt;
    renderAlerts();
}

function renderAlerts() {
    const countBadge = document.getElementById('notification-count');
    const headerCount = document.getElementById('dropdown-count');
    const list = document.getElementById('notification-list');
    if (!headerCount || !list) return;

    const counts = { critical: 0, warning: 0, info: 0 };
    _lastNotifications.forEach(a => { if (counts[a.type] !== undefined) counts[a.type]++; });
    const attention = counts.critical + counts.warning;

    headerCount.innerText = _lastNotifications.length;
    document.getElementById('alert-summary').innerHTML = ['critical', 'warning', 'info']
        .filter(t => counts[t] > 0)
        .map(t => `<span class="alert-chip ${t}">${counts[t]} ${ALERT_TYPE_LABELS[t]}</span>`).join('');

    // The badge is for things that need a human; a passing "renewal succeeded" info must not nag.
    countBadge.style.display = attention > 0 ? 'flex' : 'none';
    countBadge.innerText = attention;
    countBadge.classList.toggle('warning', counts.critical === 0 && counts.warning > 0);

    document.querySelectorAll('#alert-filters [data-alert-filter]').forEach(btn => {
        const f = btn.dataset.alertFilter;
        const base = { all: 'Toutes', critical: 'Critiques', warning: 'Avertissements', info: 'Infos' }[f];
        const n = f === 'all' ? _lastNotifications.length : counts[f];
        btn.textContent = `${base} (${n})`;
        btn.classList.toggle('active', f === _alertFilter);
    });

    const shown = _lastNotifications
        .map((a, idx) => ({ a, idx }))
        .filter(({ a }) => _alertFilter === 'all' || a.type === _alertFilter);

    if (_lastNotifications.length === 0) {
        list.innerHTML = `<div class="dropdown-empty">Tout est en ordre.<br><span style="font-size:11px;">Certificats, agents, renouvellements et connexions vérifiés : rien à signaler.</span></div>`;
    } else if (shown.length === 0) {
        list.innerHTML = `<div class="dropdown-empty">Aucune alerte de ce niveau.</div>`;
    } else {
        list.innerHTML = shown.map(({ a, idx }) => {
            const clickable = !!(a.target && ALERT_ACTION_LABELS[a.target.kind]);
            return `
            <div class="dropdown-item ${escapeHtml(a.type)}" data-notif-idx="${idx}" style="${clickable ? 'cursor:pointer;' : ''}">
                <div class="di-top">
                    <span class="di-title">${escapeHtml(a.title)}</span>
                    <span class="di-tag">${escapeHtml(ALERT_CATEGORY_LABELS[a.category] || a.category || '')}</span>
                </div>
                <span class="di-msg">${escapeHtml(a.message)}</span>
                ${clickable ? `<span class="di-action">${escapeHtml(ALERT_ACTION_LABELS[a.target.kind])} →</span>` : ''}
            </div>`;
        }).join('');
        list.querySelectorAll('.dropdown-item').forEach(el => {
            el.addEventListener('click', () => handleNotificationClick(_lastNotifications[parseInt(el.dataset.notifIdx, 10)]));
        });
    }

    const updated = document.getElementById('alerts-updated');
    if (updated) {
        updated.textContent = _alertsGeneratedAt
            ? `Actualisé à ${new Date(_alertsGeneratedAt).toLocaleTimeString('fr-FR')}`
            : 'Jamais actualisé';
    }
}

async function refreshAlerts() {
    if (!window.pywebview || !window.pywebview.api) return;
    try {
        const res = await pywebview.api.get_alerts();
        updateNotifications(res.alerts, res.generated_at);
    } catch (e) { /* a missed refresh is harmless: the next one runs in a minute */ }
}

function startAlertRefresh() {
    clearInterval(_alertsTimer);
    _alertsTimer = setInterval(refreshAlerts, 60000);
}

document.getElementById('alert-filters').addEventListener('click', (e) => {
    const btn = e.target.closest('[data-alert-filter]');
    if (!btn) return;
    _alertFilter = btn.dataset.alertFilter;
    renderAlerts();
});

document.getElementById('alerts-refresh-btn').addEventListener('click', async (e) => {
    const btn = e.currentTarget;
    btn.disabled = true;
    await refreshAlerts();
    btn.disabled = false;
});

function handleNotificationClick(n) {
    if (!n || !n.target) return;
    const target = n.target;
    document.getElementById('notification-dropdown').classList.remove('active');

    if (target.kind === 'cert' || target.kind === 'domain' || target.kind === 'org') {
        // We already have fresh data from the load that produced this alert — no need to refetch.
        switchView('dashboard', { skipDataReload: true });
        if (target.kind === 'cert') {
            document.querySelector('.main-tab[data-target="certs-view"]').click();
            showDetails(target.value);
        } else {
            document.querySelector(`.main-tab[data-target="${target.kind === 'domain' ? 'domains-view' : 'orgs-view'}"]`).click();
            document.getElementById('search-input').value = target.value;
            applyFilters();
        }
    } else if (target.kind === 'agent') {
        pendingAgentFocus = target.value || null;
        switchView('agents');
    } else if (target.kind === 'settings') {
        switchView('settings');
        const anchor = document.getElementById(target.value === 'agents' ? 'agent-listener-url' : 'setting-api-key');
        if (anchor) setTimeout(() => { anchor.scrollIntoView({ behavior: 'smooth', block: 'center' }); anchor.focus(); }, 150);
    }
}

function renderCerts(certs) {
    renderCertsPaginated(certs);
}

function renderCertsHTML(certs, container) {
    container.innerHTML = '';

    certs.forEach(cert => {
        let statusClass = 'bg-active';
        let statusText = 'Active';
        if (cert.status === 'pending') {
            statusClass = 'bg-warning';
            statusText = 'Pending Issuance';
        } else if (cert.days_left <= 7) { statusClass = 'bg-critical'; statusText = 'Critical'; }
        else if (cert.days_left <= 30) { statusClass = 'bg-warning'; statusText = 'Expires Soon'; }

        const approver = escapeHtml(cert.approver || 'Non assigné');
        const dns = escapeHtml(cert.dns_verifier || 'Non assigné');
        const installer = escapeHtml(cert.installer || 'Non assigné');
        const domainSafe = escapeHtml(cert.domain);
        const productSafe = escapeHtml(cert.product);
        
        let formattedDate = 'N/A';
        let expiryDaysHtml = '';
        if (cert.status !== 'pending') {
            const dateObj = new Date(cert.valid_till);
            formattedDate = dateObj.toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' });
            expiryDaysHtml = `<span class="expiry-days">(${cert.days_left}d)</span>`;
        }

        let prereqHtml = '';
        if (cert.prerequisites && cert.prerequisites.length > 0) {
            let pText = escapeHtml(cert.prerequisites.join(' & '));
            let tooltip = escapeHtml(`Attention : Une validation ${cert.prerequisites.join(' & ')} est expirée ou expirera bientôt. Elle est requise pour le renouvellement.`);
            prereqHtml = `<div title="${tooltip}" style="display:inline-flex; align-items:center; gap:4px; font-size:10px; color:var(--text-warning); background:var(--bg-warning); padding:2px 6px; border-radius:4px; border:1px solid var(--border-warning); margin-top:6px; cursor:help;">
                ${pText} Requis
            </div>`;
        } else {
            prereqHtml = `<div title="Aucun blocage (DCV et Org valides)" style="display:inline-flex; align-items:center; gap:4px; font-size:10px; color:var(--text-success); background:var(--bg-success); padding:2px 6px; border-radius:4px; border:1px solid var(--border-success); margin-top:6px; cursor:help;">
                Prêt pour renouvellement
            </div>`;
        }

        let actionsHtml = '';
        if (cert.days_left <= 30) {
            actionsHtml += `
                <button class="btn-primary-action" style="border-color: #38bdf8; color: #38bdf8;" onclick="showDetails('${domainSafe}')">
                    Gérer & Details
                </button>
            `;
        } else {
            actionsHtml += `
                <button class="action-btn" onclick="alert('Renouvellement non nécessaire pour le moment')">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M2.13 15.57a9 9 0 1 0 3.84-10.45L2 8"></path></svg>
                    Renew
                </button>
                <button class="action-btn" onclick="showDetails('${domainSafe}')">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                    Details
                </button>
            `;
        }

        let expiryBarHtml = '';
        if (cert.status !== 'pending' && cert.days_left <= 365) {
            const pct = Math.min(100, Math.max(0, (cert.days_left / 365) * 100));
            let barColor = '#10b981';
            if (cert.days_left <= 7) barColor = '#ef4444';
            else if (cert.days_left <= 30) barColor = '#f59e0b';
            else if (cert.days_left <= 90) barColor = '#38bdf8';
            expiryBarHtml = `<div class="expiry-bar"><div class="expiry-bar-fill" style="width:${pct}%; background:${barColor}"></div></div>`;
        }

        container.innerHTML += `
            <div class="cert-card">
                <div class="col-domain domain-name">${domainSafe}</div>
                <div class="col-issuer issuer">DigiCert</div>
                <div class="col-expiry">
                    <span class="expiry-date">${formattedDate}</span>
                    ${expiryDaysHtml}
                    ${expiryBarHtml}
                </div>
                <div class="col-team">
                    <div class="team-stack">
                        <div class="team-member"><img src="${generateAvatar(approver)}" class="team-avatar"><span class="team-role">Approver</span> <span class="team-name">${approver.split('@')[0]}</span></div>
                        <div class="team-member"><img src="${generateAvatar(dns)}" class="team-avatar"><span class="team-role">DNS Verifier</span> <span class="team-name">${dns.split('@')[0]}</span></div>
                        <div class="team-member"><img src="${generateAvatar(installer)}" class="team-avatar"><span class="team-role">Installer</span> <span class="team-name">${installer.split('@')[0]}</span></div>
                    </div>
                </div>
                <div class="col-status">
                    <span class="badge ${statusClass}">${statusText}</span>
                    ${prereqHtml}
                </div>
                <div class="col-actions">
                    ${actionsHtml}
                </div>
            </div>
        `;
    });
}

function renderDomains(domains) {
    const container = document.getElementById('domain-list');
    if(!container) return;
    if(domains.length === 0) {
        container.innerHTML = `<div style="padding:20px; text-align:center; color:#94a3b8;">Aucun domaine trouvé.</div>`;
        return;
    }
    
    container.innerHTML = domains.map(d => {
        let statusClass = 'bg-active';
        let statusText = escapeHtml(d.status);
        
        if (d.status === 'Pending validation') {
            statusClass = 'bg-warning';
        } else if (d.status === 'Expired') {
            statusClass = 'bg-critical';
        } else if (d.days_left <= 7 && d.days_left >= 0) { 
            statusClass = 'bg-critical'; 
        } else if (d.days_left <= 30 && d.days_left >= 0) { 
            statusClass = 'bg-warning'; 
        }
        
        return `
            <div class="cert-card">
                <div class="col-domain-rich" style="flex: 2">
                    <div style="font-weight: 500;">${escapeHtml(d.name)}</div>
                    <div style="font-size: 11px; color: #94a3b8;">Domain ID: ${escapeHtml(d.id)}</div>
                </div>
                <div class="col-org" style="flex: 2">
                    <div style="font-weight: 500;">${escapeHtml(d.org_name)}</div>
                    <div style="font-size: 11px; color: #94a3b8;">${escapeHtml(d.org_address)}</div>
                </div>
                <div class="col-date" style="flex: 1">${escapeHtml(d.date_added || 'N/A')}</div>
                <div class="col-dcv" style="flex: 1.5">${escapeHtml(d.method)}</div>
                <div class="col-status" style="flex: 1">
                    <span class="badge ${statusClass}">${statusText}</span>
                </div>
                <div class="col-expiry" style="flex: 1">${escapeHtml(d.expires)}</div>
            </div>
        `;
    }).join('');
}

// Turns a "OV (12 Sep 2026), EV" style string from the backend into individual
// colored chips instead of a flat, hard-to-scan comma-separated line.
function renderValidationChips(str, variant) {
    if (!str || str === '-') return `<span style="font-size:12px; color:var(--text-muted-dark);">—</span>`;
    const color = variant === 'pending' ? '#eab308' : '#10b981';
    return str.split(',').map(s => s.trim()).filter(Boolean).map(item => `
        <span style="display:inline-flex; align-items:center; font-size:11px; font-weight:600; color:${color}; background:${color}1a; border:1px solid ${color}44; padding:3px 10px; border-radius:20px; margin:2px 5px 2px 0; white-space:nowrap;">${escapeHtml(item)}</span>
    `).join('');
}

function renderOrgs(orgs) {
    const container = document.getElementById('org-list');
    if(!container) return;
    if(orgs.length === 0) {
        container.innerHTML = `<div style="padding:20px; text-align:center; color:#94a3b8;">Aucune organisation trouvée.</div>`;
        return;
    }

    container.innerHTML = orgs.map(o => {
        let statusClass = o.status === 'Active' ? 'bg-active' : 'bg-critical';

        return `
            <div class="cert-card">
                <div class="col-org-name" style="flex: 2.2; display:flex; align-items:center; gap:12px;">
                    <div style="width:38px; height:38px; border-radius:10px; background:rgba(0,159,223,0.1); display:flex; align-items:center; justify-content:center; flex-shrink:0;">
                        <svg viewBox="0 0 24 24" fill="none" stroke="var(--accent-btn)" stroke-width="2" style="width:18px;height:18px;"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>
                    </div>
                    <div style="min-width:0;">
                        <div style="font-weight: 600; color: var(--text-bright);">${escapeHtml(o.name)}</div>
                        <div style="font-size: 11px; color: var(--text-muted-dark); line-height: 1.4; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">Org #${escapeHtml(o.id)} · ${escapeHtml(o.address || 'Adresse non renseignée')}</div>
                    </div>
                </div>
                <div class="col-org-status" style="flex: 0.9">
                    <span class="badge ${statusClass}">${escapeHtml(o.status)}</span>
                </div>
                <div class="col-org-val" style="flex: 2.4;">${renderValidationChips(o.validated_for, 'validated')}</div>
                <div class="col-org-pend" style="flex: 2;">${renderValidationChips(o.pending_for, 'pending')}</div>
            </div>
        `;
    }).join('');
}

// Filters the sub-tab that's actually visible (certs/domains/orgs) instead of
// always filtering the (possibly hidden) certs table — this is what makes the
// always-visible search box behave correctly no matter which tab is open.
window.applyFilters = function() {
    const term = document.getElementById('search-input').value.toLowerCase();
    const subTab = getActiveSubTab();
    const clearBtn = document.getElementById('search-clear-btn');
    if (clearBtn) clearBtn.style.display = term ? 'flex' : 'none';

    if (subTab === 'domains-view') {
        const filtered = allDomains.filter(d =>
            !term || (d.name || '').toLowerCase().includes(term) || (d.org_name || '').toLowerCase().includes(term)
        );
        window._allFilteredDomains = filtered;
        renderDomains(filtered);
        return;
    }

    if (subTab === 'orgs-view') {
        const filtered = allOrgs.filter(o => !term || (o.name || '').toLowerCase().includes(term));
        window._allFilteredOrgs = filtered;
        renderOrgs(filtered);
        return;
    }

    const statusF = document.getElementById('filter-status').dataset.value;
    const teamF = document.getElementById('filter-team').dataset.value;

    let filtered = allData.filter(cert => {
        // Search
        if (term && !cert.domain.toLowerCase().includes(term)) return false;

        // Status Filter (pending certs have no meaningful days_left — exclude them from both buckets)
        if (statusF === 'critical' && (cert.status === 'pending' || cert.days_left > 7)) return false;
        if (statusF === 'warning' && (cert.status === 'pending' || cert.days_left > 30)) return false;

        // Team Filter (the backend returns an empty string for an unassigned role, never the
        // literal text "Non assigné" — that text is only a frontend display fallback)
        const isAssigned = !!cert.approver || !!cert.dns_verifier || !!cert.installer;
        if (teamF === 'assigned' && !isAssigned) return false;
        if (teamF === 'unassigned' && isAssigned) return false;

        return true;
    });

    certCurrentPage = 1;
    renderCerts(filtered);
}

document.getElementById('search-input').addEventListener('input', applyFilters);
document.getElementById('filter-status').addEventListener('change', applyFilters);
document.getElementById('filter-team').addEventListener('change', applyFilters);
document.getElementById('search-clear-btn').addEventListener('click', () => {
    const input = document.getElementById('search-input');
    input.value = '';
    input.focus();
    applyFilters();
});

async function loadAssignments() {
    if (!window.pywebview) return;
    const assignments = await pywebview.api.get_all_assignments();
    const container = document.getElementById('assign-container');
    container.innerHTML = '';
    
    assignments.forEach(a => {
        container.innerHTML += `
            <div class="cert-card" style="padding: 10px 20px;">
                <div style="flex:1; font-size: 13px; color: #fff;">${a.domain}</div>
                <div style="flex:1; font-size: 12px; color: #9ca3af;">${a.approver}</div>
                <div style="flex:1; font-size: 12px; color: #9ca3af;">${a.dns_verifier}</div>
                <div style="flex:1; font-size: 12px; color: #9ca3af;">${a.installer}</div>
            </div>
        `;
    });
}

document.getElementById('assignment-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const domain = document.getElementById('assign-domain').value;
    const approver = document.getElementById('assign-approver').value;
    const dns = document.getElementById('assign-dns').value;
    const installer = document.getElementById('assign-installer').value;
    
    await pywebview.api.save_assignment(domain, approver, dns, installer);
    showToast('Affectation enregistrée avec succès !', 'success');
    document.getElementById('assignment-form').reset();
    loadAssignments();
});

let currentDraftCert = null;

window.openDraftModal = function(domain) {
    currentDraftCert = allData.find(c => c.domain === domain);
    document.getElementById('draft-modal').style.display = 'flex';
    showTemplate('approver');
}

document.getElementById('close-modal').addEventListener('click', () => {
    document.getElementById('draft-modal').style.display = 'none';
});

window.showTemplate = function(role) {
    if(!currentDraftCert) return;
    
    document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
    document.getElementById('tab-' + role).classList.add('active');
    
    const cert = currentDraftCert;
    const toInput = document.getElementById('draft-to');
    const bodyInput = document.getElementById('draft-body');
    
    let toEmail = '';
    let bodyText = '';
    
    const dateObj = new Date(cert.valid_till);
    const formattedDate = dateObj.toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });
    const formattedDateShort = dateObj.toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric' });
    const rootDomain = cert.domain.split('.').length > 2 ? cert.domain.split('.').slice(-2).join('.') : cert.domain;
    
    if(role === 'approver') {
        toEmail = cert.approver;
        bodyText = `Bonjour,\n\nNous sollicitons votre validation pour procéder avant expiration au renouvellement des certificats dont les informations sont ci-après :\n\nDomaine : ${cert.domain}\nDate d’expiration : ${formattedDate}\nType : ${cert.product}\n\nCordialement,`;
    } else if(role === 'dns') {
        toEmail = cert.dns_verifier;
        bodyText = `Bonjour,\n\nMerci d’ajouter le TXT Record ci-dessous pour finaliser le renouvellement des certificats SSL des domaines concernés :\n\n• Domaine : ${cert.domain}\nType : ${cert.product}\nDate d’expiration : ${formattedDateShort}\n\n${rootDomain}\nValeur :  [INSÉRER LE TOKEN ICI]\n\nMerci de me confirmer une fois l’ajout effectué.\n\nCordialement,`;
    } else if(role === 'installer') {
        toEmail = cert.installer;
        bodyText = `Bonjour,\nLe certificat SSL pour le domaine ${cert.domain} a été renouvelé avec succès. Vous trouverez les nouveaux fichiers en pièces jointes.\n• Date d’expiration : ${formattedDateShort}\n• Type de certificat : ${cert.product}\n\n@${toEmail ? toEmail.split('@')[0] : 'Équipe'} : Merci de procéder à l'installation de ce certificat sur le serveur ou l'équipement concerné.\n\nRestant à votre disposition pour tout complément d'information.\nCordialement`;
    }

    toInput.value = toEmail || '';
    bodyInput.value = bodyText;
}

window.copyDraft = function copyDraft() {
    const text = document.getElementById('draft-body').value;
    navigator.clipboard.writeText(text).then(() => {
        showToast("Texte copié dans le presse-papier !", "success");
    }).catch(err => {
        showToast('Erreur lors de la copie', 'error');
    });
}

// Sorting logic
let sortDirections = {};
function setupSorting() {
    document.querySelectorAll('.table-header div[data-sort]').forEach(header => {
        header.addEventListener('click', () => {
            let key = header.getAttribute('data-sort');
            if (!key) return;
            
            sortDirections[key] = !sortDirections[key];
            let asc = sortDirections[key];
            
            let viewId = header.closest('.view-section').id;
            let dataArray = [];
            
            if (viewId === 'certs-view') dataArray = window.lastData.certs;
            else if (viewId === 'domains-view') dataArray = window.lastData.domains;
            else if (viewId === 'orgs-view') dataArray = window.lastData.organizations;
            
            if (!dataArray) return;
            
            dataArray.sort((a, b) => {
                let valA = a[key] !== undefined && a[key] !== null ? a[key] : '';
                let valB = b[key] !== undefined && b[key] !== null ? b[key] : '';
                
                if (typeof valA === 'string') valA = valA.toLowerCase();
                if (typeof valB === 'string') valB = valB.toLowerCase();
                
                if (valA < valB) return asc ? -1 : 1;
                if (valA > valB) return asc ? 1 : -1;
                return 0;
            });
            
            if (viewId === 'certs-view') { certCurrentPage = 1; renderCerts(dataArray); }
            else if (viewId === 'domains-view') renderDomains(dataArray);
            else if (viewId === 'orgs-view') renderOrgs(dataArray);
        });
    });
}

async function sendViaOutlook() {
    const to = document.getElementById('draft-to').value;
    const bodyText = document.getElementById('draft-body').value;
    const subject = document.getElementById('modal-title').innerText;
    
    // Convert plain text body to simple HTML for Outlook
    const htmlBody = bodyText.replace(/\n/g, '<br>');
    
    const btn = document.getElementById('mailto-btn');
    const originalText = btn.innerText;
    btn.innerText = "Génération...";
    btn.disabled = true;
    
    try {
        const response = await pywebview.api.send_outlook_email(to, subject, htmlBody);
        if (response.status === 'success') {
            showToast(response.message, 'success');
            if (currentDraftCert) clmMarkContacted(currentDraftCert.domain, true);
            document.getElementById('draft-modal').style.display = 'none';
        } else {
            showToast("Erreur Outlook: " + response.message, 'error');
        }
    } catch (e) {
        showToast("Erreur API", 'error');
    }
    
    btn.innerText = originalText;
    btn.disabled = false;
}

// Theme Logic
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    setTheme(savedTheme);
}

function toggleTheme() {
    const currentTheme = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    setTheme(currentTheme);
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    
    if (theme === 'light') {
        document.querySelector('.sun-icon').style.display = 'none';
        document.querySelector('.moon-icon').style.display = 'block';
    } else {
        document.querySelector('.sun-icon').style.display = 'block';
        document.querySelector('.moon-icon').style.display = 'none';
    }
}

function csvCell(v) {
    return `"${String(v === undefined || v === null ? '' : v).replace(/"/g, '""')}"`;
}

window.exportCSV = function() {
    const subTab = getActiveSubTab();
    let rows = [];
    let filenamePart = 'Certificats';

    if (subTab === 'domains-view') {
        filenamePart = 'Domaines';
        const data = window._allFilteredDomains || allDomains;
        if (!data || data.length === 0) { showToast('Aucune donnée à exporter', 'warning'); return; }
        rows.push(['Domaine', 'Organisation', 'Date Ajout', 'Methode DCV', 'Statut Validation', 'Expiration Validation'].map(csvCell).join(','));
        data.forEach(d => rows.push([d.name, d.org_name, d.date_added, d.method, d.status, d.expires].map(csvCell).join(',')));
    } else if (subTab === 'orgs-view') {
        filenamePart = 'Organisations';
        const data = window._allFilteredOrgs || allOrgs;
        if (!data || data.length === 0) { showToast('Aucune donnée à exporter', 'warning'); return; }
        rows.push(['ID', 'Nom', 'Statut', 'Valide Pour', 'En Attente Pour'].map(csvCell).join(','));
        data.forEach(o => rows.push([o.id, o.name, o.status, o.validated_for, o.pending_for].map(csvCell).join(',')));
    } else {
        const data = window._allFilteredCerts || allData;
        if (!data || data.length === 0) { showToast('Aucune donnée à exporter', 'warning'); return; }
        rows.push(['Domaine', 'Statut', 'Date Expiration', 'Jours Restants', 'Produit', 'Approbateur', 'DNS Verifier', 'Installeur', 'Prerequis'].map(csvCell).join(','));
        data.forEach(c => {
            const prereqs = (c.prerequisites || []).join(' & ') || 'Aucun';
            const status = c.status === 'pending' ? 'Pending' : (c.days_left <= 7 ? 'Critique' : (c.days_left <= 30 ? 'Expire bientôt' : 'Actif'));
            rows.push([c.domain, status, c.valid_till, c.days_left, c.product, c.approver, c.dns_verifier, c.installer, prereqs].map(csvCell).join(','));
        });
    }

    const csv = rows.join('\n');
    const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `certificates_${filenamePart}_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('Export CSV téléchargé avec succès !', 'success');
}

window.addEventListener('pywebviewready', function() {
    loadDashboard();
    startAlertRefresh();
});

// ===== Side Panel Details =====
function closeDetails() {
    document.getElementById('side-panel').classList.remove('open');
    document.getElementById('sp-overlay').classList.remove('active');
}

function showDetails(domain) {
    if (!window.lastData || !window.lastData.certs) return;
    
    const cert = window.lastData.certs.find(c => c.domain === domain);
    if (!cert) return;
    
    let orgName = 'N/A';
    let orgAddress = 'N/A';
    
    if (cert.org_id && window.lastData.organizations) {
        const org = window.lastData.organizations.find(o => String(o.id) === String(cert.org_id));
        if (org) {
            orgName = org.name || 'N/A';
            orgAddress = org.address || 'N/A';
        }
    }

    // Find domain validation info
    let dcvMethod = 'N/A';
    let dcvExpiry = 'N/A';
    let dcvDaysLeft = 'N/A';
    if (window.lastData.domains) {
        const domainInfo = window.lastData.domains.find(d => d.name === domain);
        if (domainInfo) {
            dcvMethod = domainInfo.method || 'N/A';
            dcvExpiry = domainInfo.expires || 'N/A';
            dcvDaysLeft = domainInfo.days_left !== undefined ? domainInfo.days_left : 'N/A';
        }
    }
    
    let statusBadge = '';
    let statusColor = '';
    if (cert.status === 'pending') { statusBadge = 'Pending'; statusColor = 'bg-warning'; }
    else if (cert.days_left <= 7) { statusBadge = 'Critical'; statusColor = 'bg-critical'; }
    else if (cert.days_left <= 30) { statusBadge = 'Expires Soon'; statusColor = 'bg-warning'; }
    else { statusBadge = 'Active'; statusColor = 'bg-active'; }

    let daysDisplay = cert.status === 'pending' ? '—' : cert.days_left;
    let daysClass = '';
    if (cert.days_left <= 7) daysClass = 'color: #ef4444;';
    else if (cert.days_left <= 30) daysClass = 'color: #f59e0b;';
    else daysClass = 'color: #10b981;';

    let prereqHtml = '';
    if (cert.prerequisites && cert.prerequisites.length > 0) {
        prereqHtml = cert.prerequisites.map(p => 
            `<span style="display:inline-flex;align-items:center;gap:4px;font-size:11px;color:#f59e0b;background:rgba(245,158,11,0.1);padding:3px 10px;border-radius:20px;border:1px solid rgba(245,158,11,0.2);">${escapeHtml(p)}</span>`
        ).join(' ');
    } else {
        prereqHtml = '<span style="display:inline-flex;align-items:center;gap:4px;font-size:11px;color:#10b981;background:rgba(16,185,129,0.1);padding:3px 10px;border-radius:20px;border:1px solid rgba(16,185,129,0.2);">Prêt</span>';
    }

    let formattedDate = 'N/A';
    if (cert.status !== 'pending' && cert.valid_till) {
        try {
            const d = new Date(cert.valid_till);
            formattedDate = d.toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });
        } catch(e) { formattedDate = cert.valid_till; }
    }
    
    const panelContent = document.getElementById('side-panel-content');
    panelContent.innerHTML = `
        <div class="sp-section">
            <span class="sp-label">Domaine</span>
            <span class="sp-value" style="font-size: 17px; font-weight: 700; color: var(--text-bright);">${escapeHtml(cert.domain)}</span>
        </div>
        
        <div class="sp-row">
            <div class="sp-section" style="border:none; padding: 0;">
                <span class="sp-label">Statut</span>
                <div style="margin-top: 6px;"><span class="sp-badge ${statusColor}">${statusBadge}</span></div>
            </div>
            <div class="sp-section" style="border:none; padding: 0; text-align: right;">
                <span class="sp-label">Jours Restants</span>
                <span class="sp-days-value" style="${daysClass}">${daysDisplay}</span>
            </div>
        </div>

        <div class="sp-section">
            <span class="sp-label">Date d'expiration</span>
            <span class="sp-value">${formattedDate}</span>
        </div>
        
        <div class="sp-section">
            <span class="sp-label">Produit</span>
            <span class="sp-value">${escapeHtml(cert.product)}</span>
        </div>
        
        <div class="sp-section">
            <span class="sp-label">Organisation</span>
            <span class="sp-value" style="color: var(--text-bright);">${escapeHtml(orgName)}</span>
            <span class="sp-value" style="font-size: 12px; color: var(--text-muted);">${escapeHtml(orgAddress)}</span>
        </div>

        <div class="sp-section">
            <span class="sp-label">Validation DCV</span>
            <div style="display: flex; gap: 20px; margin-top: 4px;">
                <div><span style="font-size:11px; color:var(--text-muted-dark);">Méthode:</span> <span class="sp-value" style="font-size:13px;">${escapeHtml(dcvMethod)}</span></div>
                <div><span style="font-size:11px; color:var(--text-muted-dark);">Expire:</span> <span class="sp-value" style="font-size:13px;">${escapeHtml(String(dcvExpiry))}</span></div>
            </div>
        </div>

        <div class="sp-section">
            <span class="sp-label">Prérequis Renouvellement</span>
            <div style="margin-top: 6px;">${prereqHtml}</div>
        </div>
        
        <div class="sp-section">
            <span class="sp-label">Équipe Assignée</span>
            <div class="sp-team-card">
                <div class="sp-team-member">
                    <img src="${generateAvatar(cert.approver || 'NA')}" alt="">
                    <span class="sp-team-role">Approver</span>
                    <span class="sp-team-name">${escapeHtml(cert.approver || 'Non assigné')}</span>
                </div>
                <div class="sp-team-member">
                    <img src="${generateAvatar(cert.dns_verifier || 'NA')}" alt="">
                    <span class="sp-team-role">DNS</span>
                    <span class="sp-team-name">${escapeHtml(cert.dns_verifier || 'Non assigné')}</span>
                </div>
                <div class="sp-team-member">
                    <img src="${generateAvatar(cert.installer || 'NA')}" alt="">
                    <span class="sp-team-role">Installer</span>
                    <span class="sp-team-name">${escapeHtml(cert.installer || 'Non assigné')}</span>
                </div>
            </div>
        </div>
        
        <div class="sp-section">
            <span class="sp-label">Notes</span>
            <textarea id="sp-note-textarea" class="form-input" style="height:70px; resize:vertical; margin-top:6px;" placeholder="Ajouter une note (ex: en attente de confirmation DNS)...">${escapeHtml(cert.note || '')}</textarea>
            <button class="btn-primary" style="margin-top:8px; align-self:flex-start; width:auto;" onclick="saveCertNote('${escapeHtml(cert.domain)}')">Enregistrer la note</button>
        </div>

        <div class="sp-section">
            <span class="sp-label">Checklist de renouvellement</span>
            <div id="sp-checklist" style="margin-top:8px;">${renderChecklistItems(cert.domain, cert.checklist)}</div>
        </div>

        <div class="sp-section">
            <span class="sp-label">Historique de renouvellement</span>
            <div id="sp-renewal-history-content" style="margin-top:6px; font-size:12px; color:var(--text-muted);">Chargement...</div>
        </div>

        <div class="sp-section" id="live-check-section" style="display: none; background: rgba(0,0,0,0.2); padding: 12px; border-radius: 8px; margin-bottom: 10px; border: 1px solid rgba(0,159,223,0.3);">
            <div style="font-size: 11px; color: var(--text-muted-dark); text-transform: uppercase; font-weight: bold; margin-bottom: 5px;">Résultat Live</div>
            <div id="live-check-content" style="font-size: 13px; color: var(--text-bright);">Chargement...</div>
        </div>

        <button class="sp-action-btn" style="background: linear-gradient(135deg, #10b981, #059669); margin-bottom: 10px; margin-top: 5px;" onclick="runLiveCheck('${escapeHtml(cert.domain)}')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
            Vérifier le Certificat en Ligne (Live)
        </button>

        <button class="sp-action-btn" style="margin-top: 0;" onclick="closeDetails(); openDraftModal('${escapeHtml(cert.domain)}')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg>
            Générer Email de Relance
        </button>
    `;
    
    document.getElementById('side-panel').classList.add('open');
    document.getElementById('sp-overlay').classList.add('active');

    loadRenewalHistoryForDomain(domain);
}

const CHECKLIST_ITEMS = [
    { key: 'approval_done', label: 'Approbation obtenue' },
    { key: 'dns_done', label: 'DNS ajouté' },
    { key: 'order_done', label: 'Commande passée' },
    { key: 'installed_done', label: 'Installé' },
    { key: 'verified_done', label: 'Vérifié en ligne' }
];

function renderChecklistItems(domain, checklist) {
    checklist = checklist || {};
    return `<div style="display:flex; flex-direction:column; gap:8px;">` + CHECKLIST_ITEMS.map(item => `
        <label style="display:flex; align-items:center; gap:10px; cursor:pointer; font-size:13px; color:${checklist[item.key] ? 'var(--text-bright)' : 'var(--text-muted)'};">
            <input type="checkbox" ${checklist[item.key] ? 'checked' : ''} onchange="toggleChecklistItem('${escapeHtml(domain)}', '${item.key}', this.checked)" style="width:16px; height:16px; accent-color: var(--accent-btn);">
            ${item.label}
        </label>
    `).join('') + `</div>`;
}

async function toggleChecklistItem(domain, key, checked) {
    const cert = (window.lastData && window.lastData.certs || []).find(c => c.domain === domain);
    const checklist = Object.assign({}, cert ? cert.checklist : {}, { [key]: checked });
    if (cert) cert.checklist = checklist;
    try {
        await pywebview.api.save_cert_checklist(domain, checklist);
        if (document.getElementById('view-pipeline').style.display !== 'none') renderPipeline(window.lastData.certs);
    } catch (e) {
        showToast('Erreur lors de la mise à jour de la checklist', 'error');
    }
}

async function saveCertNote(domain) {
    const textarea = document.getElementById('sp-note-textarea');
    if (!textarea) return;
    try {
        await pywebview.api.save_cert_note(domain, textarea.value);
        const cert = (window.lastData && window.lastData.certs || []).find(c => c.domain === domain);
        if (cert) cert.note = textarea.value;
        showToast('Note enregistrée', 'success');
    } catch (e) {
        showToast('Erreur lors de l\'enregistrement de la note', 'error');
    }
}

async function loadRenewalHistoryForDomain(domain) {
    const el = document.getElementById('sp-renewal-history-content');
    if (!el) return;
    try {
        const history = await pywebview.api.get_renewal_history(domain);
        if (!history || history.length === 0) {
            el.innerHTML = `<span style="font-style:italic;">Aucun renouvellement détecté pour ce domaine pour l'instant.</span>`;
            return;
        }
        el.innerHTML = history.map(h => `
            <div style="padding:8px 0; border-bottom:1px solid var(--border-ultralight);">
                <div style="font-size:12px; color:var(--text-bright);">${escapeHtml(h.old_valid_till)} → ${escapeHtml(h.new_valid_till)}</div>
                <div style="font-size:11px; color:var(--text-muted-dark);">Détecté le ${escapeHtml((h.detected_at || '').slice(0, 10))}</div>
            </div>
        `).join('');
    } catch (e) {
        el.innerHTML = `<span style="color:#ef4444;">Erreur de chargement.</span>`;
    }
}

async function runLiveCheck(domain) {
    const section = document.getElementById('live-check-section');
    const content = document.getElementById('live-check-content');
    
    section.style.display = 'block';
    content.innerHTML = '<span style="color: var(--accent-light);">Interrogation du serveur en cours...</span>';
    
    try {
        const result = await pywebview.api.check_live_cert(domain);
        if (result.status === 'success') {
            content.innerHTML = `
                <div style="margin-bottom: 3px;"><b>Issuer:</b> ${escapeHtml(result.issuer)}</div>
                <div><b>Expiration:</b> ${escapeHtml(result.expiry)}</div>
                <div style="margin-top: 5px; color: #10b981; font-weight: bold; font-size: 12px;">Connecté avec succès au port 443</div>
            `;
        } else {
            content.innerHTML = `<span style="color: #ef4444;">Erreur: ${escapeHtml(result.message)}</span>`;
        }
    } catch (e) {
        content.innerHTML = `<span style="color: #ef4444;">Erreur réseau ou domaine inaccessible.</span>`;
    }
}

// ===== USERS RENDERING =====
function renderUsers(users) {
    const container = document.getElementById('users-container');
    const statsRow = document.getElementById('users-stats-row');
    if (!container) return;

    if (!users || users.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 40px;">Aucun utilisateur trouvé ou accès refusé.</div>';
        if (statsRow) statsRow.innerHTML = '';
        return;
    }

    if (statsRow) {
        const isAdminRole = (u) => (u.access_roles && u.access_roles[0] ? u.access_roles[0].name : '').toLowerCase().includes('admin');
        const totalCount = users.length;
        const activeCount = users.filter(u => u.status === 'active').length;
        const adminCount = users.filter(isAdminRole).length;
        statsRow.innerHTML = `
            <div class="stat-card">
                <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M23 21v-2a4 4 0 0 0-3-3.87"></path><path d="M16 3.13a4 4 0 0 1 0 7.75"></path></svg></div>
                <div class="stat-info"><span class="stat-value">${totalCount}</span><span class="stat-label">Utilisateurs</span></div>
            </div>
            <div class="stat-card">
                <div class="stat-icon" style="background:rgba(16,185,129,0.1);"><svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg></div>
                <div class="stat-info"><span class="stat-value">${activeCount}</span><span class="stat-label">Actifs</span></div>
            </div>
            <div class="stat-card critical">
                <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg></div>
                <div class="stat-info"><span class="stat-value">${adminCount}</span><span class="stat-label">Administrateurs</span></div>
            </div>
        `;
    }

    let html = '';
    users.forEach(user => {
        let role = user.access_roles && user.access_roles.length > 0 ? user.access_roles[0].name : 'Utilisateur';
        let is_admin = role.toLowerCase().includes('admin');

        let roleColor = is_admin ? '#ef4444' : '#38bdf8';
        let statusColor = user.status === 'active' ? '#10b981' : '#f59e0b';
        let lastLogin = user.last_login_date ? user.last_login_date.substring(0, 10) : 'Jamais';

        let nameSafe = escapeHtml(user.first_name + ' ' + user.last_name);
        if (nameSafe.trim() === '') nameSafe = escapeHtml(user.username);

        html += `
            <div class="cert-card">
                <div style="flex:2; display: flex; align-items: center; gap: 12px;">
                    <img src="${generateAvatar(nameSafe)}" class="avatar" style="width:32px; height:32px;">
                    <div style="font-weight: 500; color: var(--text-bright);">${nameSafe}</div>
                </div>
                <div style="flex:2; color: var(--text-muted);">${escapeHtml(user.email || user.username)}</div>
                <div style="flex:1;">
                    <span style="background: ${roleColor}22; color: ${roleColor}; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: bold;">
                        ${escapeHtml(role)}
                    </span>
                </div>
                <div style="flex:1; display:flex; align-items:center; gap:5px; color: ${statusColor}; font-size: 12px; font-weight:500;">
                    <div class="dot" style="background-color: ${statusColor}; width:8px; height:8px;"></div>
                    ${escapeHtml(user.status || 'unknown')}
                </div>
                <div style="flex:1; font-size: 12px; color: var(--text-muted);">
                    ${escapeHtml(lastLogin)}
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

// ===== SKELETON LOADING =====
function showSkeletonCerts() {
    const list = document.getElementById('certs-container');
    if (!list) return;
    let html = '';
    for (let i = 0; i < 5; i++) {
        html += `
            <div class="skeleton-card cert-card">
                <div class="skeleton skeleton-circle"></div>
                <div class="skeleton-lines">
                    <div class="skeleton skeleton-line long"></div>
                    <div class="skeleton skeleton-line medium"></div>
                </div>
                <div class="skeleton skeleton-badge"></div>
            </div>`;
    }
    list.innerHTML = html;
}

// ===== CERT PAGINATION =====
let certCurrentPage = 1;
const CERTS_PER_PAGE = 15;

function renderCertsPaginated(certs) {
    const list = document.getElementById('certs-container');
    if (!list) return;
    if (!certs || certs.length === 0) {
        list.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 40px;">Aucun certificat trouvé.</div>';
        const pag = document.getElementById('cert-list-pagination');
        if (pag) pag.innerHTML = '';
        return;
    }
    window._allFilteredCerts = certs;
    const totalPages = Math.ceil(certs.length / CERTS_PER_PAGE);
    certCurrentPage = Math.min(Math.max(1, certCurrentPage), totalPages);
    const pageCerts = certs.slice((certCurrentPage - 1) * CERTS_PER_PAGE, certCurrentPage * CERTS_PER_PAGE);
    renderCertsHTML(pageCerts, list);
    renderPagination(certs, 'cert-list-pagination', certCurrentPage, totalPages, (p) => { certCurrentPage = p; renderCertsPaginated(certs); });
}

function renderPagination(items, containerId, currentPage, totalPages, onPageClick) {
    let container = document.getElementById(containerId);
    if (!container) return;
    if (totalPages <= 1) { container.innerHTML = ''; return; }
    
    let html = `<div class="pagination-bar">`;
    html += `<button class="page-btn" onclick="(${onPageClick.toString()})(${currentPage - 1})" ${currentPage === 1 ? 'disabled' : ''}>‹ Préc</button>`;
    
    for (let i = 1; i <= totalPages; i++) {
        if (totalPages > 7 && i > 2 && i < totalPages - 1 && Math.abs(i - currentPage) > 1) {
            if (i === 3 || i === totalPages - 2) html += `<span class="page-info">…</span>`;
            continue;
        }
        html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" onclick="(${onPageClick.toString()})(${i})">${i}</button>`;
    }
    
    html += `<button class="page-btn" onclick="(${onPageClick.toString()})(${currentPage + 1})" ${currentPage === totalPages ? 'disabled' : ''}>Suiv ›</button>`;
    html += `<span class="page-info">${items.length} éléments</span>`;
    html += `</div>`;
    container.innerHTML = html;
}

// ===== AUDIT FILTER =====
let _rawAuditLogs = [];

if (document.getElementById('audit-filter-type')) {
    document.getElementById('audit-filter-type').addEventListener('change', applyAuditFilters);
}

function applyAuditFilters() {
    const typeFilter = (document.getElementById('audit-filter-type')?.dataset.value || 'all').toLowerCase();
    const userFilter = (document.getElementById('audit-filter-user')?.value || '').toLowerCase();
    const dateFilter = document.getElementById('audit-filter-date')?.value || '';
    
    let filtered = _rawAuditLogs.filter(log => {
        const action = (log.action || '').toLowerCase();
        const username = (log.user?.username || '').toLowerCase();
        const logDate = log.date ? log.date.substring(0, 10) : '';
        
        if (typeFilter !== 'all' && !action.includes(typeFilter)) return false;
        if (userFilter && !username.includes(userFilter)) return false;
        if (dateFilter && logDate !== dateFilter) return false;
        return true;
    });
    
    renderAuditHTML(filtered);
}

function clearAuditFilters() {
    setCustomSelectValue('audit-filter-type', 'all');
    if (document.getElementById('audit-filter-user')) document.getElementById('audit-filter-user').value = '';
    if (document.getElementById('audit-filter-date')) document.getElementById('audit-filter-date').value = '';
    renderAuditHTML(_rawAuditLogs);
}

// Programmatically set a custom-select's value (mirrors what clicking an option does),
// used e.g. by "Réinitialiser" buttons instead of the old select.value = 'all' pattern.
function setCustomSelectValue(id, value) {
    const container = document.getElementById(id);
    if (!container) return;
    const label = container.querySelector('.custom-select-label');
    const options = container.querySelectorAll('.custom-select-option');
    options.forEach(o => o.classList.toggle('active', o.dataset.value === value));
    const match = container.querySelector(`.custom-select-option[data-value="${value}"]`);
    if (match && label) label.textContent = match.textContent;
    container.dataset.value = value;
}

function renderAudit(logs) {
    _rawAuditLogs = logs || [];
    renderAuditHTML(_rawAuditLogs);
}

function renderAuditHTML(logs) {
    const container = document.getElementById('audit-container');
    if (!container) return;
    
    if (!logs || logs.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 40px;">Aucun historique récent ou accès non autorisé.</div>';
        return;
    }

    let html = '<div class="audit-timeline">';
    
    logs.forEach(log => {
        let actionStr = log.action || 'Action inconnue';
        let actionLower = actionStr.toLowerCase();
        
        let dotClass = '';
        if (actionLower.includes('approve') || actionLower.includes('issue')) dotClass = 'action-approve';
        else if (actionLower.includes('revoke') || actionLower.includes('delete')) dotClass = 'action-revoke';
        else if (actionLower.includes('login')) dotClass = 'action-login';
        else if (actionLower.includes('order')) dotClass = 'action-order';
        
        let dateStr = log.date ? new Date(log.date).toLocaleString() : 'Date inconnue';
        let userSafe = escapeHtml(log.user ? log.user.username : 'Système');
        let messageSafe = escapeHtml(log.message || actionStr);
        let avatarUrl = generateAvatar(userSafe);
        
        html += `
            <div class="audit-item">
                <div class="audit-dot ${dotClass}"></div>
                <div class="audit-content">
                    <div class="audit-header">
                        <div class="audit-user">
                            <img src="${avatarUrl}" class="avatar" style="width:20px;height:20px;">
                            ${userSafe}
                        </div>
                        <div class="audit-date">${dateStr}</div>
                    </div>
                    <div class="audit-message">
                        <strong>${escapeHtml(actionStr)}</strong>: ${messageSafe}
                    </div>
                </div>
            </div>
        `;
    });
    
    html += '</div>';
    container.innerHTML = html;
}

// ===== ENHANCED INVENTORY: Accordion + Sparklines =====
function renderInventory(certs, orgs) {
    const container = document.getElementById('inventory-container');
    if (!container) return;
    
    if (!certs || certs.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 40px;">Aucun certificat trouvé.</div>';
        return;
    }

    let orgMap = {};
    if (orgs) orgs.forEach(o => { if (o.id) orgMap[o.id] = o.name; });

    let groupedCerts = {};
    certs.forEach(cert => {
        let orgName = cert.org_id && orgMap[cert.org_id] ? orgMap[cert.org_id] : 'Organisation Inconnue';
        if (!groupedCerts[orgName]) groupedCerts[orgName] = [];
        groupedCerts[orgName].push(cert);
    });

    let html = '';
    
    Object.keys(groupedCerts).sort().forEach((orgName, idx) => {
        const orgCerts = groupedCerts[orgName];
        
        // Sparkline data
        const n30 = orgCerts.filter(c => c.days_left <= 30 && c.days_left > 7).length;
        const n7  = orgCerts.filter(c => c.days_left <= 7).length;
        const nOk = orgCerts.filter(c => c.days_left > 30).length;
        const maxSpark = Math.max(n30, n7, nOk, 1);
        const sparkHtml = `
            <div style="display:flex; align-items:flex-end; gap:4px; height:30px; margin-right:8px;" title="Actifs: ${nOk} | Bientôt: ${n30} | Critiques: ${n7}">
                <div style="width:8px;background:#10b981;height:${Math.max(4,(nOk/maxSpark)*26)}px;border-radius:3px 3px 0 0;"></div>
                <div style="width:8px;background:#f59e0b;height:${Math.max(4,(n30/maxSpark)*26)}px;border-radius:3px 3px 0 0;"></div>
                <div style="width:8px;background:#ef4444;height:${Math.max(4,(n7/maxSpark)*26)}px;border-radius:3px 3px 0 0;"></div>
            </div>
        `;
        
        let certsHtml = orgCerts.sort((a, b) => a.days_left - b.days_left).map(cert => {
            let statusColor = '#10b981'; let statusBadge = 'Actif';
            if (cert.days_left <= 7) { statusColor = '#ef4444'; statusBadge = 'Critique'; }
            else if (cert.days_left <= 30) { statusColor = '#f59e0b'; statusBadge = 'Expire Bientôt'; }
            if (cert.status === 'pending') { statusColor = '#6366f1'; statusBadge = 'En Attente'; }
            
            return `
                <div class="org-cert-row">
                    <div class="org-cert-domain">
                        <svg viewBox="0 0 24 24" fill="none" stroke="${statusColor}" stroke-width="2" style="width:16px;height:16px;"><rect x="3" y="11" width="18" height="11" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>
                        ${escapeHtml(cert.domain)}
                    </div>
                    <div class="org-cert-product">${escapeHtml(cert.product)}</div>
                    <div class="org-cert-expiry">Exp.: <span style="color:${statusColor};font-weight:500;">${escapeHtml(cert.valid_till||'N/A')}</span></div>
                    <div class="org-cert-status">
                        <span style="background:${statusColor}22;color:${statusColor};border:1px solid ${statusColor}44;font-size:10px;font-weight:bold;padding:3px 8px;border-radius:4px;">${statusBadge}</span>
                    </div>
                </div>`;
        }).join('');

        html += `
            <div class="org-block">
                <div class="org-block-header org-block-toggle" onclick="toggleOrgBlock(this)">
                    <div class="org-block-title">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:20px;height:20px;color:var(--accent-btn)"><rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path></svg>
                        ${escapeHtml(orgName)}
                    </div>
                    <div style="display:flex;align-items:center;gap:12px;">
                        ${sparkHtml}
                        <div class="org-badge">${orgCerts.length} Certificat${orgCerts.length > 1 ? 's' : ''}</div>
                        <svg class="org-collapse-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    </div>
                </div>
                <div class="org-block-content">${certsHtml}</div>
            </div>`;
    });

    container.innerHTML = html;
}

function toggleOrgBlock(headerEl) {
    const content = headerEl.nextElementSibling;
    const icon = headerEl.querySelector('.org-collapse-icon');
    content.classList.toggle('collapsed');
    icon.classList.toggle('collapsed');
}

// ===== REFRESH WITH SPINNER =====
window.refreshData = async function() {
    const btn = document.getElementById('refresh-btn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<div class="spin-ring" style="width:16px;height:16px;border-width:2px;"></div> Chargement...`;
    }
    if (window.pywebview) {
        await pywebview.api.force_refresh();
    }
    await loadDashboard();
    if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg> Rafraîchir`;
        showToast('Données mises à jour avec succès', 'success');
    }
};

// ===== CLM PIPELINE (suivi de cycle de vie / automatisation des relances) =====
// Le renouvellement peut rester manuel ou être automatisé (Paramètres → Renouvellement automatique).
// Cette couche automatise dans tous les cas le SUIVI : étape de chaque dossier, horodatage
// des relances et alertes, ce qui absorbe la charge de coordination de l'équipe.
const CLM_STAGES = [
    { key: 'todo', label: 'À traiter', color: '#94a3b8' },
    { key: 'approval', label: 'Approbation', color: '#f59e0b' },
    { key: 'dns', label: 'Vérification DNS', color: '#6366f1' },
    { key: 'order_install', label: 'Commande & Installation', color: '#38bdf8' },
    { key: 'done', label: 'Terminé', color: '#10b981' }
];
const CLM_STAGE_PREFIX = 'clm_stage_';
const CLM_CONTACT_PREFIX = 'clm_contacted_';

function clmStageIndex(key) {
    return CLM_STAGES.findIndex(s => s.key === key);
}

function clmGetStage(cert) {
    const stored = localStorage.getItem(CLM_STAGE_PREFIX + cert.domain);
    if (stored && clmStageIndex(stored) !== -1) return stored;
    if (cert.status === 'pending') return 'order_install';
    if (cert.prerequisites && cert.prerequisites.length > 0) return 'approval';
    return 'todo';
}

function clmSetStage(domain, stage) {
    localStorage.setItem(CLM_STAGE_PREFIX + domain, stage);
    if (window.lastData) renderPipeline(window.lastData.certs);
}

window.clmMoveStage = function(domain, direction) {
    const cert = (window.lastData && window.lastData.certs || []).find(c => c.domain === domain);
    if (!cert) return;
    const current = clmStageIndex(clmGetStage(cert));
    const next = Math.min(CLM_STAGES.length - 1, Math.max(0, current + direction));
    clmSetStage(domain, CLM_STAGES[next].key);
};

window.clmMarkContacted = function(domain, silent) {
    localStorage.setItem(CLM_CONTACT_PREFIX + domain, Date.now().toString());
    if (window.lastData) renderPipeline(window.lastData.certs);
    if (!silent) showToast('Relance enregistrée pour ' + domain, 'success');
};

function clmRelativeTime(ts) {
    if (!ts) return null;
    const diffMs = Date.now() - parseInt(ts, 10);
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return "à l'instant";
    if (mins < 60) return `il y a ${mins} min`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `il y a ${hours}h`;
    const days = Math.floor(hours / 24);
    return `il y a ${days}j`;
}

// Drop stored stage/contact data once a domain leaves the renewal window (e.g. it was renewed)
function clmCleanupStale(candidateDomains) {
    const domainSet = new Set(candidateDomains);
    const toRemove = [];
    for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (!key) continue;
        let domain = null;
        if (key.indexOf(CLM_STAGE_PREFIX) === 0) domain = key.slice(CLM_STAGE_PREFIX.length);
        else if (key.indexOf(CLM_CONTACT_PREFIX) === 0) domain = key.slice(CLM_CONTACT_PREFIX.length);
        if (domain !== null && !domainSet.has(domain)) toRemove.push(key);
    }
    toRemove.forEach(k => localStorage.removeItem(k));
}

function renderPipeline(certs) {
    const board = document.getElementById('pipeline-board');
    const countLabel = document.getElementById('pipeline-count-label');
    if (!board) return;

    const candidates = (certs || []).filter(c => c.status === 'pending' || (c.days_left <= 90 && c.days_left >= 0));
    clmCleanupStale(candidates.map(c => c.domain));

    if (countLabel) countLabel.innerText = `${candidates.length} certificat(s) à traiter (≤ 90j)`;

    if (candidates.length === 0) {
        board.innerHTML = '<div style="color: var(--text-muted); text-align:center; padding:60px 20px;">Aucun certificat à renouveler dans les 90 prochains jours.</div>';
        return;
    }

    const grouped = {};
    CLM_STAGES.forEach(s => grouped[s.key] = []);
    candidates.forEach(c => grouped[clmGetStage(c)].push(c));

    let html = '';
    CLM_STAGES.forEach((stage, idx) => {
        const items = grouped[stage.key].sort((a, b) => (a.days_left ?? 999) - (b.days_left ?? 999));
        html += `
            <div class="pipeline-column">
                <div class="pipeline-column-header">
                    <span class="pipeline-column-dot" style="background:${stage.color}"></span>
                    <span class="pipeline-column-title">${stage.label}</span>
                    <span class="pipeline-column-count">${items.length}</span>
                </div>
                <div class="pipeline-column-body">
                    ${items.length === 0 ? '<div class="pipeline-empty">Vide</div>' : items.map(cert => clmRenderCard(cert, idx)).join('')}
                </div>
            </div>`;
    });

    board.innerHTML = html;
}

function clmRenderCard(cert, stageIdx) {
    const domainSafe = escapeHtml(cert.domain);
    const isPending = cert.status === 'pending';
    const daysBadge = isPending ? 'Pending' : `${cert.days_left}j`;
    let daysColor = '#6366f1';
    if (!isPending) {
        if (cert.days_left <= 7) daysColor = '#ef4444';
        else if (cert.days_left <= 30) daysColor = '#f59e0b';
        else daysColor = '#38bdf8';
    }

    const contactedTs = localStorage.getItem(CLM_CONTACT_PREFIX + cert.domain);
    const contactedLabel = clmRelativeTime(contactedTs);

    const canPrev = stageIdx > 0;
    const canNext = stageIdx < CLM_STAGES.length - 1;

    return `
        <div class="pipeline-card">
            <div class="pipeline-card-top">
                <span class="pipeline-card-domain" title="${domainSafe}">${domainSafe}</span>
                <span class="pipeline-card-days" style="color:${daysColor}; border-color:${daysColor}44; background:${daysColor}1a;">${daysBadge}</span>
            </div>
            <div class="pipeline-card-product">${escapeHtml(cert.product || '')}</div>
            ${contactedLabel ? `<div class="pipeline-card-contacted">Dernière relance : ${contactedLabel}</div>` : ''}
            ${cert.note ? `<div class="pipeline-card-note" title="${escapeHtml(cert.note)}">${escapeHtml(cert.note.length > 42 ? cert.note.slice(0, 42) + '…' : cert.note)}</div>` : ''}
            <div class="pipeline-checklist">
                ${CHECKLIST_ITEMS.map(item => `
                    <span class="check-dot ${cert.checklist && cert.checklist[item.key] ? 'done' : ''}" title="${escapeHtml(item.label)}" onclick="toggleChecklistItem('${domainSafe}', '${item.key}', ${!(cert.checklist && cert.checklist[item.key])})">${item.label.charAt(0)}</span>
                `).join('')}
            </div>
            <div class="pipeline-card-actions">
                <button class="pipeline-mini-btn" title="Étape précédente" ${canPrev ? '' : 'disabled'} onclick="clmMoveStage('${domainSafe}', -1)">‹</button>
                <button class="pipeline-mini-btn pipeline-mini-btn-main" onclick="closeDetails(); openDraftModal('${domainSafe}')">Contacter</button>
                <button class="pipeline-mini-btn" title="Étape suivante" ${canNext ? '' : 'disabled'} onclick="clmMoveStage('${domainSafe}', 1)">›</button>
            </div>
        </div>
    `;
}

// ===== COMPLIANCE & TRENDS =====
// Backed by main.py's get_compliance_data(): aggregates validity periods by
// product (real durations, computed from issued_date -> valid_till) plus the
// renewal history logged automatically by detect_renewals() on every load.
async function renderCompliance() {
    const statsRow = document.getElementById('compliance-stats-row');
    const productList = document.getElementById('compliance-product-list');
    const historyList = document.getElementById('renewal-history-list');
    const historyCount = document.getElementById('renewal-history-count');
    if (!statsRow || !window.pywebview) return;

    statsRow.innerHTML = `<div style="color:var(--text-muted); font-size:13px; padding:10px;">Chargement...</div>`;
    productList.innerHTML = '';
    historyList.innerHTML = '';

    let data;
    try {
        data = await pywebview.api.get_compliance_data();
    } catch (e) {
        statsRow.innerHTML = `<div style="color:#ef4444; font-size:13px; padding:10px;">Erreur de chargement des données de conformité.</div>`;
        return;
    }

    const products = data.products || [];
    const history = data.history || [];

    const totalCerts = products.reduce((sum, p) => sum + p.count, 0);
    const overallAvg = totalCerts > 0 ? Math.round(products.reduce((sum, p) => sum + p.avg_validity_days * p.count, 0) / totalCerts) : 0;
    const shortLivedCount = products.filter(p => p.avg_validity_days <= 100).reduce((sum, p) => sum + p.count, 0);

    statsRow.innerHTML = `
        <div class="stat-card">
            <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg></div>
            <div class="stat-info"><span class="stat-value">${overallAvg}j</span><span class="stat-label">Durée de validité moyenne</span></div>
        </div>
        <div class="stat-card warning">
            <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg></div>
            <div class="stat-info"><span class="stat-value">${shortLivedCount}</span><span class="stat-label">Certificats ≤ 100 jours</span></div>
        </div>
        <div class="stat-card pending">
            <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"></polyline><polyline points="1 20 1 14 7 14"></polyline><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"></path></svg></div>
            <div class="stat-info"><span class="stat-value">${history.length}</span><span class="stat-label">Renouvellements enregistrés</span></div>
        </div>
    `;

    if (products.length === 0) {
        productList.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:20px;">Pas encore assez de données (nécessite des certificats avec une date d'émission connue).</div>`;
    } else {
        const maxValidity = Math.max(...products.map(p => p.max_validity_days), 1);
        productList.innerHTML = products.map(p => {
            const pct = Math.max(4, Math.round((p.avg_validity_days / maxValidity) * 100));
            const color = p.avg_validity_days <= 100 ? '#f59e0b' : '#10b981';
            return `
                <div style="margin-bottom: 14px;">
                    <div style="display:flex; justify-content:space-between; font-size:12.5px; margin-bottom:5px;">
                        <span style="color:var(--text-bright); font-weight:500;">${escapeHtml(p.product)} <span style="color:var(--text-muted-dark); font-weight:400;">(${p.count})</span></span>
                        <span style="color:${color}; font-weight:600;">${p.avg_validity_days}j en moyenne</span>
                    </div>
                    <div class="expiry-bar"><div class="expiry-bar-fill" style="width:${pct}%; background:${color};"></div></div>
                </div>
            `;
        }).join('');
    }

    if (historyCount) historyCount.textContent = history.length;
    if (history.length === 0) {
        historyList.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:20px;">Aucun renouvellement détecté pour l'instant — ça se remplira automatiquement au fil des rafraîchissements.</div>`;
    } else {
        historyList.innerHTML = history.slice(0, 50).map(h => `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:10px 0; border-bottom:1px solid var(--border-ultralight);">
                <div>
                    <div style="font-size:13px; color:var(--text-bright); font-weight:500;">${escapeHtml(h.domain)}</div>
                    <div style="font-size:11px; color:var(--text-muted-dark);">${escapeHtml(h.old_valid_till)} → ${escapeHtml(h.new_valid_till)} · ${escapeHtml(h.product || '')}</div>
                </div>
                <div style="font-size:11px; color:var(--text-muted);">${escapeHtml((h.detected_at || '').slice(0, 10))}</div>
            </div>
        `).join('');
    }
}

// ===== AGENTS & DISCOVERY =====
// Backed by main.py's embedded HTTP listener (Api.get_agents / get_discovery_summary)
// and by CertHelmAgent.exe / certhelm_agent.py running on the servers.

async function loadAgentSettingsInfo() {
    const urlInput = document.getElementById('agent-listener-url');
    const statusInput = document.getElementById('agent-listener-status');
    const tokenInput = document.getElementById('agent-token-display');
    if (!urlInput || !window.pywebview) return;

    try {
        const cfg = await pywebview.api.get_agent_config();
        urlInput.value = cfg.listener_url_hint;
        statusInput.value = cfg.listener_running ? `En écoute sur le port ${cfg.listener_port}` : 'Non démarré';
        statusInput.style.color = cfg.listener_running ? '#10b981' : '#ef4444';
        tokenInput.value = cfg.token_masked;
    } catch (e) {
        statusInput.value = 'Erreur de chargement';
    }
}

if (document.getElementById('agent-regenerate-token-btn')) {
    document.getElementById('agent-regenerate-token-btn').addEventListener('click', async () => {
        if (!confirm("Régénérer le token ? Les agents déjà déployés avec l'ancien token devront être reconfigurés.")) return;
        try {
            const res = await pywebview.api.regenerate_agent_token();
            const revealEl = document.getElementById('agent-token-reveal');
            revealEl.style.display = 'block';
            revealEl.innerHTML = `Nouveau token (copiez-le maintenant, il ne sera plus jamais affiché en clair) : <code style="user-select:all;">${escapeHtml(res.token)}</code>`;
            showToast('Token régénéré avec succès', 'success');
            loadAgentSettingsInfo();
        } catch (e) {
            showToast('Erreur lors de la régénération du token', 'error');
        }
    });
}

function relativeTimeFromHours(hours) {
    if (hours === null || hours === undefined) return 'Jamais';
    if (hours < 1) return "à l'instant";
    if (hours < 24) return `il y a ${Math.round(hours)}h`;
    return `il y a ${Math.round(hours / 24)}j`;
}

function relativeTimeFromSeconds(seconds) {
    if (seconds === null || seconds === undefined) return 'Jamais';
    if (seconds < 90) return `il y a ${Math.max(0, Math.round(seconds))} s`;
    if (seconds < 3600) return `il y a ${Math.round(seconds / 60)} min`;
    return relativeTimeFromHours(seconds / 3600);
}

function agentFormatDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return isNaN(d) ? '—' : d.toLocaleString('fr-FR');
}

function agentDaysUntil(dateStr) {
    const d = new Date(String(dateStr || '').slice(0, 10) + 'T00:00:00');
    if (isNaN(d)) return null;
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    return Math.round((d - today) / 86400000);
}

async function copyText(text, okMessage) {
    try {
        await navigator.clipboard.writeText(text);
        showToast(okMessage || 'Copié', 'success');
    } catch (e) {
        showToast('Copie impossible : sélectionnez le texte et copiez-le à la main.', 'error');
    }
}

async function renderAgentInstallCard() {
    const el = document.getElementById('agent-install-card');
    if (!el || !window.pywebview) return;
    let url = '';
    try { url = (await pywebview.api.get_agent_config()).listener_url_hint; } catch (e) { /* card still useful without it */ }
    el.innerHTML = `
        <ol style="margin:0; padding-left:20px;">
            <li>Remettez <strong>CertHelmAgent_Setup.exe</strong> à l'administrateur du serveur (un seul fichier, à lancer en administrateur).</li>
            <li>Il y saisit l'adresse de CertHelm <code id="agent-install-url" style="user-select:all;">${escapeHtml(url)}</code>
                <button class="btn-primary-action" id="agent-copy-url-btn" style="margin-left:6px; padding:2px 10px;">Copier</button>
                et le jeton (<a href="#" id="agent-goto-token" style="color:var(--accent-btn);">Paramètres → Agents &amp; Découverte</a>, bouton « Régénérer le token » : il n'est affiché qu'une fois).</li>
            <li>Il clique <strong>Installer</strong> : l'agent démarre avec Windows et le serveur apparaît dans la liste ci-dessous en quelques secondes.</li>
        </ol>`;
    document.getElementById('agent-copy-url-btn').addEventListener('click', () => copyText(url, "Adresse copiée"));
    document.getElementById('agent-goto-token').addEventListener('click', (e) => {
        e.preventDefault();
        handleNotificationClick({ target: { kind: 'settings', value: 'agents' } });
    });
}

async function renderAgents() {
    const statsRow = document.getElementById('agents-stats-row');
    const agentsList = document.getElementById('agents-list');
    const notInstalledList = document.getElementById('agents-not-installed-list');
    const unknownList = document.getElementById('agents-unknown-list');
    if (!statsRow || !window.pywebview) return;

    statsRow.innerHTML = `<div style="color:var(--text-muted); font-size:13px; padding:10px;">Chargement...</div>`;
    agentsList.innerHTML = '';
    notInstalledList.innerHTML = '';
    unknownList.innerHTML = '';
    renderAgentInstallCard();

    let agents, summary;
    try {
        [agents, summary] = await Promise.all([
            pywebview.api.get_agents(),
            pywebview.api.get_discovery_summary()
        ]);
    } catch (e) {
        statsRow.innerHTML = `<div style="color:#ef4444; font-size:13px; padding:10px;">Erreur de chargement des données agents.</div>`;
        return;
    }

    const onlineCount = agents.filter(a => a.enabled && a.online).length;

    statsRow.innerHTML = `
        <div class="stat-card">
            <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="6" height="6" rx="1"></rect><rect x="14" y="4" width="6" height="6" rx="1"></rect><rect x="4" y="14" width="6" height="6" rx="1"></rect><rect x="14" y="14" width="6" height="6" rx="1"></rect></svg></div>
            <div class="stat-info"><span class="stat-value">${agents.length}</span><span class="stat-label">Agents enregistrés</span></div>
        </div>
        <div class="stat-card">
            <div class="stat-icon" style="background:rgba(16,185,129,0.1);"><svg viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg></div>
            <div class="stat-info"><span class="stat-value">${onlineCount}</span><span class="stat-label">En ligne</span></div>
        </div>
        <div class="stat-card warning">
            <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg></div>
            <div class="stat-info"><span class="stat-value">${summary.not_installed.length}</span><span class="stat-label">Jamais détectés installés</span></div>
        </div>
        <div class="stat-card critical">
            <div class="stat-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg></div>
            <div class="stat-info"><span class="stat-value">${summary.unknown_to_digicert.length}</span><span class="stat-label">Inconnus de DigiCert</span></div>
        </div>
    `;

    if (agents.length === 0) {
        agentsList.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:20px;">Aucun agent n'a encore fait de check-in. Suivez les étapes de « Installer un agent sur un serveur » ci-dessus.</div>`;
    } else {
        agentsCache = agents;
        agentsList.innerHTML = agents.map((a, i) => {
            const dotColor = !a.enabled ? '#6b7280' : (a.online ? '#10b981' : '#ef4444');
            const statusText = !a.enabled ? 'Désactivé' : (a.online ? 'En ligne' : 'Hors ligne');
            const parts = [escapeHtml(a.os || 'OS inconnu')];
            if (a.last_ip) parts.push(escapeHtml(a.last_ip));
            if (!a.supports_commands) {
                parts.push('<span style="color:#f59e0b;">ancienne version — pas de pilotage à distance</span>');
            } else if (a.pending_commands) {
                parts.push('<span style="color:var(--accent-color, #009FDF);">commande en attente…</span>');
            }
            if (a.cert_management === true) parts.push('<span style="color:#10b981;">renouvellement autorisé</span>');
            else if (a.cert_management === false) parts.push('renouvellement non autorisé');
            return `
            <div class="agent-block" data-agent-host="${escapeHtml(a.hostname)}" style="margin-bottom:10px;">
                <div class="cert-card" style="flex-wrap:wrap; gap:10px;">
                    <div style="flex:2; min-width:200px; display:flex; align-items:center; gap:10px;">
                        <div style="width:8px; height:8px; border-radius:50%; background:${dotColor}; flex-shrink:0;"></div>
                        <div>
                            <div style="font-weight:500; color:var(--text-bright);">${escapeHtml(a.hostname)} <span style="font-size:11px; font-weight:500; color:${dotColor};">${statusText}</span></div>
                            <div style="font-size:11px; color:var(--text-muted-dark);">${parts.join(' · ')}</div>
                        </div>
                    </div>
                    <div style="flex:1; min-width:120px; font-size:12px; color:var(--text-muted);">Dernier scan : ${relativeTimeFromHours(a.hours_since_checkin)}</div>
                    <div style="flex:1; min-width:90px; font-size:12px; color:var(--text-muted);">${a.cert_count} certificat(s)</div>
                    <div style="flex:1; min-width:50px; font-size:11px; color:var(--text-muted-dark);">v${escapeHtml(a.agent_version || '?')}</div>
                    <div style="display:flex; gap:8px; flex-shrink:0; position:relative; z-index:1;">
                        <button class="btn-primary-action" data-agent-action="scan" data-agent-index="${i}" ${(a.supports_commands && a.enabled) ? '' : 'disabled style="opacity:0.4; cursor:not-allowed;"'}>Scanner maintenant</button>
                        <button class="btn-primary-action" data-agent-action="details" data-agent-index="${i}">Détails</button>
                    </div>
                </div>
                <div class="agent-settings-panel" id="agent-panel-${i}" style="display:none; border:1px solid var(--border-light); border-top:none; border-radius:0 0 12px 12px; padding:16px 20px; background:var(--card-bg);"></div>
            </div>`;
        }).join('');
    }

    if (summary.not_installed.length === 0) {
        notInstalledList.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:15px;">Aucun — tout ce que DigiCert connaît a été retrouvé installé quelque part.</div>`;
    } else {
        notInstalledList.innerHTML = summary.not_installed.map(c => `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid var(--border-ultralight);">
                <span style="font-size:13px; color:var(--text-bright);">${escapeHtml(c.domain)}</span>
                <span style="font-size:11px; color:var(--text-muted-dark);">${escapeHtml(c.product || '')} · ${c.days_left !== null && c.days_left !== undefined ? c.days_left + 'j restants' : ''}</span>
            </div>
        `).join('');
    }

    if (summary.unknown_to_digicert.length === 0) {
        unknownList.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:15px;">Aucun — tout ce que les agents ont trouvé correspond à l'inventaire DigiCert.</div>`;
    } else {
        unknownList.innerHTML = summary.unknown_to_digicert.map(c => `
            <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid var(--border-ultralight);">
                <div>
                    <span style="font-size:13px; color:var(--text-bright);">${escapeHtml(c.domain)}</span>
                    <span style="font-size:11px; color:var(--text-muted-dark);"> — ${escapeHtml(c.hostname)}</span>
                </div>
                <span style="font-size:11px; color:var(--text-muted-dark);">${escapeHtml(c.issuer || 'Émetteur inconnu')}</span>
            </div>
        `).join('');
    }

    renderRenewals();
    focusPendingAgent();
}

// Coming from an alert ("Agent hors ligne", a failed renewal...): scroll to that server and flash it.
function focusPendingAgent() {
    if (!pendingAgentFocus) return;
    const block = Array.from(document.querySelectorAll('[data-agent-host]'))
        .find(el => el.dataset.agentHost === pendingAgentFocus);
    pendingAgentFocus = null;
    if (!block) return;
    block.scrollIntoView({ behavior: 'smooth', block: 'center' });
    block.style.transition = 'box-shadow 0.4s';
    block.style.boxShadow = '0 0 0 2px #009FDF';
    setTimeout(() => { block.style.boxShadow = ''; }, 2200);
}

// ===== AGENT CONTROL (scan now / remote settings / details) =====
// Commands are queued on the controller and picked up by the agent the next time
// it polls (every ~30s) - the controller never connects out to the agent.

let agentsCache = [];
const AGENT_INTERVAL_CHOICES = [1, 2, 6, 12, 24, 72, 168];
const AGENT_COMMAND_LABELS = {
    scan_now: 'Scan immédiat',
    generate_csr: 'Préparation de la demande de certificat',
    install_cert: 'Installation du certificat'
};
const AGENT_STATUS_LABELS = { pending: 'En attente', delivered: 'Envoyée', done: 'Terminée', failed: 'Échec' };

function formatAgentInterval(hours) {
    if (hours < 24) return `Toutes les ${hours} h`;
    return hours % 24 === 0 ? `Tous les ${hours / 24} j` : `Toutes les ${hours} h`;
}

document.addEventListener('click', (event) => {
    const btn = event.target.closest('[data-agent-action]');
    if (!btn || btn.disabled) return;
    const agent = agentsCache[Number(btn.dataset.agentIndex)];
    if (!agent) return;
    if (btn.dataset.agentAction === 'scan') requestAgentScan(agent, btn);
    else if (btn.dataset.agentAction === 'details') toggleAgentDetails(agent, Number(btn.dataset.agentIndex));
});

async function requestAgentScan(agent, btn) {
    const originalLabel = btn.textContent;
    btn.disabled = true;
    btn.style.opacity = '0.6';
    btn.textContent = 'En attente…';
    try {
        const res = await pywebview.api.request_agent_scan(agent.hostname);
        if (res.status !== 'success') {
            showToast(res.message || 'Impossible de demander le scan', 'error');
            btn.disabled = false; btn.style.opacity = ''; btn.textContent = originalLabel;
            return;
        }
        showToast(`Scan demandé à ${escapeHtml(agent.hostname)} — l'agent répond sous ~30 s`, 'info');
        const outcome = await waitForAgentCommand(agent.hostname, res.command_id);
        if (outcome && outcome.status === 'done') {
            showToast(`${escapeHtml(agent.hostname)} : ${escapeHtml(outcome.result || 'scan terminé')}`, 'success');
        } else if (outcome && outcome.status === 'failed') {
            showToast(`${escapeHtml(agent.hostname)} : ${escapeHtml(outcome.result || 'échec du scan')}`, 'error');
        } else {
            showToast(`${escapeHtml(agent.hostname)} n'a pas répondu. L'agent est-il bien lancé ?`, 'error');
        }
    } catch (e) {
        showToast('Erreur lors de la demande de scan', 'error');
    }
    renderAgents();
    refreshAlerts();
}

// Polls the command's status until the agent reports back (or ~2 minutes pass).
async function waitForAgentCommand(hostname, commandId) {
    const deadline = Date.now() + 120000;
    while (Date.now() < deadline) {
        await new Promise(r => setTimeout(r, 2000));
        try {
            const commands = await pywebview.api.get_agent_commands(hostname);
            const cmd = commands.find(c => c.id === commandId);
            if (cmd && (cmd.status === 'done' || cmd.status === 'failed')) return cmd;
        } catch (e) { /* transient - keep waiting */ }
    }
    return null;
}

function agentInfoRow(label, valueHtml) {
    return `<div style="display:flex; gap:10px; padding:3px 0;"><span style="flex:0 0 150px; color:var(--text-muted-dark);">${label}</span><span style="color:var(--text-bright); min-width:0; overflow-wrap:anywhere;">${valueHtml}</span></div>`;
}

async function toggleAgentDetails(agent, index) {
    const panel = document.getElementById(`agent-panel-${index}`);
    if (!panel) return;
    if (panel.style.display !== 'none') { panel.style.display = 'none'; return; }

    const choices = AGENT_INTERVAL_CHOICES.includes(agent.interval_hours)
        ? AGENT_INTERVAL_CHOICES
        : [...AGENT_INTERVAL_CHOICES, agent.interval_hours].sort((a, b) => a - b);

    const renewalText = agent.cert_management === true
        ? '<span style="color:#10b981;">Autorisé par l\'administrateur du serveur</span>'
        : (agent.cert_management === false
            ? 'Non autorisé — à activer en réinstallant l\'agent avec la case « Autoriser CertHelm à renouveler »'
            : 'Inconnu (l\'agent ne l\'a pas encore indiqué)');
    const alive = agent.supports_commands && agent.seconds_since_seen !== undefined
        ? relativeTimeFromSeconds(agent.seconds_since_seen)
        : relativeTimeFromHours(agent.hours_since_checkin);

    const controls = agent.supports_commands ? `
        <div style="display:flex; gap:24px; flex-wrap:wrap; align-items:flex-end; margin-top:14px;">
            <div>
                <label style="display:block; font-size:12px; color:var(--text-muted); margin-bottom:4px;">Fréquence de scan automatique</label>
                <select class="form-input" id="agent-interval-${index}" style="width:auto; min-width:170px; margin-top:0;">
                    ${choices.map(h => `<option value="${h}" ${h === agent.interval_hours ? 'selected' : ''}>${formatAgentInterval(h)}</option>`).join('')}
                </select>
            </div>
            <label style="display:flex; align-items:center; gap:8px; font-size:13px; color:var(--text-bright); cursor:pointer; padding-bottom:8px;">
                <input type="checkbox" id="agent-enabled-${index}" ${agent.enabled ? 'checked' : ''} style="accent-color:#009FDF;">
                Agent actif
            </label>
            <button class="btn-primary-action" id="agent-save-${index}" style="margin-bottom:4px;">Enregistrer</button>
        </div>
        <div style="font-size:11px; color:var(--text-muted-dark); margin-top:8px;">
            Pris en compte au prochain contact de l'agent (moins de 30 s). Un agent désactivé ne scanne plus et n'envoie plus rien tant qu'il n'est pas réactivé.
        </div>` : `
        <div style="font-size:12px; color:#f59e0b; margin-top:14px;">Cet agent est une ancienne version : réinstallez la dernière version avec CertHelmAgent_Setup.exe pour pouvoir le piloter d'ici.</div>`;

    panel.innerHTML = `
        <div style="font-size:12px;">
            ${agentInfoRow('Nom du serveur', escapeHtml(agent.hostname))}
            ${agentInfoRow('Système', escapeHtml(agent.os || 'Inconnu'))}
            ${agentInfoRow('Adresse IP', escapeHtml(agent.last_ip || '—'))}
            ${agentInfoRow("Version de l'agent", 'v' + escapeHtml(agent.agent_version || '?'))}
            ${agentInfoRow('Premier contact', escapeHtml(agentFormatDate(agent.first_seen)))}
            ${agentInfoRow('Dernier scan', escapeHtml(agentFormatDate(agent.last_checkin)))}
            ${agentInfoRow('Dernier signe de vie', escapeHtml(alive))}
            ${agentInfoRow('Renouvellement automatique', renewalText)}
        </div>
        ${controls}
        <div style="font-size:12px; color:var(--text-muted); margin:16px 0 6px;">Certificats détectés sur ce serveur</div>
        <div id="agent-certs-${index}" style="font-size:12px; color:var(--text-muted-dark);">Chargement…</div>
        <div style="font-size:12px; color:var(--text-muted); margin:16px 0 6px;">Dernières commandes</div>
        <div id="agent-history-${index}" style="font-size:12px; color:var(--text-muted-dark);">Chargement…</div>
        <div style="margin-top:18px; padding-top:12px; border-top:1px solid var(--border-ultralight); display:flex; align-items:center; gap:14px; flex-wrap:wrap;">
            <button class="btn-primary-action" id="agent-delete-${index}" style="color:#ef4444; border-color:rgba(239,68,68,0.4);">Retirer de la console</button>
            <span style="font-size:11px; color:var(--text-muted-dark);">Oublie ce serveur et ses certificats. Si l'agent tourne encore, il se ré-enregistrera à son prochain contact : désinstallez-le d'abord sur le serveur.</span>
        </div>
    `;
    panel.style.display = 'block';

    const saveBtn = document.getElementById(`agent-save-${index}`);
    if (saveBtn) saveBtn.addEventListener('click', async () => {
        const interval = Number(document.getElementById(`agent-interval-${index}`).value);
        const enabled = document.getElementById(`agent-enabled-${index}`).checked;
        try {
            const res = await pywebview.api.update_agent_settings(agent.hostname, enabled, interval);
            if (res.status === 'success') {
                showToast(`Réglages enregistrés pour ${escapeHtml(agent.hostname)}`, 'success');
                renderAgents();
                refreshAlerts();
            } else {
                showToast(res.message || 'Réglages refusés', 'error');
            }
        } catch (e) {
            showToast("Erreur lors de l'enregistrement des réglages", 'error');
        }
    });

    document.getElementById(`agent-delete-${index}`).addEventListener('click', async () => {
        if (!confirm(`Retirer « ${agent.hostname} » de la console ?\n\nLe serveur et les certificats qu'il a remontés disparaissent de CertHelm. Cela ne désinstalle pas l'agent : s'il tourne encore, le serveur réapparaîtra à son prochain contact.`)) return;
        try {
            const res = await pywebview.api.delete_agent(agent.hostname);
            if (res.status === 'success') {
                showToast(`${escapeHtml(agent.hostname)} retiré de la console`, 'success');
                renderAgents();
                refreshAlerts();
            } else {
                showToast(escapeHtml(res.message || 'Suppression refusée'), 'error');
            }
        } catch (e) {
            showToast('Erreur lors de la suppression', 'error');
        }
    });

    const certsEl = document.getElementById(`agent-certs-${index}`);
    try {
        const certs = await pywebview.api.get_agent_certs(agent.hostname);
        certsEl.innerHTML = certs.length === 0 ? 'Aucun certificat détecté au dernier scan.' : certs.map(c => {
            const d = agentDaysUntil(c.valid_till);
            const color = d === null ? 'var(--text-muted)' : (d <= 7 ? '#ef4444' : (d <= 30 ? '#f59e0b' : '#10b981'));
            const dayText = d === null ? '?' : (d < 0 ? `expiré depuis ${-d} j` : `${d} j`);
            return `
            <div style="display:flex; gap:12px; align-items:center; padding:5px 0; border-bottom:1px solid var(--border-ultralight);">
                <div style="flex:3; min-width:0;">
                    <div style="color:var(--text-bright); overflow:hidden; text-overflow:ellipsis;">${escapeHtml(c.domain || '?')}</div>
                    <div style="font-size:11px;">${escapeHtml(c.issuer || 'émetteur inconnu')} · ${escapeHtml(c.install_path || '')}</div>
                </div>
                <div style="flex:1; color:${color}; white-space:nowrap;">${dayText}<span style="color:var(--text-muted-dark);"> · ${escapeHtml(c.valid_till || '')}</span></div>
            </div>`;
        }).join('');
    } catch (e) {
        certsEl.textContent = 'Liste indisponible.';
    }

    const historyEl = document.getElementById(`agent-history-${index}`);
    try {
        const commands = await pywebview.api.get_agent_commands(agent.hostname);
        historyEl.innerHTML = commands.length === 0 ? 'Aucune commande envoyée.' : commands.slice(0, 5).map(c => `
            <div style="display:flex; justify-content:space-between; gap:12px; padding:4px 0; border-bottom:1px solid var(--border-ultralight);">
                <span>${escapeHtml(AGENT_COMMAND_LABELS[c.type] || c.type)} — ${escapeHtml(AGENT_STATUS_LABELS[c.status] || c.status)}${c.result ? ' · ' + escapeHtml(c.result) : ''}</span>
                <span>${escapeHtml(new Date(c.created_at).toLocaleString('fr-FR'))}</span>
            </div>`).join('');
    } catch (e) {
        historyEl.textContent = 'Historique indisponible.';
    }
}

// ===== CERTIFICATE RENEWAL (see renewal.py) =====
// "Renouveler" places a real DigiCert order (possibly billed), has the agent build a
// new key + CSR on the server and install the issued certificate. A confirmation that
// spells out the exact order is always required first.

let renewalSettings = { mode: 'live' };
let renewalCertsCache = [];
let renewalRefreshTimer = null;

const RENEWAL_TERMINAL = ['installed', 'failed', 'cancelled'];
const RENEWAL_STATUS = {
    awaiting_csr: ["En attente de l'agent", '#009FDF'],
    csr_ready:    ['Préparation de la commande', '#009FDF'],
    ordering:     ['Envoi de la commande', '#009FDF'],
    ordered:      ["Commandé — en attente d'émission", '#f59e0b'],
    installing:   ['Installation en cours', '#009FDF'],
    installed:    ['Installé', '#10b981'],
    failed:       ['Échec', '#ef4444'],
    cancelled:    ['Annulé', '#6b7280'],
    uncertain:    ['Statut incertain', '#ef4444']
};

function renewalStatusPill(status) {
    const [label, color] = RENEWAL_STATUS[status] || [status, '#6b7280'];
    return `<span style="font-size:11px; padding:2px 8px; border-radius:10px; color:${color}; background:${color}22; white-space:nowrap;">${escapeHtml(label)}</span>`;
}

function renewalModeBadge(mode) {
    const map = { off: ['Désactivé', '#6b7280'], live: ['Activé', '#10b981'] };
    const [label, color] = map[mode] || [mode, '#6b7280'];
    return `<span style="color:${color}; background:${color}22; padding:2px 8px; border-radius:10px;">${escapeHtml(label)}</span>`;
}

async function renderRenewals() {
    const certsEl = document.getElementById('renewal-certs-list');
    const jobsEl = document.getElementById('renewal-jobs-list');
    if (!certsEl || !jobsEl || !window.pywebview) return;

    let settings, certs, jobs;
    try {
        [settings, certs, jobs] = await Promise.all([
            pywebview.api.get_renewal_settings(),
            pywebview.api.get_certificates_overview(),
            pywebview.api.get_renewal_jobs()
        ]);
    } catch (e) {
        certsEl.innerHTML = `<div style="color:#ef4444; font-size:13px; padding:10px;">Erreur de chargement des certificats.</div>`;
        return;
    }
    renewalSettings = settings;
    renewalCertsCache = certs;

    const badge = document.getElementById('renewal-mode-badge');
    if (badge) badge.innerHTML = renewalModeBadge(settings.mode);

    if (certs.length === 0) {
        certsEl.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:15px;">Aucun certificat remonté par les agents pour l'instant.</div>`;
    } else {
        certsEl.innerHTML = certs.map((c, i) => {
            const d = c.days_left;
            const dayColor = d === null ? 'var(--text-muted)' : (d <= 7 ? '#ef4444' : (d <= 30 ? '#f59e0b' : 'var(--text-muted)'));
            const dayText = d === null ? '?' : (d < 0 ? 'expiré' : `${d} j`);
            const job = c.job;
            let action;
            if (job && !RENEWAL_TERMINAL.includes(job.status)) {
                action = renewalStatusPill(job.status);
            } else if (c.can_renew) {
                action = `<button class="btn-primary-action" data-renew-index="${i}">Renouveler</button>`;
            } else {
                action = `<span style="font-size:11px; color:var(--text-muted-dark);">${escapeHtml(c.reason || '')}</span>`;
            }
            return `
            <div style="display:flex; align-items:center; gap:12px; padding:8px 4px; border-bottom:1px solid var(--border-ultralight);">
                <div style="flex:3; min-width:0;">
                    <div style="font-size:13px; color:var(--text-bright); overflow:hidden; text-overflow:ellipsis;">${escapeHtml(c.domain)}</div>
                    <div style="font-size:11px; color:var(--text-muted-dark);">${escapeHtml(c.hostname)} · ${escapeHtml(c.issuer || 'émetteur inconnu')}</div>
                </div>
                <div style="flex:1; font-size:12px; color:${dayColor}; white-space:nowrap;">${dayText}<span style="color:var(--text-muted-dark);"> · ${escapeHtml(c.valid_till || '')}</span></div>
                <div style="flex:2; min-width:0; font-size:11px; color:var(--text-muted-dark); overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(c.install_path || '')}">${escapeHtml(c.install_path || '')}</div>
                <div style="flex:1.5; text-align:right;">${action}</div>
            </div>`;
        }).join('');
    }

    const countEl = document.getElementById('renewal-jobs-count');
    if (countEl) countEl.textContent = jobs.length;
    if (jobs.length === 0) {
        jobsEl.innerHTML = `<div style="color:var(--text-muted); text-align:center; padding:15px;">Aucun renouvellement lancé.</div>`;
    } else {
        jobsEl.innerHTML = jobs.map(j => {
            const active = !RENEWAL_TERMINAL.includes(j.status);
            const detail = j.payload
                ? `<details style="margin-top:6px;"><summary style="cursor:pointer; font-size:11px; color:var(--text-muted);">Voir la requête envoyée à DigiCert (sans la clé privée)</summary><pre style="font-size:11px; white-space:pre-wrap; color:var(--text-muted); margin:6px 0 0;">${escapeHtml(JSON.stringify(j.payload, null, 2))}</pre></details>`
                : '';
            return `
            <div style="padding:10px 4px; border-bottom:1px solid var(--border-ultralight);">
                <div style="display:flex; align-items:center; gap:12px;">
                    <div style="flex:1; min-width:0; font-size:13px; color:var(--text-bright);">#${j.id} · ${escapeHtml(j.domain)} <span style="font-size:11px; color:var(--text-muted-dark);">— ${escapeHtml(j.hostname)}</span></div>
                    <div>${renewalStatusPill(j.status)}</div>
                    <div style="font-size:11px; color:var(--text-muted-dark); white-space:nowrap;">${escapeHtml(new Date(j.updated_at).toLocaleString('fr-FR'))}</div>
                    ${active ? `<button class="btn-primary-action" data-renew-cancel="${j.id}">Annuler</button>` : ''}
                </div>
                <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">${escapeHtml(j.message || '')}</div>
                ${detail}
            </div>`;
        }).join('');
    }

    // Keep the view live while something is in flight (only these two lists are redrawn).
    clearTimeout(renewalRefreshTimer);
    const view = document.getElementById('view-agents');
    if (jobs.some(j => !RENEWAL_TERMINAL.includes(j.status)) && view && view.style.display !== 'none') {
        renewalRefreshTimer = setTimeout(renderRenewals, 10000);
    }
}

document.addEventListener('click', async (event) => {
    const renewBtn = event.target.closest('[data-renew-index]');
    if (renewBtn && !renewBtn.disabled) {
        const cert = renewalCertsCache[Number(renewBtn.dataset.renewIndex)];
        if (!cert) return;
        renewBtn.disabled = true;

        // Ask the controller exactly what would be ordered, and show it before anything happens.
        let preview;
        try {
            preview = await pywebview.api.preview_renewal(cert.hostname, cert.thumbprint);
        } catch (e) {
            renewBtn.disabled = false;
            showToast('Erreur lors de la préparation du renouvellement', 'error');
            return;
        }
        if (preview.status !== 'success') {
            renewBtn.disabled = false;
            showToast(escapeHtml(preview.message || 'Renouvellement impossible'), 'error');
            return;
        }
        const question =
            `RENOUVELLEMENT de ${preview.domain} sur ${preview.hostname}\n\n` +
            `Commande DigiCert : produit ${preview.product}, ${preview.validity_years || 1} an(s), ` +
            `renouvellement de la commande n° ${preview.original_order_id}.\n` +
            `Noms couverts : ${(preview.dns_names || []).join(', ')}\n` +
            `Cette commande peut être facturée par DigiCert.\n\n` +
            `1. L'agent génère une nouvelle clé et une demande de certificat sur le serveur.\n` +
            `2. CertHelm passe la commande chez DigiCert.\n` +
            `3. Le certificat émis remplace automatiquement l'ancien sur ce serveur (l'ancien est conservé).\n\n` +
            `Confirmer ?`;
        if (!confirm(question)) {
            renewBtn.disabled = false;
            return;
        }
        try {
            const res = await pywebview.api.start_renewal(cert.hostname, cert.thumbprint);
            if (res.status === 'success') {
                showToast('Renouvellement lancé — voir « Suivi des renouvellements »', 'success');
            } else {
                showToast(escapeHtml(res.message || 'Renouvellement refusé'), 'error');
            }
        } catch (e) {
            showToast('Erreur lors du lancement du renouvellement', 'error');
        }
        renderRenewals();
        refreshAlerts();
        return;
    }
    const cancelBtn = event.target.closest('[data-renew-cancel]');
    if (cancelBtn) {
        if (!confirm("Annuler ce renouvellement ?\n\nSi une commande a déjà été passée chez DigiCert, elle n'est PAS annulée automatiquement : il faudra le faire depuis le portail DigiCert.")) return;
        try {
            const res = await pywebview.api.cancel_renewal(Number(cancelBtn.dataset.renewCancel));
            showToast(res.status === 'success' ? 'Renouvellement annulé' : escapeHtml(res.message || 'Annulation refusée'),
                      res.status === 'success' ? 'success' : 'error');
        } catch (e) {
            showToast("Erreur lors de l'annulation", 'error');
        }
        renderRenewals();
        refreshAlerts();
    }
});

async function loadRenewalSettings() {
    const modeEl = document.getElementById('renewal-mode-select');
    const urlEl = document.getElementById('renewal-base-url');
    if (!modeEl || !window.pywebview) return;
    try {
        const s = await pywebview.api.get_renewal_settings();
        renewalSettings = s;
        modeEl.value = s.mode;
        urlEl.value = s.base_url;
        urlEl.placeholder = s.default_base_url;
    } catch (e) { /* leave defaults */ }
}

if (document.getElementById('renewal-settings-save-btn')) {
    document.getElementById('renewal-settings-save-btn').addEventListener('click', async () => {
        const mode = document.getElementById('renewal-mode-select').value;
        const baseUrl = document.getElementById('renewal-base-url').value;
        if (mode === 'live' && renewalSettings.mode !== 'live') {
            if (!confirm("Activer le renouvellement automatique ?\n\n« Renouveler » passera de vraies commandes chez DigiCert (potentiellement facturées) et remplacera des certificats sur vos serveurs.\n\nUne confirmation détaillée vous sera demandée pour chaque renouvellement.")) return;
        }
        try {
            const res = await pywebview.api.set_renewal_settings(mode, baseUrl);
            if (res.status === 'success') {
                showToast('Réglages de renouvellement enregistrés', 'success');
                loadRenewalSettings();
            } else {
                showToast(escapeHtml(res.message || 'Réglages refusés'), 'error');
            }
        } catch (e) {
            showToast("Erreur lors de l'enregistrement", 'error');
        }
    });
}

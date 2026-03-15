/**
 * dashboard.js — UI Controller & Visualization
 *
 * Wires up file drag-and-drop, animates packet-by-packet processing,
 * drives Chart.js charts, live packet feed, connection table, and blocking UI.
 */

import { parsePcapFile, PcapError, APP_COLORS } from './pcap-parser.js';
import { DPIEngine } from './dpi-engine.js';

// ─── Globals ─────────────────────────────────────────────────────────────────

let engine = new DPIEngine();
let packets = [];
let charts = {};
let processingTimer = null;
let currentIdx = 0;

// ─── DOM References ──────────────────────────────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const dropZone = $('#dropZone');
const fileInput = $('#fileInput');
const errorBanner = $('#errorBanner');
const errorMessage = $('#errorMessage');
const errorClose = $('#errorClose');
const dashboardContent = $('#dashboardContent');
const progressBar = $('#progressBar');
const progressFill = $('#progressFill');
const speedSlider = $('#speedSlider');
const speedLabel = $('#speedLabel');
const speedControl = $('#speedControl');
const processingInd = $('#processingIndicator');
const resetBtn = $('#resetBtn');

// Stats
const statTotal = $('#statTotal');
const statTotalBytes = $('#statTotalBytes');
const statForwarded = $('#statForwarded');
const statForwardedPct = $('#statForwardedPct');
const statBlocked = $('#statBlocked');
const statBlockedPct = $('#statBlockedPct');
const statConnections = $('#statConnections');
const statActiveConns = $('#statActiveConns');
const statProtocol = $('#statProtocol');
const statAppsDetected = $('#statAppsDetected');
const statSNICount = $('#statSNICount');

// Tables
const connectionBody = $('#connectionBody');
const connCount = $('#connCount');
const packetFeedBody = $('#packetFeedBody');
const packetFeedCount = $('#packetFeedCount');
const packetFeedWrap = $('#packetFeedWrap');

// Rules
const ruleType = $('#ruleType');
const ruleValue = $('#ruleValue');
const addRuleBtn = $('#addRuleBtn');
const activeRulesDiv = $('#activeRules');
const protoFilter = $('#protoFilter');

// ─── File Handling ───────────────────────────────────────────────────────────

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('drag-over');
    const file = e.dataTransfer?.files[0];
    if (file) loadFile(file);
});

fileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) loadFile(file);
});

async function loadFile(file) {
    hideError();
    resetDashboard();

    try {
        const buffer = await file.arrayBuffer();
        const result = parsePcapFile(buffer);
        packets = result.packets;

        if (packets.length === 0) {
            showError('No parseable packets found in this file.');
            return;
        }

        // Show dashboard
        dashboardContent.classList.add('visible');
        progressBar.classList.add('visible');
        speedControl.style.display = 'flex';
        processingInd.style.display = 'inline-flex';
        resetBtn.style.display = 'inline-flex';
        dropZone.style.display = 'none';

        initCharts();
        startProcessing();

    } catch (err) {
        if (err instanceof PcapError) {
            showError(err.message);
        } else {
            showError('Failed to parse file: ' + err.message);
            console.error(err);
        }
    }
}

// ─── Error Handling ──────────────────────────────────────────────────────────

function showError(msg) {
    errorMessage.textContent = msg;
    errorBanner.classList.add('visible');
}

function hideError() {
    errorBanner.classList.remove('visible');
}

errorClose.addEventListener('click', hideError);

// ─── Processing Loop ─────────────────────────────────────────────────────────

function startProcessing() {
    currentIdx = 0;
    processBatch();
}

function processBatch() {
    const speed = parseInt(speedSlider.value);
    const batchSize = Math.max(1, Math.ceil(speed / 10));

    for (let i = 0; i < batchSize && currentIdx < packets.length; i++, currentIdx++) {
        engine.processPacket(packets[currentIdx]);
    }

    // Update UI
    updateStats();
    updateProgress();

    if (currentIdx < packets.length) {
        processingTimer = requestAnimationFrame(processBatch);
    } else {
        // Done
        finishProcessing();
    }
}

function finishProcessing() {
    processingInd.style.display = 'none';
    progressFill.style.width = '100%';

    // Final full update
    updateStats();
    updateCharts();
    updateConnectionTable();
    updatePacketFeed();
}

function updateProgress() {
    const pct = (currentIdx / packets.length * 100).toFixed(1);
    progressFill.style.width = pct + '%';

    // Throttle chart/table updates: every ~5% or every 200 packets
    if (currentIdx % Math.max(1, Math.floor(packets.length / 20)) === 0 || currentIdx === packets.length) {
        updateCharts();
        updateConnectionTable();
        updatePacketFeed();
    }
}

// ─── Speed Control ───────────────────────────────────────────────────────────

speedSlider.addEventListener('input', () => {
    speedLabel.textContent = speedSlider.value + ' pkt/s';
});

// ─── Stats Update ────────────────────────────────────────────────────────────

function updateStats() {
    const s = engine.stats;

    statTotal.textContent = s.totalPackets.toLocaleString();
    statTotalBytes.textContent = formatBytes(s.totalBytes);
    statForwarded.textContent = s.forwardedPackets.toLocaleString();
    statBlocked.textContent = s.droppedPackets.toLocaleString();
    statProtocol.textContent = `${s.tcpPackets.toLocaleString()} / ${s.udpPackets.toLocaleString()}`;

    const total = s.totalPackets || 1;
    statForwardedPct.textContent = ((s.forwardedPackets / total) * 100).toFixed(1) + '%';
    statBlockedPct.textContent = ((s.droppedPackets / total) * 100).toFixed(1) + '%';

    const flows = engine.flows.size;
    const active = engine.getActiveConnectionCount();
    statConnections.textContent = flows.toLocaleString();
    statActiveConns.textContent = active + ' active';

    const apps = Object.keys(engine.appCounts);
    statAppsDetected.textContent = apps.length;
    const sniCount = Object.keys(engine.domainCounts).length;
    statSNICount.textContent = sniCount + ' SNIs extracted';
}

// ─── Chart.js Initialization ─────────────────────────────────────────────────

function initCharts() {
    // Global Chart.js defaults for dark theme
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(148,163,184,0.1)';
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.pointStyleWidth = 10;

    // App Distribution (Doughnut)
    charts.app = new Chart($('#appChart'), {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [],
                borderWidth: 0,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '62%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: { padding: 14, font: { size: 11 } }
                },
            }
        }
    });

    // Top Domains (Horizontal Bar)
    charts.domain = new Chart($('#domainChart'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: 'rgba(56,189,248,0.5)',
                borderColor: 'rgba(56,189,248,0.8)',
                borderWidth: 1,
                borderRadius: 4,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: { legend: { display: false } },
            scales: {
                x: { grid: { color: 'rgba(148,163,184,0.06)' } },
                y: { grid: { display: false }, ticks: { font: { size: 10 } } }
            }
        }
    });

    // Blocked vs Forwarded (Stacked Horizontal Bar)
    charts.blocked = new Chart($('#blockedChart'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Forwarded',
                    data: [],
                    backgroundColor: 'rgba(34,197,94,0.6)',
                    borderColor: 'rgba(34,197,94,0.9)',
                    borderWidth: 1,
                    borderRadius: 4,
                },
                {
                    label: 'Blocked',
                    data: [],
                    backgroundColor: 'rgba(239,68,68,0.6)',
                    borderColor: 'rgba(239,68,68,0.9)',
                    borderWidth: 1,
                    borderRadius: 4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { labels: { padding: 14, font: { size: 11 } } },
            },
            scales: {
                x: {
                    stacked: true,
                    grid: { color: 'rgba(148,163,184,0.06)' },
                    ticks: { font: { size: 10 } },
                },
                y: {
                    stacked: true,
                    grid: { display: false },
                    ticks: { font: { size: 10 } },
                }
            }
        }
    });
}

// ─── Chart Updates ───────────────────────────────────────────────────────────

function updateCharts() {
    // App Distribution — gray out blocked apps
    const topApps = engine.getTopApps();
    const blockedApps = new Set(engine.getRules().apps.map(a => a.toLowerCase()));
    charts.app.data.labels = topApps.map(([a]) => a);
    charts.app.data.datasets[0].data = topApps.map(([, c]) => c);
    charts.app.data.datasets[0].backgroundColor = topApps.map(([a]) => {
        if (blockedApps.has(a.toLowerCase())) return 'rgba(100,116,139,0.3)';
        return APP_COLORS[a] || '#475569';
    });
    charts.app.update('none');

    // Top Domains
    const topDomains = engine.getTopDomains(10);
    charts.domain.data.labels = topDomains.map(([d]) => truncate(d, 30));
    charts.domain.data.datasets[0].data = topDomains.map(([, c]) => c);
    charts.domain.update('none');

    // Blocked vs Forwarded per app
    const flows = engine.getFlows();
    const appStats = {};
    for (const f of flows) {
        const app = f.appType || 'Unknown';
        if (!appStats[app]) appStats[app] = { forwarded: 0, blocked: 0 };
        if (f.state === 'BLOCKED') {
            appStats[app].blocked += f.packets;
        } else {
            appStats[app].forwarded += f.packets;
        }
    }
    const sortedApps = Object.entries(appStats).sort((a, b) =>
        (b[1].forwarded + b[1].blocked) - (a[1].forwarded + a[1].blocked)
    ).slice(0, 10);

    charts.blocked.data.labels = sortedApps.map(([a]) => a);
    charts.blocked.data.datasets[0].data = sortedApps.map(([, s]) => s.forwarded);
    charts.blocked.data.datasets[1].data = sortedApps.map(([, s]) => s.blocked);
    charts.blocked.update('none');
}

// ─── Connection Flow Map ─────────────────────────────────────────────────────

const connGroupedView = $('#connGroupedView');
const connFlatView = $('#connFlatView');
const connViewToggle = $('#connViewToggle');
let connViewMode = 'grouped'; // 'grouped' or 'flat'

if (connViewToggle) {
    connViewToggle.addEventListener('click', () => {
        connViewMode = connViewMode === 'grouped' ? 'flat' : 'grouped';
        connViewToggle.textContent = connViewMode === 'grouped' ? '📊 Grouped' : '📋 Flat';
        connGroupedView.style.display = connViewMode === 'grouped' ? '' : 'none';
        connFlatView.style.display = connViewMode === 'flat' ? '' : 'none';
        updateConnectionTable();
    });
}

function updateConnectionTable() {
    const flows = engine.getFlows();
    connCount.textContent = flows.length + ' flows';

    const maxBytes = flows.reduce((m, f) => Math.max(m, f.bytes), 1);

    if (connViewMode === 'grouped') {
        renderGroupedView(flows, maxBytes);
    } else {
        renderFlatView(flows, maxBytes);
    }
}

function renderGroupedView(flows, maxBytes) {
    // Group flows by app
    const groups = {};
    for (const flow of flows) {
        const app = flow.appType || 'Unknown';
        if (!groups[app]) groups[app] = { flows: [], totalBytes: 0, totalPackets: 0 };
        groups[app].flows.push(flow);
        groups[app].totalBytes += flow.bytes;
        groups[app].totalPackets += flow.packets;
    }

    // Sort groups by total bytes descending
    const sorted = Object.entries(groups).sort((a, b) => b[1].totalBytes - a[1].totalBytes);
    const groupMaxBytes = sorted.reduce((m, [, g]) => Math.max(m, g.totalBytes), 1);

    let html = '';
    for (const [app, group] of sorted) {
        const color = APP_COLORS[app] || '#475569';
        const pct = ((group.totalBytes / groupMaxBytes) * 100).toFixed(1);
        const blocked = group.flows.some(f => f.state === 'BLOCKED');

        html += `
        <div class="flow-group ${blocked ? 'flow-blocked' : ''}">
            <div class="flow-group-header" onclick="this.parentElement.classList.toggle('expanded')">
                <div class="flow-group-left">
                    ${makeAppTag(app)}
                    <span class="flow-group-count">${group.flows.length} flow${group.flows.length > 1 ? 's' : ''}</span>
                </div>
                <div class="flow-group-right">
                    <span class="flow-group-packets">${group.totalPackets} pkts</span>
                    <span class="flow-group-bytes">${formatBytes(group.totalBytes)}</span>
                    <div class="flow-byte-bar-wrap group-bar">
                        <div class="flow-byte-bar" style="width:${pct}%;background:${color};"></div>
                    </div>
                    <span class="flow-group-chevron">▸</span>
                </div>
            </div>
            <div class="flow-group-body">
                ${group.flows.map(f => renderFlowCard(f, maxBytes)).join('')}
            </div>
        </div>`;
    }

    connGroupedView.innerHTML = html || '<div class="empty-state"><span class="icon">🔌</span>No connections yet</div>';
}

function renderFlowCard(flow, maxBytes) {
    const color = APP_COLORS[flow.appType] || '#475569';
    const pct = ((flow.bytes / maxBytes) * 100).toFixed(1);

    return `
    <div class="flow-card ${flow.state === 'BLOCKED' ? 'flow-card-blocked' : ''}">
        <div class="flow-card-endpoints">
            <span class="flow-ep src">${flow.srcIP}<span class="flow-port">:${flow.srcPort ?? ''}</span></span>
            <span class="flow-arrow" style="color:${color}">
                <svg width="48" height="16" viewBox="0 0 48 16">
                    <line x1="0" y1="8" x2="40" y2="8" stroke="${color}" stroke-width="2" ${flow.state === 'BLOCKED' ? 'stroke-dasharray="4,3"' : ''}/>
                    <polygon points="40,2 48,8 40,14" fill="${color}"/>
                </svg>
            </span>
            <span class="flow-ep dst">${flow.dstIP}<span class="flow-port">:${flow.dstPort ?? ''}</span></span>
        </div>
        <div class="flow-card-meta">
            <span class="flow-proto">${flow.protocol}</span>
            <span class="flow-sni" title="${esc(flow.sni)}">${esc(flow.sni) || '—'}</span>
            <span class="flow-stats">${flow.packets} pkts · ${formatBytes(flow.bytes)}</span>
            ${makeStateBadge(flow.state)}
        </div>
        <div class="flow-byte-bar-wrap">
            <div class="flow-byte-bar" style="width:${pct}%;background:${color};"></div>
        </div>
    </div>`;
}

function renderFlatView(flows, maxBytes) {
    connectionBody.innerHTML = '';
    for (const flow of flows.slice(0, 200)) {
        const color = APP_COLORS[flow.appType] || '#475569';
        const pct = ((flow.bytes / maxBytes) * 100).toFixed(1);
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${flow.srcIP}:${flow.srcPort ?? ''}</td>
            <td>${flow.dstIP}:${flow.dstPort ?? ''}</td>
            <td>${flow.protocol}</td>
            <td>${makeAppTag(flow.appType)}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(flow.sni)}">${esc(flow.sni) || '—'}</td>
            <td>${flow.packets}</td>
            <td>${formatBytes(flow.bytes)}</td>
            <td><div class="flow-byte-bar-wrap inline"><div class="flow-byte-bar" style="width:${pct}%;background:${color};"></div></div></td>
            <td>${makeStateBadge(flow.state)}</td>
        `;
        connectionBody.appendChild(tr);
    }
}

// ─── Packet Feed ─────────────────────────────────────────────────────────────

function updatePacketFeed() {
    const log = engine.packetLog;
    const filter = protoFilter ? protoFilter.value : 'ALL';

    // Apply protocol filter
    const filtered = filter === 'ALL'
        ? log
        : log.filter(p => p.protocol === filter);

    packetFeedCount.textContent = filtered.length + ' / ' + log.length + ' packets';

    // Show last 150 of filtered packets
    const slice = filtered.slice(-150);
    packetFeedBody.innerHTML = '';

    for (const pkt of slice) {
        const tr = document.createElement('tr');
        const hasPayload = pkt.payloadAscii && pkt.payloadAscii.length > 0;
        tr.innerHTML = `
            <td>${pkt.id}</td>
            <td>${pkt.time}</td>
            <td>${pkt.srcIP}${pkt.srcPort !== '—' ? ':' + pkt.srcPort : ''}</td>
            <td>${pkt.dstIP}${pkt.dstPort !== '—' ? ':' + pkt.dstPort : ''}</td>
            <td>${pkt.protocol}</td>
            <td>${pkt.size} B</td>
            <td>${makeAppTag(pkt.app)}</td>
            <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(pkt.sni)}">${esc(pkt.sni) || pkt.flags || '—'}</td>
            <td>${hasPayload
                ? `<div class="payload-cell" data-mode="ascii">
                     <span class="payload-text payload-ascii">${esc(pkt.payloadAscii)}</span>
                     <span class="payload-text payload-hex" style="display:none;">${pkt.payloadHex}</span>
                     <button class="payload-toggle btn-sm" title="Toggle Hex/ASCII">⟨HEX⟩</button>
                   </div>`
                : '<span style="color:var(--text-3);">—</span>'
            }</td>
            <td>${pkt.action === 'BLOCKED'
                ? '<span class="badge badge-blocked">BLOCKED</span>'
                : '<span class="badge badge-forward">FORWARD</span>'
            }</td>
        `;
        packetFeedBody.appendChild(tr);
    }

    // Attach click handlers for payload toggle buttons
    packetFeedBody.querySelectorAll('.payload-toggle').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const cell = btn.closest('.payload-cell');
            const ascii = cell.querySelector('.payload-ascii');
            const hex = cell.querySelector('.payload-hex');
            const isAscii = cell.dataset.mode === 'ascii';

            if (isAscii) {
                ascii.style.display = 'none';
                hex.style.display = 'inline';
                cell.dataset.mode = 'hex';
                btn.textContent = '⟨ASCII⟩';
            } else {
                hex.style.display = 'none';
                ascii.style.display = 'inline';
                cell.dataset.mode = 'ascii';
                btn.textContent = '⟨HEX⟩';
            }
        });
    });

    // Auto-scroll to bottom
    packetFeedWrap.scrollTop = packetFeedWrap.scrollHeight;
}

// ─── Protocol Filter ─────────────────────────────────────────────────────────

if (protoFilter) {
    protoFilter.addEventListener('change', () => updatePacketFeed());
}

// ─── Blocking Rules UI ───────────────────────────────────────────────────────

addRuleBtn.addEventListener('click', addRule);
ruleValue.addEventListener('keydown', (e) => { if (e.key === 'Enter') addRule(); });

function addRule() {
    const type = ruleType.value;
    const value = ruleValue.value.trim();
    if (!value) return;

    // Capture old stats before applying rule
    const oldBlocked = engine.stats.droppedPackets;

    switch (type) {
        case 'ip': engine.blockIP(value); break;
        case 'app': engine.blockApp(value); break;
        case 'domain': engine.blockDomain(value); break;
    }

    ruleValue.value = '';
    renderRules();

    // Re-process all packets with new rules
    reprocessAll();

    // Visual feedback
    const newBlocked = engine.stats.droppedPackets;
    const diff = newBlocked - oldBlocked;

    // Flash the blocked stat card
    const blockedCard = statBlocked.closest('.stat-card');
    blockedCard.classList.add('pulse-danger');
    setTimeout(() => blockedCard.classList.remove('pulse-danger'), 1200);

    // Toast notification
    const label = type === 'ip' ? 'IP' : type === 'app' ? 'App' : 'Domain';
    if (diff > 0) {
        showToast(`🚫 ${label}: ${value} — ${diff} packet${diff > 1 ? 's' : ''} blocked`, 'danger');
    } else {
        showToast(`⚠️ ${label}: ${value} — no matching packets found`, 'warning');
    }
}

// ─── Toast Notification System ───────────────────────────────────────────────

const toastContainer = $('#toastContainer');

function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = message;
    toastContainer.appendChild(toast);

    // Trigger enter animation
    requestAnimationFrame(() => toast.classList.add('visible'));

    // Auto remove after 3.5s
    setTimeout(() => {
        toast.classList.remove('visible');
        toast.addEventListener('transitionend', () => toast.remove());
    }, 3500);
}

function removeRule(type, value) {
    switch (type) {
        case 'ip': engine.unblockIP(value); break;
        case 'app': engine.unblockApp(value); break;
        case 'domain': engine.unblockDomain(value); break;
    }
    renderRules();
    reprocessAll();
}

function renderRules() {
    const rules = engine.getRules();
    activeRulesDiv.innerHTML = '';

    const allRules = [
        ...rules.ips.map(v => ({ type: 'ip', label: `IP: ${v}`, value: v })),
        ...rules.apps.map(v => ({ type: 'app', label: `App: ${v}`, value: v })),
        ...rules.domains.map(v => ({ type: 'domain', label: `Domain: ${v}`, value: v })),
    ];

    if (allRules.length === 0) {
        activeRulesDiv.innerHTML = '<span style="color:var(--text-3);font-size:0.8rem;">No active blocking rules</span>';
        return;
    }

    for (const rule of allRules) {
        const chip = document.createElement('span');
        chip.className = 'rule-chip';
        chip.innerHTML = `${rule.label} <span class="remove" data-type="${rule.type}" data-value="${esc(rule.value)}">&times;</span>`;
        chip.querySelector('.remove').addEventListener('click', () => removeRule(rule.type, rule.value));
        activeRulesDiv.appendChild(chip);
    }
}

function reprocessAll() {
    // Store current rules
    const rules = engine.getRules();

    // Reset engine but keep rules
    engine.reset();
    for (const ip of rules.ips) engine.blockIP(ip);
    for (const app of rules.apps) engine.blockApp(app);
    for (const domain of rules.domains) engine.blockDomain(domain);

    // Re-process all packets
    for (const pkt of packets) {
        engine.processPacket(pkt);
    }

    updateStats();
    updateCharts();
    updateConnectionTable();
    updatePacketFeed();
}

// ─── Reset ───────────────────────────────────────────────────────────────────

resetBtn.addEventListener('click', () => {
    if (processingTimer) {
        cancelAnimationFrame(processingTimer);
        processingTimer = null;
    }
    resetDashboard();
    dropZone.style.display = '';
});

function resetDashboard() {
    engine = new DPIEngine();
    packets = [];
    currentIdx = 0;

    dashboardContent.classList.remove('visible');
    progressBar.classList.remove('visible');
    speedControl.style.display = 'none';
    processingInd.style.display = 'none';
    resetBtn.style.display = 'none';
    progressFill.style.width = '0%';

    // Destroy charts
    for (const key of Object.keys(charts)) {
        charts[key]?.destroy();
    }
    charts = {};

    connectionBody.innerHTML = '';
    packetFeedBody.innerHTML = '';
    activeRulesDiv.innerHTML = '';
}

// ─── Utilities ───────────────────────────────────────────────────────────────

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function truncate(str, max) {
    return str.length > max ? str.slice(0, max - 3) + '…' : str;
}

function esc(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function makeAppTag(app) {
    const color = APP_COLORS[app] || '#475569';
    return `<span class="app-tag" style="background:${color}18;color:${color};">
        <span class="dot" style="background:${color};"></span>${esc(app)}
    </span>`;
}

function makeStateBadge(state) {
    const map = {
        NEW: { bg: 'rgba(148,163,184,0.1)', color: '#94a3b8' },
        ESTABLISHED: { bg: 'rgba(56,189,248,0.1)', color: '#38bdf8' },
        CLASSIFIED: { bg: 'rgba(34,197,94,0.1)', color: '#22c55e' },
        BLOCKED: { bg: 'rgba(239,68,68,0.1)', color: '#ef4444' },
        CLOSED: { bg: 'rgba(100,116,139,0.1)', color: '#64748b' },
    };
    const s = map[state] || map.NEW;
    return `<span class="badge" style="background:${s.bg};color:${s.color};">${state}</span>`;
}

// ─── Demo Button ─────────────────────────────────────────────────────────────

const loadDemoBtn = document.getElementById('loadDemoBtn');
if (loadDemoBtn) {
    loadDemoBtn.addEventListener('click', async () => {
        loadDemoBtn.textContent = '⏳ Loading…';
        loadDemoBtn.disabled = true;
        try {
            const resp = await fetch('test_dpi.pcap');
            if (!resp.ok) throw new Error('test_dpi.pcap not found — place it in the dashboard/ folder.');
            const buffer = await resp.arrayBuffer();

            // Reuse the same logic as file drop
            hideError();
            resetDashboard();

            const result = parsePcapFile(buffer);
            packets = result.packets;

            if (packets.length === 0) {
                showError('No parseable packets found in demo file.');
                return;
            }

            dashboardContent.classList.add('visible');
            progressBar.classList.add('visible');
            speedControl.style.display = 'flex';
            processingInd.style.display = 'inline-flex';
            resetBtn.style.display = 'inline-flex';
            dropZone.style.display = 'none';
            loadDemoBtn.parentElement.style.display = 'none';

            initCharts();
            startProcessing();
        } catch (err) {
            showError(err.message);
            loadDemoBtn.textContent = '🧪 Load Demo (test_dpi.pcap)';
            loadDemoBtn.disabled = false;
        }
    });
}

// ─── Init ────────────────────────────────────────────────────────────────────

renderRules();

// ─── Scroll Animations ───────────────────────────────────────────────────────
const observerOptions = {
    threshold: 0.15,
    rootMargin: "0px 0px -50px 0px"
};

const fadeObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            fadeObserver.unobserve(entry.target);
        }
    });
}, observerOptions);

document.querySelectorAll('.fade-in-scroll').forEach(el => {
    fadeObserver.observe(el);
});

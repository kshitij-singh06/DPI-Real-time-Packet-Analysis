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

    // Traffic Timeline (Line)
    charts.timeline = new Chart($('#timelineChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets / sec',
                data: [],
                borderColor: 'rgba(56,189,248,0.8)',
                backgroundColor: 'rgba(56,189,248,0.08)',
                fill: true,
                tension: 0.35,
                pointRadius: 0,
                borderWidth: 2,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: {
                    grid: { color: 'rgba(148,163,184,0.06)' },
                    ticks: { maxTicksLimit: 15, font: { size: 10 } }
                },
                y: {
                    grid: { color: 'rgba(148,163,184,0.06)' },
                    beginAtZero: true,
                }
            },
            interaction: { intersect: false, mode: 'index' },
        }
    });
}

// ─── Chart Updates ───────────────────────────────────────────────────────────

function updateCharts() {
    // App Distribution
    const topApps = engine.getTopApps();
    charts.app.data.labels = topApps.map(([a]) => a);
    charts.app.data.datasets[0].data = topApps.map(([, c]) => c);
    charts.app.data.datasets[0].backgroundColor = topApps.map(([a]) => APP_COLORS[a] || '#475569');
    charts.app.update('none');

    // Top Domains
    const topDomains = engine.getTopDomains(10);
    charts.domain.data.labels = topDomains.map(([d]) => truncate(d, 30));
    charts.domain.data.datasets[0].data = topDomains.map(([, c]) => c);
    charts.domain.update('none');

    // Timeline
    const timeline = engine.getTimeline();
    if (timeline.length > 0) {
        const baseTime = timeline[0][0];
        charts.timeline.data.labels = timeline.map(([t]) => {
            const diff = t - baseTime;
            return diff + 's';
        });
        charts.timeline.data.datasets[0].data = timeline.map(([, c]) => c);
        charts.timeline.update('none');
    }
}

// ─── Connection Table ────────────────────────────────────────────────────────

function updateConnectionTable() {
    const flows = engine.getFlows();
    connCount.textContent = flows.length + ' flows';

    connectionBody.innerHTML = '';
    for (const flow of flows.slice(0, 200)) { // cap at 200 rows
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${flow.srcIP}:${flow.srcPort ?? ''}</td>
            <td>${flow.dstIP}:${flow.dstPort ?? ''}</td>
            <td>${flow.protocol}</td>
            <td>${makeAppTag(flow.appType)}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(flow.sni)}">${esc(flow.sni) || '—'}</td>
            <td>${flow.packets}</td>
            <td>${formatBytes(flow.bytes)}</td>
            <td>${makeStateBadge(flow.state)}</td>
        `;
        connectionBody.appendChild(tr);
    }
}

// ─── Packet Feed ─────────────────────────────────────────────────────────────

function updatePacketFeed() {
    const log = engine.packetLog;
    const total = log.length;
    packetFeedCount.textContent = total + ' packets';

    // Show last 150 packets
    const slice = log.slice(-150);
    packetFeedBody.innerHTML = '';

    for (const pkt of slice) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${pkt.id}</td>
            <td>${pkt.time}</td>
            <td>${pkt.srcIP}${pkt.srcPort !== '—' ? ':' + pkt.srcPort : ''}</td>
            <td>${pkt.dstIP}${pkt.dstPort !== '—' ? ':' + pkt.dstPort : ''}</td>
            <td>${pkt.protocol}</td>
            <td>${pkt.size} B</td>
            <td>${makeAppTag(pkt.app)}</td>
            <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(pkt.sni)}">${esc(pkt.sni) || pkt.flags || '—'}</td>
            <td>${pkt.action === 'BLOCKED'
                ? '<span class="badge badge-blocked">BLOCKED</span>'
                : '<span class="badge badge-forward">FORWARD</span>'
            }</td>
        `;
        packetFeedBody.appendChild(tr);
    }

    // Auto-scroll to bottom
    packetFeedWrap.scrollTop = packetFeedWrap.scrollHeight;
}

// ─── Blocking Rules UI ───────────────────────────────────────────────────────

addRuleBtn.addEventListener('click', addRule);
ruleValue.addEventListener('keydown', (e) => { if (e.key === 'Enter') addRule(); });

function addRule() {
    const type = ruleType.value;
    const value = ruleValue.value.trim();
    if (!value) return;

    switch (type) {
        case 'ip': engine.blockIP(value); break;
        case 'app': engine.blockApp(value); break;
        case 'domain': engine.blockDomain(value); break;
    }

    ruleValue.value = '';
    renderRules();

    // Re-process all packets with new rules
    reprocessAll();
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

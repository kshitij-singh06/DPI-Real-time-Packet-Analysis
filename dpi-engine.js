/**
 * dpi-engine.js — DPI Engine (Flow Tracking, Classification, Blocking)
 * 
 * Manages connection flows by five-tuple, applies blocking rules,
 * tracks TCP state, and aggregates statistics for visualization.
 */

import { sniToAppType } from './pcap-parser.js';

// ─── Five-Tuple Key ──────────────────────────────────────────────────────────

function tupleKey(pkt) {
    return `${pkt.srcIP}:${pkt.srcPort}->${pkt.dstIP}:${pkt.dstPort}@${pkt.ipProto}`;
}

function reverseTupleKey(pkt) {
    return `${pkt.dstIP}:${pkt.dstPort}->${pkt.srcIP}:${pkt.srcPort}@${pkt.ipProto}`;
}

// ─── Connection States ───────────────────────────────────────────────────────

const STATE = {
    NEW: 'NEW',
    ESTABLISHED: 'ESTABLISHED',
    CLASSIFIED: 'CLASSIFIED',
    BLOCKED: 'BLOCKED',
    CLOSED: 'CLOSED',
};

// ─── DPI Engine ──────────────────────────────────────────────────────────────

export class DPIEngine {
    constructor() {
        // Flow table: tupleKey → Flow
        this.flows = new Map();

        // Blocking rules
        this.blockedIPs = new Set();
        this.blockedApps = new Set();
        this.blockedDomains = [];

        // Global stats
        this.stats = {
            totalPackets: 0,
            totalBytes: 0,
            forwardedPackets: 0,
            droppedPackets: 0,
            tcpPackets: 0,
            udpPackets: 0,
            otherPackets: 0,
        };

        // Per-app counters
        this.appCounts = {};
        // Per-domain counters
        this.domainCounts = {};
        // Timeline data (tsSec → packet count)
        this.timeline = {};
        // Processed packet log (for live feed)
        this.packetLog = [];
    }

    // ── Process a Parsed Packet ──────────────────────────────────────────────

    processPacket(pkt) {
        this.stats.totalPackets++;
        this.stats.totalBytes += pkt.size || 0;

        // Protocol stats
        if (pkt.protocol === 'TCP') this.stats.tcpPackets++;
        else if (pkt.protocol === 'UDP') this.stats.udpPackets++;
        else this.stats.otherPackets++;

        // Timeline
        if (pkt.tsSec !== undefined) {
            this.timeline[pkt.tsSec] = (this.timeline[pkt.tsSec] || 0) + 1;
        }

        // Skip non-IP packets
        if (!pkt.srcIP) {
            this.stats.forwardedPackets++;
            return this._logPacket(pkt, 'FORWARD');
        }

        // Get or create flow
        const key = tupleKey(pkt);
        const rkey = reverseTupleKey(pkt);
        let flow = this.flows.get(key) || this.flows.get(rkey);

        if (!flow) {
            flow = this._createFlow(pkt, key);
            this.flows.set(key, flow);
        }

        // Update flow stats
        flow.packets++;
        flow.bytes += pkt.size || 0;
        flow.lastSeen = pkt.tsSec || 0;

        // TCP state tracking
        if (pkt.protocol === 'TCP') {
            this._updateTCPState(flow, pkt.tcpFlags);
        }

        // If already blocked, fast-path drop
        if (flow.state === STATE.BLOCKED) {
            this.stats.droppedPackets++;
            return this._logPacket(pkt, 'BLOCKED', flow);
        }

        // Deep inspection: classify flow if not yet classified
        if (flow.state !== STATE.CLASSIFIED && pkt.dpi) {
            this._classifyFlow(flow, pkt);
        }

        // Check blocking rules
        const blocked = this._checkRules(flow, pkt);
        if (blocked) {
            flow.state = STATE.BLOCKED;
            flow.action = 'DROP';
            flow.blockReason = blocked;
            this.stats.droppedPackets++;
            return this._logPacket(pkt, 'BLOCKED', flow);
        }

        this.stats.forwardedPackets++;
        return this._logPacket(pkt, 'FORWARD', flow);
    }

    // ── Flow Creation ────────────────────────────────────────────────────────

    _createFlow(pkt, key) {
        return {
            key,
            srcIP: pkt.srcIP,
            dstIP: pkt.dstIP,
            srcPort: pkt.srcPort,
            dstPort: pkt.dstPort,
            protocol: pkt.protocol,
            state: STATE.NEW,
            appType: 'Unknown',
            sni: '',
            packets: 0,
            bytes: 0,
            firstSeen: pkt.tsSec || 0,
            lastSeen: pkt.tsSec || 0,
            action: 'FORWARD',
            blockReason: null,
            // TCP state
            synSeen: false,
            synAckSeen: false,
            finSeen: false,
        };
    }

    // ── TCP State Machine ────────────────────────────────────────────────────

    _updateTCPState(flow, flags) {
        if (flags === undefined) return;

        const SYN = 0x02, ACK = 0x10, FIN = 0x01, RST = 0x04;

        if (flags & SYN) {
            if (flags & ACK) flow.synAckSeen = true;
            else flow.synSeen = true;
        }

        if (flow.synSeen && flow.synAckSeen && (flags & ACK)) {
            if (flow.state === STATE.NEW) flow.state = STATE.ESTABLISHED;
        }

        if (flags & FIN) flow.finSeen = true;
        if (flags & RST) flow.state = STATE.CLOSED;
        if (flow.finSeen && (flags & ACK)) flow.state = STATE.CLOSED;
    }

    // ── Flow Classification ──────────────────────────────────────────────────

    _classifyFlow(flow, pkt) {
        const dpi = pkt.dpi;
        if (!dpi) return;

        let app = 'Unknown';
        let sni = '';

        if (dpi.sni) {
            sni = dpi.sni;
            app = dpi.appType || sniToAppType(sni);
        } else if (dpi.host) {
            sni = dpi.host;
            app = dpi.appType || sniToAppType(sni);
        } else if (dpi.dnsQuery) {
            sni = dpi.dnsQuery;
            app = 'DNS';
        } else if (dpi.layer7) {
            app = dpi.layer7;
        }

        if (app !== 'Unknown') {
            flow.appType = app;
            flow.sni = sni;
            flow.state = STATE.CLASSIFIED;

            // Update app counter
            this.appCounts[app] = (this.appCounts[app] || 0) + 1;

            // Update domain counter
            if (sni) {
                this.domainCounts[sni] = (this.domainCounts[sni] || 0) + 1;
            }
        }
    }

    // ── Blocking Rules ───────────────────────────────────────────────────────

    _checkRules(flow, pkt) {
        // Check IP blacklist
        if (this.blockedIPs.has(pkt.srcIP)) return `IP: ${pkt.srcIP}`;
        if (this.blockedIPs.has(pkt.dstIP)) return `IP: ${pkt.dstIP}`;

        // Check app blacklist
        if (flow.appType !== 'Unknown' && this.blockedApps.has(flow.appType)) {
            return `App: ${flow.appType}`;
        }

        // Check domain blacklist (substring match)
        if (flow.sni) {
            const lower = flow.sni.toLowerCase();
            for (const domain of this.blockedDomains) {
                if (lower.includes(domain.toLowerCase())) {
                    return `Domain: ${domain}`;
                }
            }
        }

        return null;
    }

    // ── Rule Management API ──────────────────────────────────────────────────

    blockIP(ip) { this.blockedIPs.add(ip); this._recheck(); }
    unblockIP(ip) { this.blockedIPs.delete(ip); }

    blockApp(app) { this.blockedApps.add(app); this._recheck(); }
    unblockApp(app) { this.blockedApps.delete(app); }

    blockDomain(domain) { this.blockedDomains.push(domain); this._recheck(); }
    unblockDomain(domain) {
        this.blockedDomains = this.blockedDomains.filter(d => d !== domain);
    }

    // Re-check all existing flows against new rules
    _recheck() {
        for (const flow of this.flows.values()) {
            if (flow.state === STATE.BLOCKED) continue;

            const fakePacket = { srcIP: flow.srcIP, dstIP: flow.dstIP };
            const blocked = this._checkRules(flow, fakePacket);
            if (blocked) {
                flow.state = STATE.BLOCKED;
                flow.action = 'DROP';
                flow.blockReason = blocked;
            }
        }
    }

    // ── Packet Log ───────────────────────────────────────────────────────────

    _logPacket(pkt, action, flow = null) {
        // Extract payload preview (up to 128 bytes)
        let payloadHex = '';
        let payloadAscii = '';
        if (pkt.rawData && pkt.payloadOffset != null && pkt.payloadLength > 0) {
            const maxBytes = Math.min(pkt.payloadLength, 128);
            const start = pkt.payloadOffset;
            const slice = pkt.rawData.subarray(start, start + maxBytes);
            payloadHex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
            payloadAscii = Array.from(slice).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.').join('');
        }

        const entry = {
            id: pkt.id,
            time: pkt.tsSec ? new Date(pkt.tsSec * 1000).toISOString().slice(11, 23) : '—',
            srcIP: pkt.srcIP || '—',
            dstIP: pkt.dstIP || '—',
            srcPort: pkt.srcPort ?? '—',
            dstPort: pkt.dstPort ?? '—',
            protocol: pkt.protocol || 'OTHER',
            size: pkt.size || 0,
            flags: pkt.flagStr || '—',
            app: flow?.appType || 'Unknown',
            sni: flow?.sni || pkt.dpi?.sni || pkt.dpi?.host || pkt.dpi?.dnsQuery || '',
            action,
            payloadHex,
            payloadAscii,
        };
        this.packetLog.push(entry);
        return entry;
    }

    // ── Stats Getters ────────────────────────────────────────────────────────

    getTopDomains(n = 15) {
        return Object.entries(this.domainCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, n);
    }

    getTopApps() {
        return Object.entries(this.appCounts)
            .sort((a, b) => b[1] - a[1]);
    }

    getTimeline() {
        const entries = Object.entries(this.timeline)
            .map(([t, c]) => [Number(t), c])
            .sort((a, b) => a[0] - b[0]);
        return entries;
    }

    getFlows() {
        return Array.from(this.flows.values());
    }

    getActiveConnectionCount() {
        let count = 0;
        for (const flow of this.flows.values()) {
            if (flow.state !== STATE.CLOSED) count++;
        }
        return count;
    }

    getRules() {
        return {
            ips: Array.from(this.blockedIPs),
            apps: Array.from(this.blockedApps),
            domains: [...this.blockedDomains],
        };
    }

    reset() {
        this.flows.clear();
        this.stats = {
            totalPackets: 0, totalBytes: 0,
            forwardedPackets: 0, droppedPackets: 0,
            tcpPackets: 0, udpPackets: 0, otherPackets: 0,
        };
        this.appCounts = {};
        this.domainCounts = {};
        this.timeline = {};
        this.packetLog = [];
    }
}

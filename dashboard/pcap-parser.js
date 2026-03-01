/**
 * pcap-parser.js — PCAP File Parser & Protocol Decoder
 * 
 * JavaScript port of the C++ DPI Engine's parsing logic.
 * Handles PCAP global/packet headers, Ethernet/IPv4/TCP/UDP parsing,
 * TLS SNI extraction, HTTP Host extraction, and DNS query extraction.
 * Detects PCAP-ng files and shows a clear error message.
 */

// ─── PCAP-ng Detection ──────────────────────────────────────────────────────

const PCAP_MAGIC_LE       = 0xA1B2C3D4;
const PCAP_MAGIC_BE       = 0xD4C3B2A1;
const PCAPNG_MAGIC        = 0x0A0D0D0A;
const PCAP_GLOBAL_HDR_LEN = 24;
const PCAP_PKT_HDR_LEN    = 16;

// ─── PCAP Parser ─────────────────────────────────────────────────────────────

export function parsePcapFile(arrayBuffer) {
    const view = new DataView(arrayBuffer);

    if (arrayBuffer.byteLength < PCAP_GLOBAL_HDR_LEN) {
        throw new PcapError('File too small to be a valid PCAP file.');
    }

    // Check for PCAP-ng
    const firstWord = view.getUint32(0, true);
    if (firstWord === PCAPNG_MAGIC) {
        throw new PcapError(
            'This is a .pcapng file. Please re-export from Wireshark as legacy .pcap:\n' +
            'File → Save As → select "Wireshark/tcpdump/… - pcap" format.'
        );
    }

    // Determine endianness
    let littleEndian;
    if (firstWord === PCAP_MAGIC_LE) {
        littleEndian = true;
    } else if (firstWord === PCAP_MAGIC_BE) {
        littleEndian = false;
    } else {
        throw new PcapError(
            'Unrecognized file format. Expected a .pcap file.\n' +
            'Magic number: 0x' + firstWord.toString(16).toUpperCase()
        );
    }

    // Read global header
    const globalHeader = {
        magic:        firstWord,
        versionMajor: view.getUint16(4, littleEndian),
        versionMinor: view.getUint16(6, littleEndian),
        thiszone:     view.getInt32(8, littleEndian),
        sigfigs:      view.getUint32(12, littleEndian),
        snaplen:      view.getUint32(16, littleEndian),
        network:      view.getUint32(20, littleEndian),
    };

    // Parse packets
    const packets = [];
    let offset = PCAP_GLOBAL_HDR_LEN;
    let packetId = 0;

    while (offset + PCAP_PKT_HDR_LEN <= arrayBuffer.byteLength) {
        const tsSec   = view.getUint32(offset, littleEndian);
        const tsUsec  = view.getUint32(offset + 4, littleEndian);
        const inclLen = view.getUint32(offset + 8, littleEndian);
        const origLen = view.getUint32(offset + 12, littleEndian);
        offset += PCAP_PKT_HDR_LEN;

        if (offset + inclLen > arrayBuffer.byteLength) break;

        const data = new Uint8Array(arrayBuffer, offset, inclLen);
        const parsed = parsePacket(data, inclLen);

        if (parsed) {
            parsed.id      = packetId++;
            parsed.tsSec   = tsSec;
            parsed.tsUsec  = tsUsec;
            parsed.origLen = origLen;
            parsed.rawData = data;
            packets.push(parsed);
        }

        offset += inclLen;
    }

    return { globalHeader, packets };
}

// ─── Custom Error ────────────────────────────────────────────────────────────

export class PcapError extends Error {
    constructor(message) {
        super(message);
        this.name = 'PcapError';
    }
}

// ─── Packet Parser ───────────────────────────────────────────────────────────

function parsePacket(data, length) {
    if (length < 14) return null; // too small for Ethernet

    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const result = {};

    // ── Ethernet Header (14 bytes) ──
    result.dstMac = formatMAC(data, 0);
    result.srcMac = formatMAC(data, 6);
    result.etherType = view.getUint16(12, false); // big-endian

    if (result.etherType !== 0x0800) {
        // Not IPv4 — skip but still return basic info
        result.protocol = 'OTHER';
        result.size = length;
        return result;
    }

    // ── IPv4 Header (20+ bytes) ──
    const ipOffset = 14;
    if (length < ipOffset + 20) return null;

    const versionIHL = data[ipOffset];
    const ipVersion  = (versionIHL >> 4) & 0xF;
    const ihl        = (versionIHL & 0xF) * 4; // header length in bytes

    if (ipVersion !== 4) return null;

    result.ttl      = data[ipOffset + 8];
    result.ipProto  = data[ipOffset + 9];
    result.srcIP    = formatIP(view, ipOffset + 12);
    result.dstIP    = formatIP(view, ipOffset + 16);
    result.size     = length;

    const transportOffset = ipOffset + ihl;

    // ── TCP Header ──
    if (result.ipProto === 6) {
        if (length < transportOffset + 20) return null;

        result.protocol = 'TCP';
        result.srcPort  = view.getUint16(transportOffset, false);
        result.dstPort  = view.getUint16(transportOffset + 2, false);
        result.seqNum   = view.getUint32(transportOffset + 4, false);
        result.ackNum   = view.getUint32(transportOffset + 8, false);

        const dataOffsetByte = data[transportOffset + 12];
        const tcpHeaderLen   = ((dataOffsetByte >> 4) & 0xF) * 4;
        result.tcpFlags      = data[transportOffset + 13];
        result.flagStr       = decodeTCPFlags(result.tcpFlags);

        const payloadOffset = transportOffset + tcpHeaderLen;
        result.payloadOffset = payloadOffset;
        result.payloadLength = Math.max(0, length - payloadOffset);

        // Deep inspection
        if (result.payloadLength > 0) {
            const payload = data.subarray(payloadOffset);
            result.dpi = deepInspect(payload, result.payloadLength, result.dstPort, result.srcPort);
        }

    // ── UDP Header ──
    } else if (result.ipProto === 17) {
        if (length < transportOffset + 8) return null;

        result.protocol = 'UDP';
        result.srcPort  = view.getUint16(transportOffset, false);
        result.dstPort  = view.getUint16(transportOffset + 2, false);

        const payloadOffset = transportOffset + 8;
        result.payloadOffset = payloadOffset;
        result.payloadLength = Math.max(0, length - payloadOffset);

        if (result.payloadLength > 0) {
            const payload = data.subarray(payloadOffset);
            result.dpi = deepInspect(payload, result.payloadLength, result.dstPort, result.srcPort);
        }

    } else {
        result.protocol = 'OTHER';
    }

    return result;
}

// ─── Deep Packet Inspection ──────────────────────────────────────────────────

function deepInspect(payload, length, dstPort, srcPort) {
    const result = {};

    // TLS SNI extraction (port 443 typically, but try on any TLS-looking data)
    const sni = extractTLSSNI(payload, length);
    if (sni) {
        result.sni     = sni;
        result.appType = sniToAppType(sni);
        result.layer7  = 'TLS';
        return result;
    }

    // HTTP Host extraction (port 80 typically)
    const host = extractHTTPHost(payload, length);
    if (host) {
        result.host    = host;
        result.appType = sniToAppType(host);
        result.layer7  = 'HTTP';
        return result;
    }

    // DNS query extraction (port 53)
    if (dstPort === 53 || srcPort === 53) {
        const domain = extractDNSQuery(payload, length);
        if (domain) {
            result.dnsQuery = domain;
            result.appType  = 'DNS';
            result.layer7   = 'DNS';
            return result;
        }
    }

    return result;
}

// ─── TLS SNI Extraction ──────────────────────────────────────────────────────
// Mirrors sni_extractor.cpp SNIExtractor::extract()

function extractTLSSNI(payload, length) {
    if (length < 44) return null;

    // Check TLS record header: ContentType = 0x16 (Handshake)
    if (payload[0] !== 0x16) return null;

    // TLS record length
    const recordLen = (payload[3] << 8) | payload[4];
    if (length < 5 + recordLen) return null;

    // Check Handshake type = 0x01 (Client Hello)
    if (payload[5] !== 0x01) return null;

    // Skip handshake header (4 bytes: type + 3-byte length)
    // Skip client version (2 bytes) + random (32 bytes)
    let offset = 5 + 4 + 2 + 32; // = 43

    if (offset >= length) return null;

    // Skip Session ID
    const sessionIdLen = payload[offset];
    offset += 1 + sessionIdLen;
    if (offset + 2 > length) return null;

    // Skip Cipher Suites
    const cipherSuitesLen = (payload[offset] << 8) | payload[offset + 1];
    offset += 2 + cipherSuitesLen;
    if (offset + 1 > length) return null;

    // Skip Compression Methods
    const compMethodsLen = payload[offset];
    offset += 1 + compMethodsLen;
    if (offset + 2 > length) return null;

    // Extensions length
    const extensionsLen = (payload[offset] << 8) | payload[offset + 1];
    offset += 2;

    const extensionsEnd = offset + extensionsLen;
    if (extensionsEnd > length) return null;

    // Search for SNI extension (type 0x0000)
    while (offset + 4 <= extensionsEnd) {
        const extType = (payload[offset] << 8) | payload[offset + 1];
        const extLen  = (payload[offset + 2] << 8) | payload[offset + 3];
        offset += 4;

        if (extType === 0x0000 && extLen > 5) {
            // SNI extension found
            // Skip SNI list length (2 bytes), SNI type (1 byte = 0x00 for hostname)
            const sniLength = (payload[offset + 3] << 8) | payload[offset + 4];
            if (offset + 5 + sniLength <= length) {
                const sniBytes = payload.subarray(offset + 5, offset + 5 + sniLength);
                return new TextDecoder().decode(sniBytes);
            }
        }

        offset += extLen;
    }

    return null;
}

// ─── HTTP Host Extraction ────────────────────────────────────────────────────
// Mirrors sni_extractor.cpp HTTPHostExtractor::extract()

function extractHTTPHost(payload, length) {
    if (length < 16) return null;

    // Check if it starts with an HTTP method
    const start = new TextDecoder().decode(payload.subarray(0, Math.min(8, length)));
    const httpMethods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'CONNECT '];
    if (!httpMethods.some(m => start.startsWith(m))) return null;

    // Search for "Host: " header
    const text = new TextDecoder().decode(payload.subarray(0, Math.min(length, 2048)));
    const hostMatch = text.match(/Host:\s*([^\r\n]+)/i);
    if (hostMatch) {
        return hostMatch[1].trim().split(':')[0]; // strip port if present
    }

    return null;
}

// ─── DNS Query Extraction ────────────────────────────────────────────────────
// Mirrors sni_extractor.cpp DNSExtractor::extractQuery()

function extractDNSQuery(payload, length) {
    if (length < 12) return null;

    // Check DNS flags — standard query (QR=0)
    const flags = (payload[2] << 8) | payload[3];
    if ((flags & 0x8000) !== 0) return null; // response, not query

    const qdcount = (payload[4] << 8) | payload[5];
    if (qdcount < 1) return null;

    // Parse question section
    let offset = 12;
    const labels = [];

    while (offset < length) {
        const labelLen = payload[offset];
        if (labelLen === 0) break;
        if (labelLen > 63 || offset + 1 + labelLen > length) return null;
        labels.push(new TextDecoder().decode(payload.subarray(offset + 1, offset + 1 + labelLen)));
        offset += 1 + labelLen;
    }

    return labels.length > 0 ? labels.join('.') : null;
}

// ─── App Classification ──────────────────────────────────────────────────────
// Mirrors types.cpp sniToAppType()

const APP_PATTERNS = [
    { app: 'YouTube',     patterns: ['youtube', 'ytimg', 'youtu.be', 'yt3.ggpht'] },
    { app: 'Google',      patterns: ['google', 'gstatic', 'googleapis', 'ggpht', 'gvt1'] },
    { app: 'Facebook',    patterns: ['facebook', 'fbcdn', 'fb.com', 'fbsbx', 'meta.com'] },
    { app: 'Instagram',   patterns: ['instagram', 'cdninstagram'] },
    { app: 'WhatsApp',    patterns: ['whatsapp', 'wa.me'] },
    { app: 'Twitter/X',   patterns: ['twitter', 'twimg', 'x.com', 't.co'] },
    { app: 'Netflix',     patterns: ['netflix', 'nflxvideo', 'nflximg'] },
    { app: 'Amazon',      patterns: ['amazon', 'amazonaws', 'cloudfront', 'aws'] },
    { app: 'Microsoft',   patterns: ['microsoft', 'msn.com', 'office', 'azure', 'live.com', 'outlook', 'bing'] },
    { app: 'Apple',       patterns: ['apple', 'icloud', 'mzstatic', 'itunes'] },
    { app: 'Telegram',    patterns: ['telegram', 't.me'] },
    { app: 'TikTok',      patterns: ['tiktok', 'tiktokcdn', 'musical.ly', 'bytedance'] },
    { app: 'Spotify',     patterns: ['spotify', 'scdn.co'] },
    { app: 'Zoom',        patterns: ['zoom'] },
    { app: 'Discord',     patterns: ['discord', 'discordapp'] },
    { app: 'GitHub',      patterns: ['github', 'githubusercontent'] },
    { app: 'Cloudflare',  patterns: ['cloudflare'] },
];

export function sniToAppType(sni) {
    if (!sni) return 'Unknown';
    const lower = sni.toLowerCase();
    for (const { app, patterns } of APP_PATTERNS) {
        if (patterns.some(p => lower.includes(p))) return app;
    }
    return 'HTTPS'; // known SNI but unrecognized app
}

// ─── App Colors ──────────────────────────────────────────────────────────────

export const APP_COLORS = {
    'YouTube':     '#FF0000',
    'Google':      '#4285F4',
    'Facebook':    '#1877F2',
    'Instagram':   '#E4405F',
    'WhatsApp':    '#25D366',
    'Twitter/X':   '#1DA1F2',
    'Netflix':     '#E50914',
    'Amazon':      '#FF9900',
    'Microsoft':   '#00A4EF',
    'Apple':       '#A2AAAD',
    'Telegram':    '#0088CC',
    'TikTok':      '#00F2EA',
    'Spotify':     '#1DB954',
    'Zoom':        '#2D8CFF',
    'Discord':     '#5865F2',
    'GitHub':      '#F0F0F0',
    'Cloudflare':  '#F6821F',
    'DNS':         '#8B5CF6',
    'HTTP':        '#10B981',
    'HTTPS':       '#06B6D4',
    'TCP':         '#64748B',
    'UDP':         '#94A3B8',
    'Unknown':     '#475569',
    'OTHER':       '#334155',
};

// ─── Utility Functions ───────────────────────────────────────────────────────

function formatMAC(data, offset) {
    return Array.from(data.subarray(offset, offset + 6))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(':');
}

function formatIP(dataView, offset) {
    return `${dataView.getUint8(offset)}.${dataView.getUint8(offset+1)}.${dataView.getUint8(offset+2)}.${dataView.getUint8(offset+3)}`;
}

function decodeTCPFlags(flags) {
    const names = [];
    if (flags & 0x01) names.push('FIN');
    if (flags & 0x02) names.push('SYN');
    if (flags & 0x04) names.push('RST');
    if (flags & 0x08) names.push('PSH');
    if (flags & 0x10) names.push('ACK');
    if (flags & 0x20) names.push('URG');
    return names.join(',') || '—';
}

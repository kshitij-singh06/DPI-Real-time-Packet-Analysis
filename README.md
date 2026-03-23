# NetScope — Deep Packet Inspection Dashboard + C++17 Engine

A dual-implementation Deep Packet Inspection (DPI) project:

- **Browser dashboard (JavaScript):** parse `.pcap` files locally, classify traffic, apply simulated blocking rules, and visualize results.
- **Native engine (C++17):** parse/filter PCAP traffic with rule-based blocking and multi-threaded packet processing.

This repository is useful for demonstrating networking fundamentals, protocol parsing, flow tracking, and systems-level concurrency.

## Quick links

- Dashboard entry: `index.html`
- C++ engine source: `engine/src/`
- C++ engine deep-dive doc: `engine/README.md`
- Windows build notes: `engine/WINDOWS_SETUP.md`
- C++ feature showcase: `cpp_features/index.html`
- C++ docs page: `cpp_docs.html`

## What this project does

- Parses PCAP files (legacy `.pcap`, with explicit `.pcapng` rejection in the JS parser)
- Decodes Ethernet, IPv4, TCP, and UDP headers
- Extracts L7 indicators:
  - TLS SNI
  - HTTP `Host` header
  - DNS query names
- Classifies traffic into app/protocol categories (Google, YouTube, Facebook, GitHub, etc.)
- Tracks flows using the 5-tuple and TCP state transitions
- Applies blocking rules by IP, application, and domain
- Produces:
  - interactive dashboard metrics/charts (JS path)
  - filtered output PCAP (C++ path)

## Website highlights (what GitHub visitors will see)

- Drag/drop PCAP upload and one-click demo load (`test_dpi.pcap`)
- Animated packet playback (`requestAnimationFrame`) with adjustable processing speed
- Multiple visualizations: timeline, app distribution, top domains, blocked vs forwarded
- Live packet feed + flow table with TCP state badges
- Policy simulation controls in UI (IP/app/domain) with immediate re-evaluation of flows
- Optional Geo-IP map panel using Leaflet + GeoJS lookups (internet required)

## What It Detects

| Category | Apps / Protocols |
|----------|------------------|
| **Social** | Facebook, Instagram, Twitter/X, TikTok, WhatsApp, Telegram |
| **Streaming** | YouTube, Netflix, Spotify |
| **Productivity** | Google, Microsoft, GitHub, Zoom, Discord |
| **Cloud** | Amazon/AWS, Apple, Cloudflare |
| **Protocols** | HTTP, HTTPS/TLS, DNS, QUIC* |

\* QUIC extraction helpers exist in the C++ codebase; active classification paths are primarily HTTP/HTTPS/DNS.

## Blocking Rules

### Dashboard (simulation)

Simulate policy behavior by adding rules in the browser dashboard:

| Rule Type | Example | Effect |
|-----------|---------|--------|
| **Simulate App Block** | `YouTube` | Marks matching YouTube-classified packets/flows as blocked in analysis output |
| **Simulate IP Block** | `192.168.1.50` | Marks packets involving that IP as blocked in analysis output |
| **Simulate Domain Block** | `tiktok.com` | Matches SNI/domain substring and marks matching flows as blocked |

Rules are applied instantly — the capture is re-processed and stats/charts update in real time.

### C++ engine (enforced filtering)

In native mode, matching packets are actually dropped and only forwarded packets are written to output PCAP.

| Rule Type | Example | Effect |
|-----------|---------|--------|
| **Block App** | `YouTube` | Drops packets from flows classified as YouTube |
| **Block IP** | `192.168.1.50` | Drops packets matching blocked IP rules |
| **Block Domain** | `tiktok.com` or `*.tiktok.com` | Drops packets for matching extracted domain/SNI |

## Getting PCAP Files

1. **Wireshark capture** — save as legacy `.pcap` (not `.pcapng`)
2. **Built-in generator** — run `python engine/generate_test_pcap.py` from project root
3. **Online samples** — [Wireshark SampleCaptures](https://wiki.wireshark.org/SampleCaptures), [Netresec PCAP files](https://www.netresec.com/?page=PcapFiles)

> ⚠️ Wireshark often defaults to `.pcapng`. Use **File → Save As → Wireshark/tcpdump - pcap**.

## Architecture

This dashboard mirrors the C++ DPI Engine architecture at a conceptual level:

```text
┌─────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   pcap-parser   │     │   dpi-engine     │     │   dashboard      │
│                 │     │                  │     │                  │
│ • PCAP format   │────▶│ • Flow table     │────▶│ • Chart.js       │
│ • Ethernet/IP   │     │ • TCP state      │     │ • Packet feed    │
│ • TCP/UDP       │     │ • App classify   │     │ • Conn table     │
│ • TLS SNI       │     │ • Policy rules   │     │ • Stats cards    │
│ • HTTP Host     │     │ • Statistics     │     │ • Rules UI       │
│ • DNS query     │     │                  │     │                  │
└─────────────────┘     └──────────────────┘     └──────────────────┘
```

For a deeper C++ pipeline walkthrough and implementation notes, read [`engine/README.md`](engine/README.md).

## Repository layout

```text
.
├── index.html                 # Dashboard UI entry
├── dashboard.js               # UI controller + Chart.js + Geo-IP flow
├── pcap-parser.js             # PCAP and protocol parser (JS)
├── dpi-engine.js              # Flow tracking and rules (JS)
├── style.css
├── test_dpi.pcap              # Demo/sample capture
├── cpp_docs.html
├── cpp_features/
└── engine/
    ├── include/               # C++ headers
    ├── src/                   # C++ implementations and CLI mains
    ├── CMakeLists.txt
    ├── WINDOWS_SETUP.md
    ├── generate_test_pcap.py
    └── test_dpi.pcap
```

## Prerequisites

### Dashboard

- Modern browser with ES Modules support
- Local HTTP server (recommended for loading module scripts and demo pcap)

### C++ engine

- C++17 compiler
  - GCC/Clang on Linux/macOS, or MSVC/MinGW on Windows
- Optional: CMake (for the parser-focused target in `engine/CMakeLists.txt`)

### Optional tooling

- Python 3 (for local web server and test PCAP generation)

## Quick start (dashboard)

From repository root:

```bash
python -m http.server 8765
```

Open:

```text
http://localhost:8765
```

Then either:

- drag/drop your `.pcap` file, or
- click **Load Demo (test_dpi.pcap)**.

> For GitHub visitors: run a local server instead of opening `index.html` directly, so module imports and demo asset loading work reliably across browsers.

## Build and run (C++)

### Option A — CMake target (`packet_analyzer`)

From `engine/`:

```bash
cmake -S . -B build
cmake --build build --config Release
```

Run:

```bash
# Linux/macOS
./build/packet_analyzer test_dpi.pcap

# Windows (path depends on generator)
build\Release\packet_analyzer.exe test_dpi.pcap
```

### Option B — Build multi-threaded DPI CLI (`dpi_mt.cpp`)

From `engine/`:

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

Run:

```bash
./dpi_engine test_dpi.pcap output.pcap --block-app YouTube --block-domain facebook.com --block-ip 192.168.1.50
```

Windows (MSVC manual compile pattern shown in `engine/WINDOWS_SETUP.md`):

```cmd
dpi_engine.exe test_dpi.pcap output.pcap
```

### Option C — Build Live DPI Tracker (`dpi_live.cpp`, needs libpcap)

From `engine/`:

```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_live \
    src/dpi_live.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp \
    -lpcap
```

Run (Live default interface):

```bash
./dpi_live --live default live.pcap --block-app YouTube --block-domain facebook.com
```

### `dpi_mt.cpp` / `dpi_live.cpp` CLI options

- `--live <device>` (dpi_live only)
- `--block-ip <ip>`
- `--block-app <app>`
- `--block-domain <domain>`
- `--lbs <n>`
- `--fps <n>`

### Alternate CLI (`main_dpi.cpp`)

`engine/src/main_dpi.cpp` exposes an extended CLI surface (including `--rules <file>` and `--verbose`) that integrates with `DPI::DPIEngine` + `RuleManager` APIs.

## Generate a test PCAP

From `engine/`:

```bash
python generate_test_pcap.py
```

This writes `test_dpi.pcap` containing synthetic TLS/HTTP/DNS traffic plus blocked-IP test packets.

## Key modules

### JavaScript path

- `pcap-parser.js`: format parsing, endianness handling, L2/L3/L4 decode, DPI extractors
- `dpi-engine.js`: flow lifecycle, rule evaluation, counters/timeline/packet log
- `dashboard.js`: rendering, controls, chart updates, optional Geo-IP map enrichment

### C++ path

- `engine/include/pcap_reader.h` + `src/pcap_reader.cpp`: PCAP I/O
- `engine/include/packet_parser.h` + `src/packet_parser.cpp`: protocol decoding
- `engine/include/sni_extractor.h` + `src/sni_extractor.cpp`: TLS/HTTP/DNS extraction helpers
- `engine/include/types.h` + `src/types.cpp`: shared flow/app abstractions and classification mapping
- `engine/include/rule_manager.h` + `src/rule_manager.cpp`: thread-safe blocking rules + persistence
- `engine/include/dpi_engine.h` + `src/dpi_engine.cpp`: orchestrator for threaded pipeline
- `engine/src/main*.cpp`: multiple CLI entry points for parser/demo/DPI variants

### C++ feature page alignment

`cpp_features/index.html` presents the native engine as a multi-threaded firewall-style pipeline and documents CLI-oriented scenarios. It is useful as a narrative walkthrough, but the authoritative behavior remains the source files under `engine/src/`.

## Dependencies

### JavaScript runtime dependencies (CDN)

- Chart.js 4.4.7 (`index.html`)
- Leaflet 1.9.4 (`index.html`)
- Google Fonts (Inter/JetBrains Mono/Syne)
- GeoJS API (runtime lookup used by Geo-IP button in dashboard)

### Native dependencies

- Standard C++17 library + threading support (`-pthread` on GCC/Clang builds)

## Current build note

- The checked-in CMake target currently builds `engine/src/main.cpp` (packet parser CLI), while the multi-threaded DPI CLI is built via the explicit `dpi_mt.cpp` compile command above.
- If you want one canonical CMake target for the full DPI pipeline, extend `engine/CMakeLists.txt` to include DPI sources and choose the desired main entry.

## Operational notes

- Browser-side blocking is **simulation for analysis**; packets are not actually dropped on a live interface.
- Native engine output PCAP contains **forwarded packets only**; blocked packets are omitted.
- JS parser rejects `.pcapng` and expects legacy `.pcap` format.
- `Load Demo` expects `test_dpi.pcap` at repository root.
- `RuleManager` supports wildcard domain patterns (e.g., `*.example.com`) and rule persistence (`saveRules`/`loadRules`).
- `RuleManager` includes port-blocking APIs, but port flags are not exposed in `dpi_mt.cpp` CLI.
- QUIC SNI extraction helpers exist in `engine/src/sni_extractor.cpp`, but are not currently wired into the active packet-classification path.



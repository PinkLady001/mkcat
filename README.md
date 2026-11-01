# Mascara Kitsune Cat (`mkcat`) — Web Component Inspection Tool

**`mkcat` (Mascara Kitsune Cat)** is an automated inspection tool for modern web applications utilizing Web Components, Shadow DOM, and complex client-side front-end architectures. Built on Playwright and headless Chromium, `mkcat` inspects DOM structures, tests canary reflections, probes object prototype handling, and fingerprints front-end library versions.

---

## Key Features

* **Web Component & Shadow DOM Discovery**: Traverses open and closed Shadow DOM roots (instrumented via Shadow DOM hooks) and polls for dynamic custom element initialization.
* **Canary Reflection Analysis**: Evaluates canary reflection across URL parameters, storage contexts, cookies, and window properties.
* **Prototype Property Probing**: Multi-worker concurrent evaluation for prototype property handling with isolated browser instances.
* **Front-End Library Fingerprinting**: Identifies client-side JavaScript libraries (`jQuery`, `Lodash`, `AngularJS`, `Bootstrap`, `Handlebars`, `React`, `Vue`, `Moment`) and flags versions against advisories.
* **DOM Interaction Testing (`--interact`)**: Bounded interaction engine that triggers click and hover event listeners on DOM elements to uncover hidden execution paths.
* **Egress & Scope Controls**: Strict domain scope management (`--scope {all,allow,domain}`) coupled with public URL IP validation (blocks loopback and private IPs by default).
* **Challenge Page Detection**: Heuristic detection for common challenge pages, rate limits, and verification interstitials.
* **Extensible Hook Pipeline**: Hook registry allowing custom detection rules, classifiers, or deployment-specific pipeline logic.

---

## Repository Structure

To publish and run `mkcat`, maintain the following directory layout:

```text
.
├── mkcat.py   # Main executable CLI
├── js/                       # Browser instrumentation scripts
│   ├── init_script.js        # Shadow DOM instrumentation script
│   └── classify_canary.js    # Canary reflection classifier
├── requirements.txt          # Python package dependencies
├── .gitignore                # Git ignore configuration
└── README.md                 # Project documentation
```

> **Important**: The script resolves browser instrumentation scripts relative to its installation location (`./js/init_script.js` and `./js/classify_canary.js`). Ensure the `js/` directory is published alongside `mkcat.py`.

---

## Requirements

### Prerequisites
* **Python**: 3.8 or higher
* **Chromium Browser**: Managed via Playwright

### Python Dependencies (`requirements.txt`)
```text
playwright>=1.30.0
packaging>=20.0
```

---

## Installation

1. **Obtain the Source Code**:
   Download or clone the project repository into your working environment.

2. **Create and Activate a Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Python Packages**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Playwright Chromium Browser**:
   ```bash
   playwright install chromium
   ```

---

## Usage

### Basic Scan
Scan a single target URL with default settings:
```bash
python mkcat.py target_url
```

### Batch Scanning from File
Scan multiple targets listed in a text file and write structured JSON output:
```bash
python mkcat.py -i targets.txt -o results.json
```

### JSON Lines Format
Stream results as JSON Lines (one JSON object per line):
```bash
python mkcat.py -i targets.txt --jsonl
```

### Scope Management & Domain Filtering
Restrict navigations to a specific root domain and its subdomains:
```bash
python mkcat.py target_url --scope domain --scope-domain domain_name
```

Allow additional trusted domains under the default `allow` scope:
```bash
python mkcat.py target_url --allow-domain cdn_domain --allow-domain auth_domain
```

### Enabling DOM Interactions
Opt-in to click/hover event trigger testing on interactive components:
```bash
python mkcat.py target_url --interact
```

### Testing Local Applications
To run scans against a local test application on `localhost:8000`, use the `--allow-local-test` flag:
```bash
python mkcat.py local_target_url --allow-local-test
```

---

## Command-Line Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| `URL ...` | Target URL(s) to scan | Positionals |
| `-i, --input FILE` | File containing target URLs (one per line) | `None` |
| `-o, --output FILE` | Output file path for JSON results | `stdout` |
| `--jsonl` | Output JSON Lines format instead of JSON array | `False` |
| `--scope {all,allow,domain}` | Scope policy for browser navigation | `allow` |
| `--allow-domain DOMAIN` | Additional domain allowed under `--scope allow` | `[]` |
| `--scope-domain DOMAIN` | Allowed root domain when using `--scope domain` | `None` |
| `--scan-timeout SECONDS` | Maximum wall-clock seconds spent per target | `120.0` |
| `--nav-timeout MS` | Per-navigation timeout in milliseconds | `20000` |
| `--pp-workers N` | Number of parallel worker threads for prototype analysis | `4` |
| `--interact` | Enable event trigger interactions (click/hover) | `False` |
| `--canary-retries N` | Retry attempts per canary source | `2` |
| `--max-retries N` | Retries on transient target navigation failure | `2` |
| `--delay SECONDS` | Pause duration between target scans | `0.0` |
| `--allow-local-test` | Permit scan on local loopback fixture | `False` |
| `-v, --verbose` | Enable verbose debug log output | `False` |
| `--silent` | Suppress banner and stdout output | `False` |

---

## Output Schema

Results are produced in a standardized v1.0 JSON format:

```json
{
  "url": "target_url",
  "scanned_at": "2026-10-29T09:46:00Z",
  "scan_status": "complete",
  "scan_stop_reason": "completed",
  "custom_elements": [
    {
      "tagName": "custom-card",
      "hasShadow": true,
      "shadowMode": "open"
    }
  ],
  "shadow_roots": {
    "open": 3,
    "closed": 1
  },
  "findings": [
    {
      "type": "vulnerable_library",
      "status": "potential",
      "library": "lodash",
      "version": "4.17.15"
    }
  ],
  "coverage": {
    "stages": {
      "target_validation": "complete",
      "navigation": "complete",
      "component_detection": "complete",
      "prototype_pollution": "complete",
      "library_detection": "complete"
    }
  }
}
```

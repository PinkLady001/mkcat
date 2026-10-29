#!/usr/bin/env python3
"""
Mascara Kitsune Cat.

Point it at one or more URLs and it will:
  - discover custom elements in the document and recursively in accessible open shadow roots
  - traverse closed shadow roots created after instrumentation (attachShadow is hooked)
  - hook common DOM/JS injection sinks (innerHTML, eval, setAttribute, ...)
  - inject canaries into URL params, storage, cookies, window.name and
    classify where/how they come back out (plain text vs. event handler
    vs. executable script block vs. shadow DOM, etc.)
  - probe for client-side prototype pollution via URL params
  - fingerprint common front-end libraries and flag known-vulnerable versions

"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import ipaddress
import math
import re
from concurrent.futures import ThreadPoolExecutor
import socket


log = logging.getLogger("webcomponent_scanner")

# ---------------------------------------------------------------------------
# Config 
# ---------------------------------------------------------------------------
BANNER = r"""
 /\_/\ <3       mkcat {ver}
( '.' )      Mascara Kitsune Cat
 > ^ <       shadow DOM - web component scanner
"""

ASYNC_CONFIG = {
    "min_observation_ms": 3000,       # Minimum observation when network idle was NOT reached
    "min_observation_ms_idle": 1000,  # Minimum observation after network idle (3000 restores old behavior)
    "network_idle_timeout": 8000,     # Wait up to 8s for network idle
    "component_poll_timeout": 12000,  # Poll for components up to 12s
    "poll_interval": 500,             # Check every 500ms
    "min_components_to_stop": 5,      # Stop early if 5+ components found
    "stable_rounds": 3,               # Consecutive unchanged snapshots before stable
    "max_custom_elements": 100,        # Safety cap on polling
    "max_shadow_roots": 500,          # Safety cap for shadow root counting
}

CANARY_CONFIG = {
    "retry_count": 2,                 # Retries on navigation failure
    "nav_timeout": 20_000,            # Navigation timeout (ms) — now actually used
    "network_idle_timeout": 5000,     # Post-nav idle wait (ms)
}

WORKER_CONFIG = {
    "max_retries": 2,                 # Retries per URL on transient errors — now actually used
    "request_delay": 0.0,             # Optional pause between URLs (politeness)
}

NAV_TIMEOUT = CANARY_CONFIG["nav_timeout"]
PP_WORKERS = 4  # parallel prototype-pollution vector workers; 1 = sequential
INTERACTION_ENABLED = False  # gated by --interact; off by default, see trigger_interactions()

# ---------------------------------------------------------------------------
# Hook registry. This is an extension point for the operator, not a place for
# the scanner to grow its own built-in detection logic: register_hook() is how
# site-specific or deployment-specific behavior (a custom WAF signature, a
# different bot-check vendor, a whole extra pipeline stage) gets added without
# editing analyze_page/test_canary_reflection. Every hook category documents
# its call signature and what a non-None return means; hooks run in
# registration order and the first non-None result wins. A hook that raises
# is logged at debug level and skipped, never fatal to the scan.
# ---------------------------------------------------------------------------

_HOOKS: dict = {}

HOOK_CATEGORIES = {
    "waf": "fn(page, status: int, headers: dict) -> dict | None. "
           "Return {\'blocked\': True, \'type\': <str>} to report a block/challenge page; "
           "return None to defer to the next registered hook.",
}


def register_hook(category: str, fn) -> None:
    """Register fn under category (see HOOK_CATEGORIES for the expected signature
    and return contract). Hooks run in the order they were registered."""
    _HOOKS.setdefault(category, []).append(fn)


def clear_hooks(category: str | None = None) -> None:
    """Remove all hooks for one category, or every category if omitted."""
    if category is None:
        _HOOKS.clear()
    else:
        _HOOKS.pop(category, None)


def run_hooks(category: str, *args, **kwargs):
    """Run every hook registered under category; return the first non-None
    result, or None if none fired (or none are registered)."""
    for fn in _HOOKS.get(category, []):
        try:
            result = fn(*args, **kwargs)
        except Exception as e:
            log.debug("Hook %r in category %r raised: %s",
                      getattr(fn, "__name__", fn), category, e)
            continue
        if result is not None:
            return result
    return None

DEFAULT_SCAN_TIMEOUT_SECONDS = 120
SCANNER_VERSION = "1.0.0"
OUTPUT_SCHEMA_VERSION = "1.0"
MAX_WALK_NODES = 5_000

KNOWN_VULNERABLE_RANGES = {
    "jquery":     [("<3.5.0",            "CVE-2020-11022")],
    "lodash":     [("<4.17.21",          "CVE-2021-23337")],
    "angular":    [("<1.8.0",            "CVE-2020-7676")],   # AngularJS 1.x
    "bootstrap":  [(">=3.0.0,<3.4.1",    "CVE-2019-8331"),
                   (">=4.0.0,<4.3.1",    "CVE-2019-8331")],
    "handlebars": [("<4.7.7",            "CVE-2021-23369")],
}

# ---------------------------------------------------------------------------
# Exceptions 
# ---------------------------------------------------------------------------

class TransientScanError(Exception):
    """Worth retrying (timeout, flaky network, etc.)."""


class PermanentScanError(Exception):
    """Not worth retrying (blocked, WAF, unreachable)."""


class ScanDeadlineExceeded(TransientScanError):
    """The per-target time budget was exhausted; remaining tests are skipped."""


class ScanDeadline:
    """Monotonic wall-clock budget shared by all stages for one target."""

    def __init__(self, timeout_seconds: float):
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("scan timeout must be a finite number > 0")
        self.timeout_seconds = float(timeout_seconds)
        self.started_at = time.monotonic()
        self.expires_at = self.started_at + self.timeout_seconds

    def remaining_seconds(self) -> float:
        return max(0.0, self.expires_at - time.monotonic())

    def expired(self) -> bool:
        return self.remaining_seconds() <= 0.0

    def check(self, stage: str) -> None:
        if self.expired():
            raise ScanDeadlineExceeded(f"scan_timeout: total scan deadline exceeded during {stage}")

    def timeout_ms(self, configured_ms: int, stage: str) -> int:
        """Cap a Playwright timeout at the time remaining in the full scan."""
        self.check(stage)
        remaining_ms = int(self.remaining_seconds() * 1000)
        if remaining_ms <= 0:
            raise ScanDeadlineExceeded(f"scan_timeout: total scan deadline exceeded during {stage}")
        return max(1, min(int(configured_ms), remaining_ms))


STOP_REASON_DESCRIPTIONS = {
    "completed": "The stage finished all planned checks.",
    "stable": "Observed component state remained unchanged for the required rounds.",
    "timeout": "The stage-specific observation time limit was reached.",
    "deadline_exceeded": "The target-wide scan time budget was exhausted.",
    "max_custom_elements": "The custom-element safety cap was reached.",
    "max_shadow_roots": "The shadow-root safety cap was reached.",
    "blocked_by_policy": "The target or a required request was blocked by scanner scope policy.",
    "blocked_by_waf": "The page appears to have blocked the scan.",
    "navigation_timeout": "A navigation did not complete within its timeout.",
    "navigation_failed": "Navigation failed for a reason other than the scan deadline.",
    "probe_error": "The probe could not complete because an operation failed.",
    "probe_errors": "One or more probe vectors failed; negative results are inconclusive.",
    "finding_observed": "A finding was observed, so remaining vectors were skipped.",
    "analysis_error": "The scan failed during page analysis.",
    "partial_coverage": "The scan ended with one or more checks incomplete.",
}


def _exception_stop_reason(exc: BaseException) -> str:
    """Map low-level exceptions to a small, stable set of coverage reasons."""
    message = str(exc).lower()
    if isinstance(exc, ScanDeadlineExceeded) or "scan_timeout" in message or "deadline exceeded" in message:
        return "deadline_exceeded"
    if "waf" in message:
        return "blocked_by_waf"
    if any(token in message for token in ("egress policy", "blocked by policy", "blocked: policy", "scope policy")):
        return "blocked_by_policy"
    if "timeout" in message or "timed out" in message:
        return "navigation_timeout"
    if any(token in message for token in ("net::err_aborted", "navigation failed", "net::err_")):
        return "navigation_failed"
    return "probe_error"


def _mark_unstarted_stages(stage_coverage: dict, reason: str) -> None:
    """Give each not-yet-run stage an explicit reason instead of leaving it ambiguous."""
    for stage, status in list(stage_coverage.items()):
        if status == "not_started":
            stage_coverage[stage] = f"skipped_{reason}"


# ---------------------------------------------------------------------------
# Library / version detection 
# ---------------------------------------------------------------------------

LIBRARY_DETECTION_JS = """
() => {
    const d = [];
    const bsv = window.bootstrap?.Tooltip?.VERSION || window.jQuery?.fn?.tooltip?.Constructor?.VERSION;
    if (window.jQuery?.fn?.jquery)     d.push({library:'jquery',     version:window.jQuery.fn.jquery});
    if (window._?.VERSION)             d.push({library:'lodash',     version:window._.VERSION});
    if (window.React?.version)         d.push({library:'react',      version:window.React.version});
    if (window.Vue?.version)           d.push({library:'vue',        version:window.Vue.version});
    if (window.angular?.version?.full) d.push({library:'angular',    version:window.angular.version.full});
    if (bsv || window.bootstrap?.Modal) d.push({library:'bootstrap', version: bsv || 'unknown'});
    if (window.Handlebars?.VERSION)    d.push({library:'handlebars', version:window.Handlebars.VERSION});
    if (window.moment?.version)        d.push({library:'moment',     version:window.moment.version});
    return d;
}
"""


def detect_libraries_on_page(page, deadline: ScanDeadline | None = None) -> list:
    try:
        from packaging import version as pkg_version
    except ImportError:
        log.warning("packaging not installed — skipping library version check")
        return []

    if deadline is not None:
        deadline.check("library detection")
    try:
        libraries = page.evaluate(LIBRARY_DETECTION_JS)
    except Exception as e:
        log.debug(f"Library JS eval failed: {e}")
        return []

    findings = []
    for lib in libraries:
        if deadline is not None:
            deadline.check("library detection")
        name = lib["library"]
        ver_str = lib.get("version", "unknown")
        if name not in KNOWN_VULNERABLE_RANGES or ver_str == "unknown":
            continue
        try:
            v = pkg_version.parse(ver_str.split("-")[0])
            for range_str, cve in KNOWN_VULNERABLE_RANGES[name]:
                if v in SpecifierSet(range_str):
                    findings.append({
                        "type": "vulnerable_library",
                        "status": "potential",
                        "library": name,
                        "version": ver_str,
                        "cve": cve,
                        "affected_version_condition": range_str,
                        "sink": "", "element": "", "source": "library_detection",
                        "evidence": [
                            f"The page reports {name} version {ver_str}.",
                            f"The detected version matches the scanner's known affected-version condition {range_str} for {cve}.",
                        ],
                        "sample": {
                            "library": name,
                            "detected_version": ver_str,
                            "affected_version_condition": range_str,
                            "cve": cve,
                        },
                        "limitations": [
                            "A client-side version match does not by itself demonstrate that the vulnerable code path is reachable or exploitable on this site.",
                            "Verify the detected version and the advisory's affected-version conditions against the deployed dependency.",
                        ],
                    })
                    break
        except Exception as e:
            log.debug(f"Version parse error {name} {ver_str}: {e}")
    return findings


# ---------------------------------------------------------------------------
# Browser-side instrumentation 
# ---------------------------------------------------------------------------

_JS_DIR = Path(__file__).resolve().parent / "js"


def _load_js(name: str) -> str:
    return (_JS_DIR / name).read_text(encoding="utf-8")


INIT_SCRIPT = _load_js("init_script.js")
CLASSIFY_JS_TEMPLATE = _load_js("classify_canary.js")

# ---------------------------------------------------------------------------
#  Self-contained helpers.
# ---------------------------------------------------------------------------

def _host_matches_scope(hostname: str, allowed_domains: set[str] | None) -> bool:
    """Return whether a hostname belongs to the configured domain scope. None means unrestricted scope."""
    if allowed_domains is None:
        return True
    host = hostname.rstrip(".").lower()
    return any(host == domain or host.endswith("." + domain) for domain in allowed_domains)


def _validate_public_http_url(url: str, allowed_hosts: set[str] | None = None,
                              allow_local_test: bool = False,
                              deadline: ScanDeadline | None = None) -> None:
    """Reject URLs that could target local/private services.

    This is a defense-in-depth guard, not a substitute for network egress
    controls: DNS can change between validation and connection. Run scans in a
    sandbox/container whose network policy also blocks private and metadata IPs.
    """
    try:
        if deadline is not None:
            deadline.check("URL safety validation")
        parts = urlsplit(url)
        if parts.scheme.lower() not in {"http", "https"}:
            raise ValueError("only http:// and https:// URLs are allowed")
        if not parts.hostname:
            raise ValueError("URL has no hostname")
        if parts.username is not None or parts.password is not None:
            raise ValueError("URLs containing credentials are not allowed")
        hostname = parts.hostname.rstrip(".").lower()
        if not hostname or "%" in hostname:
            raise ValueError("invalid hostname")
        if not _host_matches_scope(hostname, allowed_hosts):
            raise ValueError(f"hostname {hostname!r} is outside the configured domain scope")
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
        local_test_host = hostname in {"localhost", "127.0.0.1", "::1"}
        if allow_local_test and local_test_host:
            # Deliberately narrow exception for the bundled local fixture only.
            # It is opt-in, HTTP-only, loopback-only, and fixed to port 8000.
            if parts.scheme.lower() != "http" or port != 8000:
                raise ValueError("--allow-local-test permits only http://localhost:8000 or loopback equivalent")
        elif port not in {80, 443}:
            raise ValueError("only ports 80 and 443 are allowed (or port 8000 with --allow-local-test)")

        # Resolve every returned address and reject the hostname if any answer
        # is non-global. The opt-in local fixture exception accepts loopback only.
        try:
            literal_ip = ipaddress.ip_address(hostname)
            addresses = [literal_ip]
        except ValueError:
            # DNS can fail transiently even when the host is reachable. Retry a
            # few times before treating the target as unresolved; still fail
            # closed if every attempt fails.
            records = None
            last_dns_error = None
            for dns_attempt in range(3):
                if deadline is not None:
                    deadline.check("DNS validation")
                dns_start = time.monotonic()
                try:
                    records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
                    elapsed = time.monotonic() - dns_start
                    if deadline is not None:
                        deadline.check("DNS validation")
                    if elapsed >= 0.5:
                        log.warning("SLOW DNS: %.2fs resolving %s", elapsed, hostname,)
                    break
                except socket.gaierror as e:
                    elapsed = time.monotonic() - dns_start
                    log.warning("DNS attempt %d/3 took %.2fs for %s: %s", dns_attempt + 1, elapsed, hostname, e,)
                    last_dns_error = e
                    if dns_attempt < 2:
                        pause = 0.25 * (dns_attempt + 1)
                        if deadline is not None:
                            deadline.check("DNS retry backoff")
                            pause = min(pause, deadline.remaining_seconds())
                        if pause > 0:
                            time.sleep(pause)
            if records is None:
                raise ValueError(f"hostname resolution failed after 3 attempts: {last_dns_error}") from last_dns_error
            addresses = []
            for record in records:
                try:
                    addresses.append(ipaddress.ip_address(record[4][0].split("%", 1)[0]))
                except ValueError:
                    continue
        if not addresses:
            raise ValueError("hostname did not resolve to an IP address")
        if allow_local_test and local_test_host:
            if any(not address.is_loopback for address in addresses):
                raise ValueError("local test hostname resolved to a non-loopback address")
        elif any(not address.is_global for address in addresses):
            raise ValueError("target resolves to a non-public IP address")
    except ScanDeadlineExceeded:
        raise
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"invalid target URL: {e}") from e


def _guard_browser_request(route, allowed_hosts: set[str] | None, allow_local_test: bool = False,
                          deadline: ScanDeadline | None = None) -> None:
    """Abort requests outside the explicit host scope or to non-public IPs."""
    started = time.monotonic()
    request_url = route.request.url

    try:
        # Browser-internal schemes are not network destinations. Only allow
        # them when they are not being handled as HTTP(S) requests.
        _validate_public_http_url(request_url, allowed_hosts, allow_local_test=allow_local_test,
                                  deadline=deadline)
        route.continue_()
    except Exception as e:
        log.warning(f"Blocked browser request to {route.request.url!r}: {e}")
        try:
            route.abort("blockedbyclient")
        except Exception:
            pass
    finally:
        elapsed = time.monotonic() - started
        if elapsed >= 0.5:
            log.warning("SLOW BROWSER-REQUEST validation: %.2fs for %s", elapsed, request_url,)

def is_target_reachable(url: str, allowed_hosts: set[str] | None,
                        allow_local_test: bool = False,
                        deadline: ScanDeadline | None = None) -> tuple[bool, str]:
    """Validate target safety before browser navigation; actual reachability is tested by Playwright."""
    try:
        _validate_public_http_url(url, allowed_hosts, allow_local_test=allow_local_test,
                                  deadline=deadline)
        return True, "validated_public_target"
    except ValueError as e:
        return False, f"unsafe_target:{e}"


_WAF_MARKERS = (
    "attention required", "checking your browser", "cf-browser-verification",
    "access denied", "request blocked", "ray id", "akamai", "incapsula",
    "distil networks", "please verify you are a human",
)


def detect_waf(page) -> dict:
    """Heuristic only — looks for common challenge-page markers, not an
    evasion toolkit. Used to avoid wasting time/queueing findings for pages
    that are actually a bot-check interstitial rather than the real target."""
    try:
        title = (page.title() or "").lower()
        body_snippet = page.evaluate("() => document.body ? document.body.innerText.slice(0, 2000) : ''").lower()
    except Exception:
        return {"blocked": False}

    haystack = f"{title} {body_snippet}"
    for marker in _WAF_MARKERS:
        if marker in haystack:
            return {"blocked": True, "type": marker}
    return {"blocked": False}


_VENDOR_WAF_HEADER_MARKERS = {
    "x-vercel-mitigated": {"challenge"},
    "cf-mitigated": {"challenge"},
}


def _waf_from_headers(status: int, headers: dict) -> dict:
    """Challenge / rate-limit detection from response headers. Heuristic only; no evasion."""
    h = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    for name, values in _VENDOR_WAF_HEADER_MARKERS.items():
        if h.get(name) in values:
            return {"blocked": True, "type": f"{name}:{h.get(name)}"}
    if "x-vercel-challenge-token" in h:
        return {"blocked": True, "type": "vercel_challenge"}
    if status == 429:
        return {"blocked": True, "type": "rate_limited"}
    return {"blocked": False}


# Default "waf" hooks: page-content markers, then response-header markers.
# Both built on the uniform (page, status, headers) hook signature so an
# operator can register additional detectors alongside these, or call
# clear_hooks("waf") first to replace them outright.
def _waf_hook_page_markers(page, status, headers):
    return detect_waf(page)


def _waf_hook_response_headers(page, status, headers):
    return _waf_from_headers(status, headers)


register_hook("waf", _waf_hook_page_markers)
register_hook("waf", _waf_hook_response_headers)


def make_context(browser, allowed_hosts: set[str] | None, allow_local_test: bool = False,
                 deadline: ScanDeadline | None = None):
    context = browser.new_context(
        viewport={"width": 1366, "height": 768},
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ),
        locale="en-US",
    )
    context.add_init_script(INIT_SCRIPT)
    # Intercept top-level navigations, redirects and HTTP(S) subresources.
    # Network-level egress restrictions are still required against DNS rebinding.
    context.route("**/*", lambda route: _guard_browser_request(
        route, allowed_hosts, allow_local_test, deadline=deadline
    ))
    return context


def launch_browser(pw):
    return pw.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
            "--disable-extensions", "--disable-background-networking",
            "--mute-audio", "--js-flags=--max-old-space-size=256",
        ],
    )


# ---------------------------------------------------------------------------
# Async component polling
# ---------------------------------------------------------------------------

def wait_for_custom_elements(page, timeout_ms: int = 12000,
                              poll_interval_ms: int = 500,
                              stable_rounds: int = 3,
                              min_observation_ms: int = 3000,
                              deadline: ScanDeadline | None = None) -> dict:
    """Poll component/Shadow DOM state until it is stable or a safety limit is hit.

    Stability is based on the current DOM snapshot (including zero custom
    elements), not only on the accumulated set of tags. A minimum observation
    period gives delayed component registration a chance to occur.
    """
    if deadline is not None:
        timeout_ms = deadline.timeout_ms(timeout_ms, "component polling")
    start = time.monotonic()
    found_elems = set()
    open_max = 0
    closed_max = 0
    poll_rounds = 0
    stable_cnt = 0
    previous_signature = None
    error = None
    stop_reason = 'timeout'

    poll_interval_ms = max(100, int(poll_interval_ms))
    timeout_ms = max(poll_interval_ms, int(timeout_ms))
    stable_rounds = max(1, int(stable_rounds))
    min_observation_ms = max(0, int(min_observation_ms))
    max_polls = max(1, (timeout_ms + poll_interval_ms - 1) // poll_interval_ms)

    for round_num in range(max_polls):
        if deadline is not None and deadline.expired():
            stop_reason = 'deadline_exceeded'
            break
        poll_rounds += 1
        try:
            result = page.evaluate("""
                () => {
                    const elements = new Set();
                    const __cm = new Map((window.__closedRoots || []).filter(r => r.host.isConnected).map(r => [r.host, r.root]));
                    const visitedRoots = new Set();
                    const roots = [document];
                    let open_count = 0;
                    while (roots.length) {
                        const root = roots.pop();
                        if (!root || visitedRoots.has(root)) continue;
                        visitedRoots.add(root);
                        let descendants = [];
                        try { descendants = root.querySelectorAll('*'); } catch (_) {}
                        descendants.forEach(el => {
                            const tag = el.tagName.toLowerCase();
                            if (tag.includes('-')) elements.add(tag);
                            if (!el.shadowRoot && __cm.has(el)) roots.push(__cm.get(el));
                            if (el.shadowRoot && el.shadowRoot.mode === 'open') {
                                open_count++;
                                roots.push(el.shadowRoot);
                            }
                        });
                    }
                    const hooked = window.__shadowLog || [];
                    const closed_count = hooked.filter(r => r.mode === 'closed').length;
                    return {
                        elements: Array.from(elements).sort(),
                        open_count,
                        closed_count
                    };
                }
            """)
            current_elements = set(result.get('elements', []))
            found_elems.update(current_elements)
            current_open = int(result.get('open_count', 0) or 0)
            current_closed = int(result.get('closed_count', 0) or 0)
            open_max = max(open_max, current_open)
            closed_max = max(closed_max, current_closed)

            if deadline is not None and deadline.expired():
                stop_reason = 'deadline_exceeded'
                break

            signature = (
                tuple(sorted(current_elements)),
                current_open,
                current_closed,
            )
            elapsed_ms = (time.monotonic() - start) * 1000
            if signature == previous_signature:
                stable_cnt += 1
            else:
                stable_cnt = 0
            previous_signature = signature

            if (elapsed_ms >= min_observation_ms and
                    stable_cnt >= stable_rounds):
                stop_reason = 'stable'
                break
            if len(found_elems) >= ASYNC_CONFIG.get('max_custom_elements', 50):
                stop_reason = 'max_custom_elements'
                break
            if open_max + closed_max >= ASYNC_CONFIG.get('max_shadow_roots', 100):
                stop_reason = 'max_shadow_roots'
                break
        except Exception as e:
            error = f"Poll round {round_num} failed: {str(e)}"
            log.debug(error)

        remaining_ms = timeout_ms - ((time.monotonic() - start) * 1000)
        if deadline is not None:
            remaining_ms = min(remaining_ms, int(deadline.remaining_seconds() * 1000))
        if remaining_ms <= 0:
            if deadline is not None and deadline.expired():
                stop_reason = 'deadline_exceeded'
            break
        time.sleep(min(poll_interval_ms, remaining_ms) / 1000)

    elapsed_ms = (time.monotonic() - start) * 1000
    return {
        'custom_elements': sorted(found_elems),
        'shadow_roots': {'open': open_max, 'closed': closed_max},
        'poll_rounds': poll_rounds,
        'elapsed_ms': elapsed_ms,
        'stable': stop_reason == 'stable',
        'stop_reason': stop_reason,
        'stop_reason_detail': STOP_REASON_DESCRIPTIONS.get(
            stop_reason, 'The component observation stage stopped before full convergence.'
        ),
        'error': error,
    }


# ---------------------------------------------------------------------------
# Prototype pollution
# ---------------------------------------------------------------------------

def test_prototype_pollution_app(page, url: str, deadline: ScanDeadline | None = None) -> dict:
    """Probe URL-driven prototype pollution and report per-vector coverage.

    A negative result is only conclusive if every vector completed. Failed
    navigations/evaluations are retained as failed coverage instead of being
    silently converted to a clean result.
    """
    marker = f"__pp_{uuid.uuid4().hex[:8]}__"
    base = url.split('?')[0].split('#')[0]
    vectors = [
        ("direct_proto", f"__proto__[{marker}]=polluted"),
        ("constructor_prototype", f"constructor[prototype][{marker}]=polluted"),
        ("nested_proto", f"a[__proto__][{marker}]=polluted"),
        ("nested_constructor_prototype", f"x[constructor][prototype][{marker}]=polluted"),
    ]
    coverage = {"attempted": [], "completed": [], "failed": [], "skipped": []}

    def finish(vulnerable: bool, stop_reason: str, **extra) -> dict:
        failures = bool(coverage["failed"])
        return {
            "vulnerable": vulnerable,
            "payload": extra.pop("payload", None),
            "skipped": stop_reason == "deadline_exceeded",
            "stop_reason": stop_reason,
            "assessment": ("vulnerable" if vulnerable else
                           "inconclusive" if failures or coverage["skipped"] else
                           "no_pollution_observed"),
            "coverage": coverage,
            **extra,
        }

    def skip_remaining(start_index: int, reason: str) -> None:
        coverage["skipped"].extend(
            {"vector": name, "reason": reason} for name, _ in vectors[start_index:]
        )

    def locations_js() -> str:
        return f"""
            () => {{
                const marker = '{marker}';
                const locations = [];
                if (Object.prototype.hasOwnProperty(marker)) locations.push('Object.prototype');
                if (Array.prototype.hasOwnProperty(marker)) locations.push('Array.prototype');
                if (Function.prototype.hasOwnProperty(marker)) locations.push('Function.prototype');
                if (typeof HTMLElement !== 'undefined' && HTMLElement.prototype &&
                    HTMLElement.prototype.hasOwnProperty(marker)) locations.push('HTMLElement.prototype');
                if (typeof Element !== 'undefined' && Element.prototype &&
                    Element.prototype.hasOwnProperty(marker)) locations.push('Element.prototype');
                return locations;
            }}
        """

    # Single baseline for all vectors. The marker is unique per run, so the
    # pre-existing prototype state cannot differ between vectors.
    pre_set = set()
    try:
        nav_timeout = deadline.timeout_ms(NAV_TIMEOUT, "prototype-pollution baseline navigation") if deadline else NAV_TIMEOUT
        page.goto(base, timeout=nav_timeout, wait_until='domcontentloaded')
        if deadline is not None:
            deadline.check("prototype-pollution baseline navigation")
        try:
            idle_timeout = deadline.timeout_ms(3000, "prototype-pollution baseline network idle") if deadline else 3000
            page.wait_for_load_state('networkidle', timeout=idle_timeout)
        except ScanDeadlineExceeded:
            raise
        except Exception:
            if deadline is not None:
                deadline.check("prototype-pollution baseline network idle")
        pre_set = set(page.evaluate(locations_js()))
    except ScanDeadlineExceeded as e:
        coverage["failed"].append({"vector": "baseline", "phase": "baseline", "reason": "deadline_exceeded", "error": str(e)})
        skip_remaining(0, "deadline_exceeded")
        return finish(False, "deadline_exceeded")
    except Exception as e:
        # Informational only: a failed baseline does not reduce vector coverage.
        log.debug("Prototype-pollution baseline failed for %s: %s", base, e)
        if deadline is not None and deadline.expired():
            skip_remaining(0, "deadline_exceeded")
            return finish(False, "deadline_exceeded")

    for index, (vector_name, vec) in enumerate(vectors):
        if deadline is not None and deadline.expired():
            skip_remaining(index, "deadline_exceeded")
            return finish(False, "deadline_exceeded")
        coverage["attempted"].append(vector_name)

        try:
            nav_timeout = deadline.timeout_ms(NAV_TIMEOUT, "prototype-pollution test navigation") if deadline else NAV_TIMEOUT
            page.goto(f"{base}?{vec}", timeout=nav_timeout, wait_until='domcontentloaded')
            if deadline is not None:
                deadline.check("prototype-pollution test navigation")
            try:
                idle_timeout = deadline.timeout_ms(3000, "prototype-pollution test network idle") if deadline else 3000
                page.wait_for_load_state('networkidle', timeout=idle_timeout)
            except ScanDeadlineExceeded:
                raise
            except Exception:
                if deadline is not None:
                    deadline.check("prototype-pollution test network idle")

            post_locations = page.evaluate(locations_js())
            new_locations = set(post_locations) - pre_set
            value = None
            if new_locations:
                try:
                    value = page.evaluate(f"""
                        () => {{
                            const marker = '{marker}';
                            for (const proto of [Object.prototype, Array.prototype, Function.prototype,
                                typeof HTMLElement !== 'undefined' && HTMLElement.prototype,
                                typeof Element !== 'undefined' && Element.prototype]) {{
                                if (proto && Object.prototype.hasOwnProperty.call(proto, marker))
                                    return String(proto[marker]).slice(0, 50);
                            }}
                            return null;
                        }}
                    """)
                except Exception:
                    value = None

            # Clean up only our unique marker even when the vector did not succeed.
            try:
                page.evaluate(f"""
                    () => {{
                        const marker = '{marker}';
                        [Object.prototype, Array.prototype, Function.prototype,
                         typeof HTMLElement !== 'undefined' && HTMLElement.prototype,
                         typeof Element !== 'undefined' && Element.prototype
                        ].forEach(p => {{ if (p) {{ try {{ delete p[marker]; }} catch(e) {{}} }} }});
                    }}
                """)
            except Exception:
                pass

            coverage["completed"].append(vector_name)
            if new_locations:
                log.info("Prototype pollution via: %s (new: %s)", vec, sorted(new_locations))
                skip_remaining(index + 1, "finding_observed")
                return finish(
                    True, "finding_observed", payload=vec, value=value,
                    vector="url_param", locations=sorted(new_locations),
                    pre_existing=sorted(pre_set) if pre_set else [],
                )
        except ScanDeadlineExceeded as e:
            coverage["failed"].append({"vector": vector_name, "phase": "injected_navigation_or_check", "reason": "deadline_exceeded", "error": str(e)})
            skip_remaining(index + 1, "deadline_exceeded")
            return finish(False, "deadline_exceeded")
        except Exception as e:
            reason = _exception_stop_reason(e)
            coverage["failed"].append({"vector": vector_name, "phase": "injected_navigation_or_check", "reason": reason, "error": str(e)})
            log.debug("Prototype-pollution vector %s failed: %s", vector_name, e)
            if deadline is not None and deadline.expired():
                skip_remaining(index + 1, "deadline_exceeded")
                return finish(False, "deadline_exceeded")

    if coverage["failed"]:
        return finish(False, "probe_errors")
    return finish(False, "completed")


# ---------------------------------------------------------------------------
# Main page analysis
# ---------------------------------------------------------------------------

# --- Parallel prototype-pollution probe (one Chromium per vector) ----------
# Playwright's sync API is not thread-safe, so each worker thread owns its own
# sync_playwright() instance, browser and context. The marker is unique per
# run, so no baseline load is needed: it cannot pre-exist on the page.

PP_VECTOR_TEMPLATES = [
    ("direct_proto", "__proto__[{m}]=polluted"),
    ("constructor_prototype", "constructor[prototype][{m}]=polluted"),
    ("nested_proto", "a[__proto__][{m}]=polluted"),
    ("nested_constructor_prototype", "x[constructor][prototype][{m}]=polluted"),
]

_PP_LOCATIONS_JS = """
() => {
    const marker = '__MARKER__';
    const locations = [];
    if (Object.prototype.hasOwnProperty(marker)) locations.push('Object.prototype');
    if (Array.prototype.hasOwnProperty(marker)) locations.push('Array.prototype');
    if (Function.prototype.hasOwnProperty(marker)) locations.push('Function.prototype');
    if (typeof HTMLElement !== 'undefined' && HTMLElement.prototype &&
        HTMLElement.prototype.hasOwnProperty(marker)) locations.push('HTMLElement.prototype');
    if (typeof Element !== 'undefined' && Element.prototype &&
        Element.prototype.hasOwnProperty(marker)) locations.push('Element.prototype');
    return locations;
}
"""

_PP_VALUE_JS = """
() => {
    const marker = '__MARKER__';
    for (const proto of [Object.prototype, Array.prototype, Function.prototype,
        typeof HTMLElement !== 'undefined' && HTMLElement.prototype,
        typeof Element !== 'undefined' && Element.prototype]) {
        if (proto && Object.prototype.hasOwnProperty.call(proto, marker))
            return String(proto[marker]).slice(0, 50);
    }
    return null;
}
"""


def _pp_vector_worker(vector_name: str, vec: str, marker: str, base: str,
                      allowed_hosts: set[str] | None, allow_local_test: bool,
                      deadline: ScanDeadline | None) -> dict:
    """Run one pollution vector in a private Playwright instance (thread-safe)."""
    from playwright.sync_api import sync_playwright
    locations_js = _PP_LOCATIONS_JS.replace("__MARKER__", marker)
    value_js = _PP_VALUE_JS.replace("__MARKER__", marker)
    try:
        with sync_playwright() as pw:
            browser = launch_browser(pw)
            try:
                context = make_context(browser, allowed_hosts,
                                       allow_local_test=allow_local_test, deadline=deadline)
                try:
                    page = context.new_page()
                    nav_timeout = (deadline.timeout_ms(NAV_TIMEOUT, f"prototype-pollution navigation ({vector_name})")
                                   if deadline else NAV_TIMEOUT)
                    page.goto(f"{base}?{vec}", timeout=nav_timeout, wait_until='domcontentloaded')
                    if deadline is not None:
                        deadline.check(f"prototype-pollution navigation ({vector_name})")
                    try:
                        idle_timeout = (deadline.timeout_ms(3000, f"prototype-pollution network idle ({vector_name})")
                                        if deadline else 3000)
                        page.wait_for_load_state('networkidle', timeout=idle_timeout)
                    except ScanDeadlineExceeded:
                        raise
                    except Exception:
                        if deadline is not None:
                            deadline.check(f"prototype-pollution network idle ({vector_name})")
                    locations = page.evaluate(locations_js)
                    value = None
                    if locations:
                        try:
                            value = page.evaluate(value_js)
                        except Exception:
                            value = None
                    return {"status": "completed", "locations": locations, "value": value}
                finally:
                    try:
                        context.close()
                    except Exception:
                        pass
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except ScanDeadlineExceeded as e:
        return {"status": "failed", "reason": "deadline_exceeded", "error": str(e)}
    except Exception as e:
        reason = ("deadline_exceeded" if (deadline is not None and deadline.expired())
                  else _exception_stop_reason(e))
        log.debug("Prototype-pollution worker %s failed: %s", vector_name, e)
        return {"status": "failed", "reason": reason, "error": str(e)}


def test_prototype_pollution_parallel(url: str, allowed_hosts: set[str] | None,
                                      allow_local_test: bool = False,
                                      deadline: ScanDeadline | None = None,
                                      workers: int = 4) -> dict:
    """Same result shape as test_prototype_pollution_app, vectors run concurrently."""
    marker = f"__pp_{uuid.uuid4().hex[:8]}__"
    base = url.split('?')[0].split('#')[0]
    vectors = [(name, tpl.format(m=marker)) for name, tpl in PP_VECTOR_TEMPLATES]
    coverage = {"attempted": [], "completed": [], "failed": [], "skipped": []}

    def finish(vulnerable: bool, stop_reason: str, **extra) -> dict:
        failures = bool(coverage["failed"])
        return {
            "vulnerable": vulnerable,
            "payload": extra.pop("payload", None),
            "skipped": stop_reason == "deadline_exceeded",
            "stop_reason": stop_reason,
            "assessment": ("vulnerable" if vulnerable else
                           "inconclusive" if failures or coverage["skipped"] else
                           "no_pollution_observed"),
            "coverage": coverage,
            **extra,
        }

    if deadline is not None and deadline.expired():
        coverage["skipped"].extend({"vector": n, "reason": "deadline_exceeded"} for n, _ in vectors)
        return finish(False, "deadline_exceeded")

    coverage["attempted"].extend(n for n, _ in vectors)
    with ThreadPoolExecutor(max_workers=max(1, min(int(workers), len(vectors))),
                            thread_name_prefix="pp") as pool:
        futures = [pool.submit(_pp_vector_worker, n, v, marker, base,
                               allowed_hosts, allow_local_test, deadline)
                   for n, v in vectors]
        results = [f.result() for f in futures]

    hits = []
    deadline_hit = False
    for (name, vec), res in zip(vectors, results):
        if res["status"] == "completed":
            coverage["completed"].append(name)
            if res["locations"]:
                hits.append((name, vec, res))
        else:
            coverage["failed"].append({"vector": name, "phase": "injected_navigation_or_check",
                                       "reason": res["reason"], "error": res["error"]})
            deadline_hit = deadline_hit or res["reason"] == "deadline_exceeded"

    if hits:
        name, vec, res = hits[0]
        log.info("Prototype pollution via: %s (new: %s)", vec, sorted(res["locations"]))
        return finish(True, "finding_observed", payload=vec, value=res["value"],
                      vector="url_param", locations=sorted(res["locations"]),
                      pre_existing=[], vulnerable_vectors=[h[0] for h in hits])
    if deadline_hit or (deadline is not None and deadline.expired()):
        return finish(False, "deadline_exceeded")
    if coverage["failed"]:
        return finish(False, "probe_errors")
    return finish(False, "completed")


def analyze_page(url: str, context, allowed_hosts: set[str] | None,
                 allow_local_test: bool = False,
                 deadline: ScanDeadline | None = None) -> dict:
    analysis = {
        'customElements': [], 'shadowRoots': {'open': 0, 'closed': 0},
        'attachShadowCalls': [], 'protoPollution': {'vulnerable': False, 'payload': None},
        'libraryFindings': [], 'domClobbering': [],
        'csp': '', 'response_headers': {}, 'security_headers': {},
        'response_metadata': {},
        'trustedTypes': {'supported': False, 'enforced': False},
        'detection_metadata': {}, 'error': None,
        'scan_status': 'running', 'scan_stop_reason': None,
        'stage_coverage': {
            'target_validation': 'not_started',
            'navigation': 'not_started',
            'component_detection': 'not_started',
            'prototype_pollution': 'not_started',
            'library_detection': 'not_started',
        },
    }
    page = context.new_page()
    page_errors: list = []
    analysis['page_errors'] = page_errors
    page.on("pageerror", lambda err: page_errors.append(str(err)[:300]) if len(page_errors) < 20 else None)
    try:
        if deadline is not None:
            deadline.check("target validation")
        reachable, reason = is_target_reachable(
            url, allowed_hosts, allow_local_test=allow_local_test, deadline=deadline
        )
        if not reachable:
            analysis['error'] = f"blocked:{reason}"
            analysis['scan_status'] = 'blocked'
            analysis['scan_stop_reason'] = 'target_validation_blocked'
            analysis['stage_coverage']['target_validation'] = 'blocked'
            _mark_unstarted_stages(analysis['stage_coverage'], 'blocked_by_policy')
            return analysis
        analysis['stage_coverage']['target_validation'] = 'complete'

        nav_start = time.monotonic()
        analysis['stage_coverage']['navigation'] = 'running'
        nav_timeout = deadline.timeout_ms(NAV_TIMEOUT, "main navigation") if deadline else NAV_TIMEOUT
        response = page.goto(url, timeout=nav_timeout, wait_until='domcontentloaded')
        if deadline is not None:
            deadline.check("main navigation")
        if response is None:
            raise RuntimeError(
                "navigation returned no HTTP response; the request may have been blocked or aborted"
            )

        if response:
            headers = response.headers or {}
            analysis['csp'] = headers.get('content-security-policy', '')
            analysis['response_headers'] = dict(headers)
            analysis['response_metadata'] = {
                'status': response.status,
                'final_url': response.url,
                'header_count': len(headers),
                'header_names': sorted(headers.keys()),
            }
            analysis['security_headers'] = {
                'x_frame_options': headers.get('x-frame-options'),
                'x_content_type_options': headers.get('x-content-type-options'),
                'cross_origin_opener_policy': headers.get('cross-origin-opener-policy'),
                'cross_origin_embedder_policy': headers.get('cross-origin-embedder-policy'),
            }

        waf = run_hooks("waf", page, response.status, headers) or {"blocked": False}
        if waf.get('blocked'):
            analysis['error'] = f"waf:{waf.get('type', 'unknown')}"
            analysis['scan_status'] = 'blocked'
            analysis['scan_stop_reason'] = 'waf_detected'
            analysis['stage_coverage']['navigation'] = 'blocked_by_waf'
            _mark_unstarted_stages(analysis['stage_coverage'], 'blocked_by_waf')
            return analysis

        network_idle_reached = False
        try:
            idle_timeout = deadline.timeout_ms(ASYNC_CONFIG['network_idle_timeout'], "main navigation network idle") if deadline else ASYNC_CONFIG['network_idle_timeout']
            page.wait_for_load_state('networkidle', timeout=idle_timeout)
            network_idle_reached = True
        except Exception:
            if deadline is not None:
                deadline.check("main navigation network-idle fallback")
                fallback_ms = deadline.timeout_ms(3000, "main navigation fallback wait")
            else:
                fallback_ms = 3000
            page.wait_for_timeout(fallback_ms)

        analysis['stage_coverage']['navigation'] = 'complete'
        if deadline is not None:
            deadline.check("trusted types detection")
        nav_elapsed = (time.monotonic() - nav_start) * 1000

        analysis['trustedTypes'] = page.evaluate("""
            () => {
                try {
                    if (!window.trustedTypes) return {supported: false, enforced: false};
                    let enforced = false;
                    try { const div = document.createElement('div'); div.innerHTML = '<img src=x>'; }
                    catch(e) { enforced = true; }
                    return {
                        supported: true, enforced,
                        defaultPolicy: trustedTypes.defaultPolicy?.name || null,
                        policies: trustedTypes.getPolicyNames?.() || []
                    };
                } catch(e) { return {supported: false, enforced: false, error: String(e)}; }
            }
        """)

        analysis['stage_coverage']['component_detection'] = 'running'
        async_result = wait_for_custom_elements(
            page,
            timeout_ms=ASYNC_CONFIG['component_poll_timeout'],
            poll_interval_ms=ASYNC_CONFIG['poll_interval'],
            stable_rounds=ASYNC_CONFIG.get('stable_rounds', 3),
            min_observation_ms=(ASYNC_CONFIG['min_observation_ms_idle'] if network_idle_reached
                                else ASYNC_CONFIG['min_observation_ms']),
            deadline=deadline,
        )

        detection_stop_reason = async_result.get('stop_reason', 'probe_error')
        analysis['detection_metadata'].update({
            'async_poll_rounds': async_result.get('poll_rounds', 0),
            'async_elapsed_ms': async_result.get('elapsed_ms', 0),
            'detection_stable': async_result.get('stable', False),
            'detection_stop_reason': detection_stop_reason,
            'detection_stop_reason_detail': async_result.get('stop_reason_detail',
                STOP_REASON_DESCRIPTIONS.get(detection_stop_reason, 'Unknown component-detection stop reason.')),
            'detection_error': async_result.get('error'),
        })
        if detection_stop_reason == 'timeout':
            analysis['stage_coverage']['component_detection'] = 'limited_timeout'
        elif detection_stop_reason in {'max_custom_elements', 'max_shadow_roots'}:
            analysis['stage_coverage']['component_detection'] = 'limited_by_resource_cap'
        elif detection_stop_reason not in {'stable', 'deadline_exceeded'}:
            analysis['stage_coverage']['component_detection'] = 'partial_probe_error'

        if deadline is not None:
            deadline.check("static DOM inspection")
        static = page.evaluate("""
            () => {
                const elements = [];
                const seenTags = new Set();
                const __cm = new Map((window.__closedRoots || []).filter(r => r.host.isConnected).map(r => [r.host, r.root]));
                const visitedRoots = new Set();
                const roots = [document];
                let open_count = 0;
                while (roots.length) {
                    const root = roots.pop();
                    if (!root || visitedRoots.has(root)) continue;
                    visitedRoots.add(root);
                    let descendants = [];
                    try { descendants = root.querySelectorAll('*'); } catch (_) {}
                    descendants.forEach(el => {
                        const tag = el.tagName.toLowerCase();
                        if (!el.shadowRoot && __cm.has(el)) roots.push(__cm.get(el));
                        if (tag.includes('-') && !seenTags.has(tag)) {
                            seenTags.add(tag);
                            elements.push({ tagName: tag, hasShadow: !!el.shadowRoot || __cm.has(el),
                                shadowMode: el.shadowRoot ? el.shadowRoot.mode : (__cm.has(el) ? 'closed' : 'none') });
                        }
                        if (el.shadowRoot && el.shadowRoot.mode === 'open') {
                            open_count++;
                            roots.push(el.shadowRoot);
                        }
                    });
                }
                const DANGEROUS_NAMES = ['config','state','user','auth','token','redirectTo'];
                const clobbered = [];
                for (const k of DANGEROUS_NAMES) {
                    try {
                        const v = window[k];
                        if (v instanceof HTMLElement || v instanceof HTMLCollection)
                            clobbered.push({ name: k, type: v.constructor?.name || typeof v });
                    } catch(e) {}
                }
                const hooked = window.__shadowLog || [];
                return { elements, open_count,
                    closed_count: hooked.filter(r => r.mode === 'closed').length,
                    hookedAll: hooked, dom_clobbering: clobbered };
            }
        """)

        analysis['customElements'] = static.get('elements', [])
        analysis['attachShadowCalls'] = static.get('hookedAll', [])
        analysis['domClobbering'] = static.get('dom_clobbering', [])
        analysis['shadowRoots'] = {
            'open': max(static.get('open_count', 0), async_result['shadow_roots']['open']),
            'closed': max(static.get('closed_count', 0), async_result['shadow_roots']['closed']),
        }
        if detection_stop_reason == 'stable' and not async_result.get('error'):
            analysis['stage_coverage']['component_detection'] = 'complete'
        elif async_result.get('error'):
            analysis['stage_coverage']['component_detection'] = 'partial_probe_error'

        for tag in async_result['custom_elements']:
            if not any(c.get('tagName') == tag for c in analysis['customElements']):
                analysis['customElements'].append({
                    'tagName': tag, 'hasShadow': False,
                    'shadowMode': 'none', 'found_async': True,
                })

        if deadline is not None:
            deadline.check("prototype-pollution probe")
        analysis['stage_coverage']['prototype_pollution'] = 'running'
        pp_page = context.new_page()
        try:
            if PP_WORKERS > 1:
                analysis['protoPollution'] = test_prototype_pollution_parallel(
                    url, allowed_hosts, allow_local_test=allow_local_test,
                    deadline=deadline, workers=PP_WORKERS)
            else:
                analysis['protoPollution'] = test_prototype_pollution_app(pp_page, url, deadline=deadline)
        except ScanDeadlineExceeded:
            analysis['protoPollution'] = {'vulnerable': False, 'payload': None,
                                          'skipped': True, 'stop_reason': 'deadline_exceeded'}
        except Exception as e:
            log.debug(f"PP test failed: {e}")
        finally:
            try:
                pp_page.close()
            except Exception:
                pass
        pp_result = analysis.get('protoPollution', {})
        pp_reason = pp_result.get('stop_reason', 'probe_error')
        if pp_reason == 'deadline_exceeded':
            analysis['stage_coverage']['prototype_pollution'] = 'incomplete_deadline'
        elif pp_reason == 'probe_errors':
            analysis['stage_coverage']['prototype_pollution'] = 'partial_probe_errors'
        elif pp_reason == 'finding_observed':
            analysis['stage_coverage']['prototype_pollution'] = 'complete_with_finding'
        elif pp_reason == 'completed':
            analysis['stage_coverage']['prototype_pollution'] = 'complete'
        else:
            analysis['stage_coverage']['prototype_pollution'] = 'partial_probe_error'

        if deadline is not None:
            deadline.check("library detection")
        analysis['stage_coverage']['library_detection'] = 'running'
        analysis['libraryFindings'] = detect_libraries_on_page(page, deadline=deadline)
        analysis['stage_coverage']['library_detection'] = 'complete'
        analysis['detection_metadata'] = {
            'navigation_ms': nav_elapsed, 'network_idle_reached': network_idle_reached,
            'async_poll_rounds': async_result['poll_rounds'],
            'async_elapsed_ms': async_result['elapsed_ms'],
            'detection_stable': async_result['stable'],
            'detection_stop_reason': async_result.get('stop_reason', 'unknown'),
            'detection_stop_reason_detail': async_result.get('stop_reason_detail',
                STOP_REASON_DESCRIPTIONS.get(async_result.get('stop_reason'), 'Unknown component-detection stop reason.')),
            'detection_error': async_result.get('error'),
            'trusted_types_supported': analysis['trustedTypes'].get('supported', False),
            'trusted_types_enforced': analysis['trustedTypes'].get('enforced', False),
            'csp_present': bool(analysis.get('csp')),
            'proto_pollution_stop_reason': pp_reason,
            'proto_pollution_stop_reason_detail': pp_result.get('stop_reason_detail',
                STOP_REASON_DESCRIPTIONS.get(pp_reason, 'Unknown prototype-pollution stop reason.')),
            'proto_pollution_coverage': pp_result.get('coverage', {}),
        }
        partial_stage_prefixes = ('limited_', 'partial_', 'incomplete_', 'skipped_')
        has_partial_stage = any(
            status.startswith(partial_stage_prefixes)
            for status in analysis['stage_coverage'].values()
        )
        analysis['scan_status'] = 'partial' if has_partial_stage else 'complete'
        if pp_reason == 'probe_errors':
            analysis['scan_stop_reason'] = 'probe_errors'
        elif has_partial_stage:
            analysis['scan_stop_reason'] = 'partial_coverage'
        else:
            analysis['scan_stop_reason'] = 'completed'

    except ScanDeadlineExceeded as e:
        log.info("Scan deadline reached for %s: %s", url, e)
        for stage, stage_status in list(analysis['stage_coverage'].items()):
            if stage_status == 'running':
                analysis['stage_coverage'][stage] = 'incomplete_deadline'
            elif stage_status == 'not_started':
                analysis['stage_coverage'][stage] = 'skipped_deadline'
        analysis['scan_status'] = 'partial'
        analysis['scan_stop_reason'] = 'deadline_exceeded'
        analysis['scan_timeout_detail'] = str(e)
    except Exception as e:
        if deadline is not None and deadline.expired():
            log.info("Scan deadline reached for %s during analysis: %s", url, e)
            for stage, stage_status in list(analysis['stage_coverage'].items()):
                if stage_status == 'running':
                    analysis['stage_coverage'][stage] = 'incomplete_deadline'
                elif stage_status == 'not_started':
                    analysis['stage_coverage'][stage] = 'skipped_deadline'
            analysis['scan_status'] = 'partial'
            analysis['scan_stop_reason'] = 'deadline_exceeded'
            analysis['scan_timeout_detail'] = str(e)
        else:
            log.error(f"analyze_page failed for {url}: {e}")
            analysis['error'] = str(e)
            for stage, stage_status in list(analysis['stage_coverage'].items()):
                if stage_status == 'running':
                    analysis['stage_coverage'][stage] = 'failed'
                elif stage_status == 'not_started':
                    analysis['stage_coverage'][stage] = 'skipped_after_error'
            analysis['scan_status'] = 'failed'
            analysis['scan_stop_reason'] = 'analysis_error'
    finally:
        try:
            page.close()
        except Exception:
            pass

    return analysis


# ---------------------------------------------------------------------------
# Canary reflection scanner with context classification
# ---------------------------------------------------------------------------

def _url_with_canary_parameter(url: str, canary: str) -> str:
    """Add/replace the q parameter while preserving existing query and fragment."""
    parts = urlsplit(url)
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True)
             if key != "q"]
    query.append(("q", canary))
    fragment = canary if not parts.fragment else f"{parts.fragment}&{canary}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), fragment))


def _classify_canary_observations(hits: list[dict], was_redirected: bool = False) -> dict:
    """Classify observations without treating reflection or sink flow as proof of execution."""
    self_contexts = {"localStorage", "sessionStorage", "cookie", "window_name"}
    filtered = list(hits or [])
    if was_redirected:
        # A script block on a different destination may be unrelated to the
        # injected URL. Preserve other observations rather than suppressing all hits.
        filtered = [hit for hit in filtered if hit.get("context") != "script_block"]

    # Storage-only hits are not reflection. Keep storage evidence when it is
    # accompanied by an actual page-context or sink observation.
    if filtered and all(hit.get("context") in self_contexts for hit in filtered):
        filtered = []

    seen = set()
    deduped = []
    for hit in filtered:
        key = (hit.get("context"), hit.get("parent"), hit.get("attr"), hit.get("element"),
               hit.get("risk"), hit.get("sink"), hit.get("category"), hit.get("value"), hit.get("stack"),
               hit.get("parent_id"), hit.get("parent_class"), hit.get("target"))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(hit)

    contexts = sorted({str(hit.get("context", "unknown")) for hit in deduped})
    executable_context = any(
        hit.get("risk") == "event_handler" or hit.get("context") == "script_block"
        for hit in deduped
    )
    sink_flow = any(
        str(hit.get("context", "")).startswith("sink_")
        and hit.get("category") in {"code_exec", "html_injection"}
        for hit in deduped
    )

    if executable_context:
        status = "potential"
        assessment = "potential_executable_context_observed"
    elif sink_flow:
        status = "observed_sink_flow"
        assessment = "dangerous_sink_data_flow_observed"
    else:
        status = "observed_reflection"
        assessment = "reflection_only_not_confirmed_xss"

    return {
        "hits": deduped,
        "contexts": contexts,
        "status": status,
        "assessment": assessment,
        "executable_context_observed": executable_context,
        "sink_flow_observed": sink_flow,
    }


def trigger_interactions(page, deadline: ScanDeadline | None = None, max_elements: int = 8,
                         event_types=("click", "mouseenter", "mouseover"),
                         per_action_timeout_ms: int = 2500) -> dict:
    """Fire a small, bounded set of real interactions (click/hover) on elements
    that have a listener for one of event_types, or a matching on<type> DOM
    property (covers inline on* attribute handlers). A sink call inside a
    click/hover handler never runs during passive navigation and is otherwise
    invisible to this scanner (see SWIPE/DOMsday fuzzing research). This is
    not a general fuzzer: bounded element count, short per-action timeout,
    best-effort, and never allowed to fail the overall scan. Caller gates
    this behind an explicit opt-in (see INTERACTION_ENABLED) because real
    clicks on a live third-party target can have real side effects."""
    result = {"candidates_tagged": 0, "triggered": [], "skipped": [], "navigated_away": False}
    tag_js = """
        ([types, maxCount]) => {
            let n = 0;
            const seen = new Set();
            for (const type of types) {
                if (n >= maxCount) break;
                const propName = 'on' + type;
                const nodes = document.querySelectorAll('*');
                for (const el of nodes) {
                    if (n >= maxCount) break;
                    if (seen.has(el)) continue;
                    const hasProp = typeof el[propName] !== 'undefined' && el[propName] !== null;
                    const hasListener = window.__listenersByType && window.__listenersByType[type] &&
                                         window.__listenersByType[type].has(el);
                    if (hasProp || hasListener) {
                        seen.add(el);
                        el.setAttribute('data-dpk-interact', type);
                        n++;
                    }
                }
            }
            return n;
        }
    """
    try:
        if deadline is not None:
            deadline.check("interaction tagging")
        result["candidates_tagged"] = page.evaluate(tag_js, [list(event_types), max_elements])
    except Exception as e:
        result["error"] = f"tagging_failed: {e}"
        return result
    if not result["candidates_tagged"]:
        return result
    try:
        handles = page.query_selector_all('[data-dpk-interact]')
    except Exception as e:
        result["error"] = f"query_failed: {e}"
        return result
    start_url = page.url
    for handle in handles:
        if deadline is not None and deadline.expired():
            result["skipped"].append({"reason": "deadline_exceeded"})
            break
        if page.url != start_url:
            result["navigated_away"] = True
            break
        try:
            etype = handle.get_attribute("data-dpk-interact") or "click"
        except Exception:
            continue
        try:
            if etype in ("mouseenter", "mouseover"):
                handle.hover(timeout=per_action_timeout_ms)
            else:
                handle.click(timeout=per_action_timeout_ms)
            result["triggered"].append(etype)
        except Exception as e:
            result["skipped"].append({"type": etype, "reason": str(e)[:150]})
    try:
        page.evaluate("document.querySelectorAll('[data-dpk-interact]').forEach(el => el.removeAttribute('data-dpk-interact'))")
    except Exception:
        pass
    return result


def test_canary_reflection(url: str, context, retries: int = None, deadline: ScanDeadline | None = None) -> tuple[list, dict]:
    canary = f"CANARY_{uuid.uuid4().hex[:8]}"
    findings = []
    coverage = {'attempted': [], 'completed': [], 'failed': [], 'skipped': [], 'stop_reason': 'running'}
    if retries is None:
        retries = CANARY_CONFIG["retry_count"]

    sources = [
        ("url_param",      True,  _url_with_canary_parameter(url, canary), False),
        ("localStorage",   False, f"localStorage.setItem('canary', '{canary}')",   True),
        ("sessionStorage", False, f"sessionStorage.setItem('canary', '{canary}')", True),
        ("cookie",         False, f"document.cookie = 'canary={canary}'",          True),
        ("window_name",    False, f"window.name = '{canary}'",                     True),
    ]


    for source_index, (source_name, is_url_nav, injection, needs_reload) in enumerate(sources):
        if deadline is not None and deadline.expired():
            coverage['skipped'].extend(
                {'source': remaining[0], 'reason': 'deadline_exceeded'}
                for remaining in sources[source_index:]
            )
            break
        coverage['attempted'].append(source_name)
        try:
            context.clear_cookies()
        except Exception:
            pass
        page = context.new_page()
        attempt = 0
        try:
            while True:
                if deadline is not None:
                    deadline.check(f"canary source {source_name}")
                attempt += 1
                try:
                    page.add_init_script(f"window.__canary = '{canary}';")
                    nav_timeout = deadline.timeout_ms(NAV_TIMEOUT, f"canary navigation ({source_name})") if deadline else NAV_TIMEOUT
                    if is_url_nav:
                        page.goto(injection, timeout=nav_timeout, wait_until='domcontentloaded')
                    else:
                        page.goto(url, timeout=nav_timeout, wait_until='domcontentloaded')
                        if deadline is not None:
                            deadline.check(f"canary injection ({source_name})")
                        page.evaluate("try { localStorage.clear(); sessionStorage.clear(); } catch (e) {}")
                        page.evaluate(injection)
                        if needs_reload:
                            reload_timeout = deadline.timeout_ms(NAV_TIMEOUT, f"canary reload ({source_name})") if deadline else NAV_TIMEOUT
                            page.reload(timeout=reload_timeout, wait_until='domcontentloaded')
                    if deadline is not None:
                        deadline.check(f"canary navigation ({source_name})")
                    break
                except ScanDeadlineExceeded:
                    raise
                except Exception as e:
                    if deadline is not None and deadline.expired():
                        raise ScanDeadlineExceeded(f"scan_timeout: deadline exceeded during canary source {source_name}") from e
                    if attempt > retries:
                        raise
                    log.debug(f"[{source_name}] attempt {attempt} failed, retrying: {e}")
                    pause = min(0.5, deadline.remaining_seconds()) if deadline else 0.5
                    if pause > 0:
                        time.sleep(pause)

            nav_target = injection if is_url_nav else url
            base_target = nav_target.split('?')[0].split('#')[0]
            base_current = page.url.split('?')[0].split('#')[0]
            was_redirected = (base_current != base_target)

            try:
                idle_timeout = deadline.timeout_ms(CANARY_CONFIG['network_idle_timeout'], f"canary network idle ({source_name})") if deadline else CANARY_CONFIG['network_idle_timeout']
                page.wait_for_load_state('networkidle', timeout=idle_timeout)
            except Exception:
                if deadline is not None:
                    deadline.check(f"canary network-idle fallback ({source_name})")
                    fallback_ms = deadline.timeout_ms(1500, f"canary fallback wait ({source_name})")
                else:
                    fallback_ms = 1500
                page.wait_for_timeout(fallback_ms)

            interaction_result = None
            if source_name == "url_param" and INTERACTION_ENABLED:
                try:
                    interaction_result = trigger_interactions(page, deadline=deadline)
                except Exception as e:
                    interaction_result = {"error": str(e)[:200]}
                coverage.setdefault('interaction', {})[source_name] = interaction_result

            if deadline is not None:
                deadline.check(f"canary classification ({source_name})")
            classify_js = (CLASSIFY_JS_TEMPLATE
                           .replace('__CANARY__', canary)
                           .replace('__MAX_WALK__', str(MAX_WALK_NODES)))
            if page.evaluate("typeof window.__sinkHits === 'undefined'"):
                raise RuntimeError("probe_error: instrumentation not installed (window.__sinkHits missing)")
            hits = page.evaluate(classify_js)
            if deadline is not None:
                deadline.check(f"canary classification ({source_name})")
            coverage['completed'].append(source_name)

            classification = _classify_canary_observations(hits, was_redirected=was_redirected)
            deduped = classification['hits']
            contexts = classification['contexts']

            if deduped:
                evidence = [f"The scanner's canary value was observed in: {', '.join(contexts)}."]
                if classification['executable_context_observed']:
                    evidence.append("A script-block or event-handler context was observed; this does not establish that the canary executed.")
                elif classification['sink_flow_observed']:
                    evidence.append("The canary was present in a recorded HTML/code-execution sink value; the record shows data flow, not successful execution or exploitability.")
                else:
                    evidence.append("The observations show reflection or propagation, but do not establish an executable injection context.")

                findings.append({
                    'type': 'canary_reflection',
                    'status': classification['status'],
                    'source': source_name,
                    'canary': canary,
                    'hits': deduped,
                    'sink': '', 'element': '',
                    'assessment': classification['assessment'],
                    'exploitability_confirmed': False,
                    'evidence': evidence,
                    'sample': {
                        'source': source_name,
                        'canary_value': canary,
                        'observed_contexts': contexts,
                        'observations': deduped,
                        'executable_context_observed': classification['executable_context_observed'],
                        'sink_flow_observed': classification['sink_flow_observed'],
                        'interaction': interaction_result,
                    },
                    'limitations': [
                        "Reflection of a canary is not, by itself, proof of cross-site scripting.",
                        "A sink record establishes that the canary appeared in the recorded value; it does not prove the browser executed attacker-controlled code.",
                        "Script-block and event-handler observations are context indicators, not proof that the observed value is syntactically executable or that a user can control it.",
                        "Storage-only occurrences are not reported as reflection findings; cross-origin frames, roots attached before instrumentation, and unobserved execution paths may limit coverage.",
                    ] + ([
                        "This canary was also injected into the URL fragment; modern Chromium percent-encodes special characters there by default (older browsers did not), so a payload containing brackets, quotes, or angle brackets may not reach the page unescaped even though this alphanumeric canary did.",
                    ] if source_name == "url_param" else []),
                })

        except ScanDeadlineExceeded as e:
            coverage['failed'].append({'source': source_name, 'reason': 'deadline_exceeded', 'error': str(e)})
            coverage['skipped'].extend(
                {'source': remaining[0], 'reason': 'deadline_exceeded'}
                for remaining in sources[source_index + 1:]
            )
            coverage['stop_reason'] = 'deadline_exceeded'
            log.info("Canary source %s stopped by scan deadline", source_name)
            break
        except Exception as e:
            reason = _exception_stop_reason(e)
            coverage['failed'].append({'source': source_name, 'reason': reason, 'error': str(e)})
            log.warning("Canary source %s failed: %s", source_name, e)
            if deadline is not None and deadline.expired():
                coverage['skipped'].extend(
                    {'source': remaining[0], 'reason': 'deadline_exceeded'}
                    for remaining in sources[source_index + 1:]
                )
                coverage['stop_reason'] = 'deadline_exceeded'
                break
        finally:
            try:
                page.close()
            except Exception:
                pass

        if deadline is None or not deadline.expired():
            try:
                cleanup = context.new_page()
                cleanup.evaluate("delete window.__canary")
                cleanup.close()
            except Exception:
                pass

    if coverage['stop_reason'] == 'running':
        coverage['stop_reason'] = 'probe_errors' if coverage['failed'] else (
            'partial_coverage' if coverage['skipped'] else 'completed'
        )
    coverage['partial'] = bool(coverage['failed'] or coverage['skipped'])
    coverage['stop_reason_detail'] = STOP_REASON_DESCRIPTIONS.get(
        coverage['stop_reason'], 'The stage stopped before all checks completed.'
    )
    return findings, coverage


# ---------------------------------------------------------------------------
# Finding assembly
# ---------------------------------------------------------------------------

def assemble_findings(analysis: dict, canary_findings: list) -> list:
    findings = []

    if analysis.get('protoPollution', {}).get('vulnerable'):
        pp = analysis['protoPollution']
        locations = pp.get('locations', [])
        findings.append({
            'type': 'prototype_pollution',
            'status': 'observed_prototype_pollution',
            'payload': pp.get('payload'),
            'vector': pp.get('vector', 'url_param'),
            'sink': '', 'element': '', 'source': 'url_param_injection',
            'evidence': [
                "The injected marker was observed on a JavaScript prototype during the test.",
                (f"Affected prototype locations: {', '.join(locations)}." if locations
                 else "The test recorded a prototype-pollution signal; inspect the sample and probe coverage for details."),
            ],
            'sample': {
                'payload': pp.get('payload'),
                'vector': pp.get('vector', 'url_param'),
                'prototype_locations': locations,
                'observed_value': pp.get('value'),
                'vulnerable_vectors': pp.get('vulnerable_vectors'),
            },
            'limitations': [
                "This demonstrates the observed behavior for the tested payload and page state; it does not by itself establish the broader impact or exploitability of the application.",
                "Only the vectors listed in the probe coverage were tested; skipped or failed vectors remain unverified.",
            ],
        })

    # Sink instrumentation records only values containing an active canary.
    # analyze_page() does not inject a canary, so its sinkHits list is not a
    # general sink-activity signal and must not be reported as a finding.

    findings.extend(canary_findings)
    findings.extend(analysis.get('libraryFindings', []))
    return findings


def finding_hash(url: str, finding: dict) -> str:
    key = "|".join([
        url, finding.get('type', 'unknown'), finding.get('sink', ''),
        finding.get('element', ''), finding.get('source', ''),
        re.sub(r"__pp_[0-9a-f]{8}__", "__pp__", str(finding.get('payload', '')))[:40],
    ])
    if finding.get('library'):
        key += f"|{finding['library']}|{finding.get('cve', '')}"
    return hashlib.sha256(key.encode()).hexdigest()


def normalize_finding(finding: dict) -> dict:
    """Apply the stable v1 common finding shape without discarding type-specific evidence."""
    item = dict(finding or {})
    item.setdefault("type", "unknown")
    item.setdefault("status", "observed")
    item.setdefault("source", "unknown")
    item.setdefault("sink", "")
    item.setdefault("element", "")
    item.setdefault("evidence", [])
    item.setdefault("sample", {})
    item.setdefault("limitations", [])

    # Enforce common JSON types so downstream consumers do not need per-finding
    # special cases. Preserve existing scalar evidence as a one-item list.
    for key in ("evidence", "limitations"):
        value = item.get(key)
        if value is None:
            item[key] = []
        elif isinstance(value, str):
            item[key] = [value]
        elif not isinstance(value, list):
            item[key] = [str(value)]
    if not isinstance(item.get("sample"), dict):
        item["sample"] = {"value": item["sample"]} if item["sample"] is not None else {}

    # v1 intentionally has no score-based or recommendation fields.
    for deprecated in ("confidence", "severity", "weight", "recommendation", "recommendations"):
        item.pop(deprecated, None)
    return item


def normalize_scan_result(result: dict) -> dict:
    """Normalize all CLI result paths (complete, partial, blocked, and failed)."""
    item = dict(result or {})
    item.setdefault("url", "")
    item.setdefault("error", None)
    item.setdefault("scanned_at", datetime.now(timezone.utc).isoformat())
    item.setdefault("scan_status", "failed")
    item.setdefault("scan_stop_reason", "analysis_error")
    item.setdefault("scan_stop_reason_detail", STOP_REASON_DESCRIPTIONS.get(
        item["scan_stop_reason"], "The scan stopped before all checks completed."))
    item.setdefault("scan_timeout_seconds", DEFAULT_SCAN_TIMEOUT_SECONDS)
    item.setdefault("scan_elapsed_seconds", 0.0)
    item.setdefault("scan_timeout_detail", None)
    item.setdefault("custom_elements", [])
    item.setdefault("shadow_roots", {"open": 0, "closed": 0})
    item.setdefault("trusted_types", {})
    item.setdefault("security_headers", {})
    item.setdefault("response_metadata", {})
    item.setdefault("csp_present", False)
    item.setdefault("detection_metadata", {})

    coverage = item.get("coverage")
    if not isinstance(coverage, dict):
        coverage = {}
    # Older early-return paths used coverage as a stage map directly.
    if "stages" not in coverage:
        coverage = {"stages": coverage}
    coverage.setdefault("stages", {})
    coverage.setdefault("canary_sources", {
        "attempted": [], "completed": [], "failed": [], "skipped": [],
        "stop_reason": "not_run", "partial": item.get("scan_status") != "complete",
        "stop_reason_detail": "Canary checks were not run on this scan path.",
    })
    coverage.setdefault("partial", item.get("scan_status") != "complete")
    item["coverage"] = coverage

    http_status = (item.get("response_metadata") or {}).get("status")
    error_status = isinstance(http_status, int) and http_status >= 400
    notes = list(item.get("scan_notes") or [])
    item.setdefault("page_errors", [])
    if item["page_errors"]:
        notes.append(f"page_script_errors: {len(item['page_errors'])} uncaught error(s) during load; component and sink coverage may be incomplete")
    if error_status:
        notes.append(f"target_returned_http_{http_status}: results describe an error page, not the application's normal content")
    final_url = (item.get("response_metadata") or {}).get("final_url")
    if final_url and final_url.split("#")[0].rstrip("/") != (item.get("url") or "").split("#")[0].rstrip("/"):
        notes.append(f"redirected_to: {final_url}")
    item["target_http_status"] = http_status
    item["target_error_status"] = error_status
    item["scan_notes"] = notes
    normalized_findings = []
    for finding in item.get("findings", []) or []:
        normalized = normalize_finding(finding)
        if error_status:
            normalized["limitations"].append(
                f"The target responded with HTTP {http_status}; this finding comes from an error page and may not reflect the real application.")
        normalized.setdefault("finding_hash", finding_hash(item["url"], normalized))
        normalized_findings.append(normalized)
    item["findings"] = normalized_findings
    item["scanner_version"] = SCANNER_VERSION
    item["schema_version"] = OUTPUT_SCHEMA_VERSION
    return item


# ---------------------------------------------------------------------------
# Per-URL orchestration with simple retry
# ---------------------------------------------------------------------------

def scan_one(url: str, browser, max_retries: int,
             extra_allowed_hosts: set[str] | None = None,
             allow_local_test: bool = False,
             scan_timeout_s: float = DEFAULT_SCAN_TIMEOUT_SECONDS,
             scope_mode: str = "allow",
             scope_domain: str | None = None) -> dict:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    target_host = (urlsplit(url).hostname or "").rstrip(".").lower()
    if scope_mode == "all":
        allowed_hosts = None
    elif scope_mode == "domain":
        allowed_hosts = {scope_domain} if scope_domain else set()
    else:
        # Strict-by-default: target domain plus explicitly allowed domains.
        allowed_hosts = {target_host} if target_host else set()
        allowed_hosts.update(extra_allowed_hosts or set())
    deadline = ScanDeadline(scan_timeout_s)
    canary_sources = ("url_param", "localStorage", "sessionStorage", "cookie", "window_name")

    def partial_timeout_result(analysis: dict | None = None) -> dict:
        analysis = analysis or {}
        skipped = [{'source': source, 'reason': 'deadline_exceeded'} for source in canary_sources]
        stages = dict(analysis.get('stage_coverage', {
            "target_validation": "not_started", "navigation": "not_started",
            "component_detection": "not_started", "prototype_pollution": "not_started",
            "library_detection": "not_started",
        }))
        for stage, status in list(stages.items()):
            if status == "not_started":
                stages[stage] = "skipped_deadline"
            elif status == "running":
                stages[stage] = "incomplete_deadline"
        return {
            "url": url,
            "error": None,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scan_status": "partial",
            "scan_stop_reason": "deadline_exceeded",
            "scan_stop_reason_detail": STOP_REASON_DESCRIPTIONS["deadline_exceeded"],
            "scan_timeout_seconds": scan_timeout_s,
            "scan_elapsed_seconds": round(time.monotonic() - deadline.started_at, 3),
            "scan_timeout_detail": "Total per-target scan deadline exceeded; remaining stages were skipped.",
            "custom_elements": analysis.get("customElements", []),
            "shadow_roots": analysis.get("shadowRoots", {"open": 0, "closed": 0}),
            "trusted_types": analysis.get("trustedTypes", {}),
            "security_headers": analysis.get("security_headers", {}),
            "response_metadata": analysis.get("response_metadata", {}),
            "csp_present": bool(analysis.get("csp")),
            "detection_metadata": analysis.get("detection_metadata", {}),
            "page_errors": list(analysis.get("page_errors", [])),
            "coverage": {
                "stages": stages,
                "canary_sources": {
                    "attempted": [], "completed": [], "failed": [], "skipped": skipped,
                    "stop_reason": "deadline_exceeded", "partial": True,
                    "stop_reason_detail": STOP_REASON_DESCRIPTIONS["deadline_exceeded"],
                },
                "partial": True,
            },
            "findings": assemble_findings(analysis, []),
        }

    attempt = 0
    last_analysis: dict | None = None
    while True:
        if deadline.expired():
            return partial_timeout_result(last_analysis)
        attempt += 1
        context = make_context(
            browser, allowed_hosts, allow_local_test=allow_local_test, deadline=deadline
        )
        try:
            analysis = analyze_page(
                url, context, allowed_hosts,
                allow_local_test=allow_local_test, deadline=deadline,
            )
            last_analysis = analysis
            err = analysis.get('error')
            if err:
                if err.startswith(("blocked:", "waf:")):
                    return {
                        "url": url, "error": err, "findings": [],
                        "scan_status": "blocked", "scan_stop_reason": (
                            "blocked_by_waf" if err.startswith("waf:") else "blocked_by_policy"
                        ),
                        "scan_stop_reason_detail": STOP_REASON_DESCRIPTIONS.get(
                            "blocked_by_waf" if err.startswith("waf:") else "blocked_by_policy"
                        ),
                        "scan_timeout_seconds": scan_timeout_s,
                        "scan_elapsed_seconds": round(time.monotonic() - deadline.started_at, 3),
                        "coverage": {"stages": analysis.get("stage_coverage", {}), "partial": False},
                    }
                if deadline.expired():
                    return partial_timeout_result(analysis)
                if attempt <= max_retries:
                    log.warning(f"{url}: transient error '{err}', retrying ({attempt}/{max_retries})")
                    continue
                return {
                    "url": url, "error": err, "findings": [],
                    "scan_status": "failed", "scan_stop_reason": "analysis_error",
                    "scan_stop_reason_detail": STOP_REASON_DESCRIPTIONS["analysis_error"],
                    "scan_timeout_seconds": scan_timeout_s,
                    "scan_elapsed_seconds": round(time.monotonic() - deadline.started_at, 3),
                    "coverage": {"stages": analysis.get("stage_coverage", {}), "partial": True},
                }

            analysis_status = analysis.get("scan_status", "complete")
            if deadline.expired() or analysis.get("scan_stop_reason") == "deadline_exceeded":
                skip_reason = "deadline_exceeded"
                canary_findings = []
                canary_coverage = {
                    "attempted": [], "completed": [], "failed": [],
                    "skipped": [{'source': source, 'reason': skip_reason} for source in canary_sources],
                    "stop_reason": skip_reason, "partial": True,
                    "stop_reason_detail": STOP_REASON_DESCRIPTIONS[skip_reason],
                }
            elif analysis_status in {"blocked", "failed"}:
                skip_reason = analysis.get("scan_stop_reason") or "analysis_error"
                canary_findings = []
                canary_coverage = {
                    "attempted": [], "completed": [], "failed": [],
                    "skipped": [{'source': source, 'reason': skip_reason} for source in canary_sources],
                    "stop_reason": skip_reason, "partial": True,
                    "stop_reason_detail": STOP_REASON_DESCRIPTIONS.get(skip_reason, skip_reason),
                }
            else:
                canary_findings, canary_coverage = test_canary_reflection(
                    url, context, retries=CANARY_CONFIG['retry_count'], deadline=deadline
                )

            all_findings = assemble_findings(analysis, canary_findings)
            for finding in all_findings:
                finding["finding_hash"] = finding_hash(url, finding)

            timed_out = deadline.expired() or analysis.get("scan_stop_reason") == "deadline_exceeded"
            timeout_detail = analysis.get("scan_timeout_detail")
            if timed_out and not timeout_detail:
                timeout_detail = "Total per-target scan deadline exceeded; remaining stages were skipped."
            partial = (analysis_status != "complete" or bool(canary_coverage.get('failed'))
                       or bool(canary_coverage.get('skipped')) or timed_out)
            if timed_out:
                stop_reason = "deadline_exceeded"
            elif canary_coverage.get('stop_reason') not in (None, 'completed'):
                stop_reason = canary_coverage['stop_reason']
            elif analysis.get("scan_stop_reason") not in (None, "completed"):
                stop_reason = analysis["scan_stop_reason"]
            else:
                stop_reason = "partial_coverage" if partial else "completed"
            return {
                "url": url,
                "error": None,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "scan_status": "partial" if partial else "complete",
                "scan_stop_reason": stop_reason,
                "scan_stop_reason_detail": STOP_REASON_DESCRIPTIONS.get(
                    stop_reason, "The scan stopped before all checks completed."
                ),
                "scan_timeout_seconds": scan_timeout_s,
                "scan_elapsed_seconds": round(time.monotonic() - deadline.started_at, 3),
                "scan_timeout_detail": timeout_detail,
                "custom_elements": analysis.get("customElements", []),
                "shadow_roots": analysis.get("shadowRoots", {}),
                "trusted_types": analysis.get("trustedTypes", {}),
                "security_headers": analysis.get("security_headers", {}),
                "response_metadata": analysis.get("response_metadata", {}),
                "csp_present": bool(analysis.get("csp")),
                "detection_metadata": analysis.get("detection_metadata", {}),
                "page_errors": list(analysis.get("page_errors", [])),
                "coverage": {
                    "stages": analysis.get("stage_coverage", {}),
                    "canary_sources": canary_coverage,
                    "partial": partial,
                },
                "findings": all_findings,
            }
        finally:
            try:
                context.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _read_urls(args) -> list[str]:
    urls: list[str] = list(args.urls)
    if args.input:
        with open(args.input) as f:
            urls.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
    if not urls and not sys.stdin.isatty():
        urls.extend(line.strip() for line in sys.stdin if line.strip() and not line.startswith("#"))
    # de-dupe, preserve order
    seen = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def main():
    global NAV_TIMEOUT, PP_WORKERS, INTERACTION_ENABLED

    parser = argparse.ArgumentParser()
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {SCANNER_VERSION} (output schema {OUTPUT_SCHEMA_VERSION})")
    parser.add_argument("-i", "--input", help="File with one URL per line")
    parser.add_argument("urls", nargs="*", help="One or more target URLs")
    parser.add_argument("-o", "--output", help="Write JSON results here instead of stdout")
    parser.add_argument("--jsonl", action="store_true", help="Write one JSON object per line instead of a JSON array")
    parser.add_argument("--max-retries", type=int, default=WORKER_CONFIG["max_retries"],
                        help="Retries for a target navigation that fails transiently")
    parser.add_argument("--nav-timeout", type=int, default=CANARY_CONFIG["nav_timeout"],
                        help="Per-navigation timeout in milliseconds.")
    parser.add_argument("--scan-timeout", type=float, default=DEFAULT_SCAN_TIMEOUT_SECONDS,
                        help="Maximum total wall-clock seconds spent scanning each target")
    parser.add_argument("--pp-workers", type=int, default=PP_WORKERS,
                        help="Parallel prototype-pollution workers")
    parser.add_argument("--interact", action="store_true",
                        help="Click or Hover a small bounded set of "
                             "elements with click/mouseenter/mouseover listeners")
    parser.add_argument("--canary-retries", type=int, default=CANARY_CONFIG["retry_count"],
                        help="Retries per canary source")
    parser.add_argument("--delay", type=float, default=WORKER_CONFIG["request_delay"], help="Seconds to sleep between URLs")
    parser.add_argument("--scope", choices=("all", "allow", "domain"), default="allow",
                        help="Navigation scope: all=any public domain; allow=target plus --allow-domain entries; domain=only --scope-domain and its subdomains")
    parser.add_argument("--allow-domain", "--allow-host", dest="allow_domain", action="append", default=[], metavar="DOMAIN",
                        help="Additional domain allowed in --scope allow, including its subdomains (repeatable; --allow-host remains as a compatibility alias)")
    parser.add_argument("--scope-domain", metavar="DOMAIN",
                        help="Root domain allowed in --scope domain; its subdomains are included")
    parser.add_argument("--allow-local-test", action="store_true",
                        help="Opt in to scan the local fixture at http://localhost:8000")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--silent", action="store_true",
                        help="Suppress log messages")
    args = parser.parse_args()
    if args.nav_timeout <= 0:
        parser.error("--nav-timeout must be > 0")
    if not math.isfinite(args.scan_timeout) or args.scan_timeout <= 0:
        parser.error("--scan-timeout must be a finite number > 0")
    if args.canary_retries < 0:
        parser.error("--canary-retries must be >= 0")
    if args.max_retries < 0:
        parser.error("--max-retries must be >= 0")
    if args.delay < 0:
        parser.error("--delay must be >= 0")
    if args.pp_workers < 1:
        parser.error("--pp-workers must be >= 1")
    if not args.silent and sys.stderr.isatty():
        print(BANNER.format(ver=SCANNER_VERSION), file=sys.stderr)
    extra_allowed_hosts = set()
    for domain in args.allow_domain:
        normalized = domain.strip().rstrip(".").lower()
        if not normalized or "/" in normalized or "://" in normalized or ":" in normalized or " " in normalized:
            parser.error(f"--allow-domain expects a domain name only, got {domain!r}")
        extra_allowed_hosts.add(normalized)
    normalized_scope_domain = None
    if args.scope_domain:
        normalized_scope_domain = args.scope_domain.strip().rstrip(".").lower()
        if (not normalized_scope_domain or "/" in normalized_scope_domain or
                "://" in normalized_scope_domain or ":" in normalized_scope_domain or
                " " in normalized_scope_domain):
            parser.error("--scope-domain expects a domain name only")
    if args.scope == "domain" and not normalized_scope_domain:
        parser.error("--scope domain requires --scope-domain DOMAIN")
    if args.scope != "domain" and normalized_scope_domain:
        parser.error("--scope-domain can only be used with --scope domain")
    if args.scope != "allow" and extra_allowed_hosts:
        parser.error("--allow-domain can only be used with --scope allow")

    logging.basicConfig(
        level=(logging.CRITICAL + 1) if args.silent else
              (logging.DEBUG if args.verbose else logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    NAV_TIMEOUT = args.nav_timeout
    PP_WORKERS = args.pp_workers
    INTERACTION_ENABLED = args.interact
    CANARY_CONFIG["retry_count"] = args.canary_retries

    urls = _read_urls(args)
    if not urls:
        parser.error("No URLs given (pass as args, --input FILE, or pipe via stdin)")

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        log.error("playwright is not installed. Run: pip install playwright && playwright install chromium")
        sys.exit(1)

    results = []

    with sync_playwright() as pw:
        browser = launch_browser(pw)
        try:
            for i, url in enumerate(urls):
                log.info(f"[{i+1}/{len(urls)}] scanning {url}")
                result = scan_one(url, browser, args.max_retries, extra_allowed_hosts,
                                  allow_local_test=args.allow_local_test,
                                  scan_timeout_s=args.scan_timeout,
                                  scope_mode=args.scope, scope_domain=normalized_scope_domain)
                result = normalize_scan_result(result)
                result["scope_policy"] = {
                    "mode": args.scope,
                    "scope_domain": normalized_scope_domain if args.scope == "domain" else None,
                    "additional_domains": sorted(extra_allowed_hosts) if args.scope == "allow" else [],
                    "ssrf_protection": "always_enabled",
                }
                results.append(result)

                n = len(result.get("findings", []))
                if result.get("error"):
                    log.info(f"  -> error: {result['error']}")
                else:
                    log.info(f"  -> {n} finding(s)")

                if args.jsonl and not args.output:
                    print(json.dumps(result))

                if args.delay:
                    time.sleep(args.delay)
        finally:
            browser.close()

    if args.output:
        out_path = Path(args.output)
        if args.jsonl:
            out_path.write_text("\n".join(json.dumps(r) for r in results) + "\n")
        else:
            out_path.write_text(json.dumps(results, indent=2))
        log.info(f"Wrote results to {out_path}")
    elif not args.jsonl:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()



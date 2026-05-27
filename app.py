from __future__ import annotations

import argparse
import hashlib
import html
import ipaddress
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import tldextract
from playwright.sync_api import sync_playwright, Request, Response, TimeoutError as PWTimeoutError
from rich.console import Console
from rich.table import Table

console = Console()

def ensure_scheme(url: str) -> str:
    p = urlparse(url)
    if not p.scheme:
        return "https://" + url
    return url

def host_of(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""

def safe_slug(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"[^a-z0-9\-_.]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s or "site"

def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

def now_ts() -> int:
    return int(time.time())

def etld1(host: str) -> str:
    ext = tldextract.extract(host)
    if not ext.suffix:
        return host
    return f"{ext.domain}.{ext.suffix}"

def is_local_or_private_host(host: str) -> bool:
    if not host:
        return True
    h = host.lower()
    if h == "localhost":
        return True
    if h.endswith(".local"):
        return True
    try:
        return ipaddress.ip_address(h).is_private
    except ValueError:
        return False

def json_dump(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")

def build_out_path(base_dir: str, url: str) -> Path:
    p = urlparse(url)
    host = p.hostname or "site"
    site = safe_slug(etld1(host))
    ts = now_ts()
    out = Path(base_dir) / site / str(ts)
    out.mkdir(parents=True, exist_ok=True)
    return out

def summarize_console(summary: Dict[str, Any]) -> None:
    table = Table(title="Scan Summary")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for k in [
        "scanned_url",
        "scenario",
        "viewport",
        "final_url",
        "duration_ms",
        "requests_total",
        "responses_total",
        "cookies_before_total",
        "cookies_after_actions_total",
        "script_tags_total",
        "iframe_tags_total",
        "third_party_request_domains",
    ]:
        if k in summary:
            table.add_row(k, str(summary[k]))
    console.print(table)

def registrable(host: str) -> str:
    return etld1(host) if host else ""

def classify_party(site_etld1: str, resource_host: str) -> Tuple[str, str, str]:
    h = (resource_host or "").lstrip(".")
    r = registrable(h)
    party = "third"
    if site_etld1 and r and r == site_etld1:
        party = "first"
    return h, r, party

def cookie_key(c: Dict[str, Any]) -> str:
    return f'{c.get("name")}::{c.get("domain")}::{c.get("path")}'

def diff_cookies(before: List[Dict[str, Any]], after: List[Dict[str, Any]]) -> Dict[str, Any]:
    b = {cookie_key(c): c for c in before}
    a = {cookie_key(c): c for c in after}
    added = [a[k] for k in a.keys() - b.keys()]
    removed = [b[k] for k in b.keys() - a.keys()]
    changed = []

    for k in a.keys() & b.keys():
        fields = ["expires", "secure", "httpOnly", "sameSite", "value"]
        diffs = {}
        for f in fields:
            if a[k].get(f) != b[k].get(f):
                diffs[f] = {"before": b[k].get(f), "after": a[k].get(f)}
        if diffs:
            changed.append({"key": k, "diffs": diffs})

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {"before": len(before), "after": len(after), "added": len(added), "removed": len(removed), "changed": len(changed)}
    }

def top_counts(items: List[str], limit: int = 15) -> List[Tuple[str, int]]:
    return Counter(items).most_common(limit)

def enrich_cookies(cookies: List[Dict[str, Any]], site_etld1: str) -> List[Dict[str, Any]]:
    enriched = []
    for c in cookies:
        dom = (c.get("domain") or "").lstrip(".")
        host_, r_etld1, party = classify_party(site_etld1, dom)
        cc = dict(c)
        cc["domain_host"] = host_
        cc["domain_etld1"] = r_etld1
        cc["party"] = party
        enriched.append(cc)
    return enriched

REJECT_PATTERNS = [
    r"\breject\b", r"\bdecline\b", r"\bdeny\b", r"\bopt[- ]?out\b", r"\bdo not accept\b",
    r"\brefuse\b", r"\bonly necessary\b", r"\bnecessary only\b"
]
ACCEPT_PATTERNS = [
    r"\baccept\b", r"\bagree\b", r"\ballow\b", r"\bok\b", r"\bi understand\b", r"\bgot it\b",
    r"\baccept all\b", r"\ballow all\b"
]

def try_click_consent(page, mode: str, reject_selector: Optional[str], accept_selector: Optional[str]) -> Dict[str, Any]:
    result = {"attempted": True, "mode": mode, "clicked": False, "method": None, "error": None}
    try:
        if mode == "reject" and reject_selector:
            loc = page.locator(reject_selector)
            if loc.count() > 0:
                loc.first.click(timeout=3000)
                result.update({"clicked": True, "method": "selector", "selector": reject_selector})
                return result

        if mode == "accept" and accept_selector:
            loc = page.locator(accept_selector)
            if loc.count() > 0:
                loc.first.click(timeout=3000)
                result.update({"clicked": True, "method": "selector", "selector": accept_selector})
                return result

        patterns = REJECT_PATTERNS if mode == "reject" else ACCEPT_PATTERNS
        regex = re.compile("|".join(patterns), re.I)

        btn = page.get_by_role("button", name=regex)
        if btn.count() > 0:
            btn.first.click(timeout=3000)
            result.update({"clicked": True, "method": "role_button_regex"})
            return result

        candidates = page.locator("button, [role='button'], a, input[type='button'], input[type='submit']")
        n = candidates.count()
        for i in range(min(n, 50)):
            el = candidates.nth(i)
            try:
                txt = (el.inner_text(timeout=200) or "").strip()
            except Exception:
                txt = ""
            if txt and regex.search(txt):
                el.click(timeout=3000)
                result.update({"clicked": True, "method": "text_scan"})
                return result

        result["method"] = "not_found"
        return result
    except Exception as e:
        result["error"] = repr(e)
        return result

def parse_actions(action_args: List[str]) -> List[Tuple[str, Optional[str]]]:
    actions: List[Tuple[str, Optional[str]]] = []
    for a in action_args:
        a = a.strip()
        if not a:
            continue
        if a == "scroll":
            actions.append(("scroll", None))
        elif a.startswith("idle:"):
            actions.append(("idle", a.split(":", 1)[1]))
        elif a.startswith("click:"):
            actions.append(("click", a.split(":", 1)[1]))
        else:
            raise ValueError(f"Unknown action: {a}")
    return actions

def perform_actions(page, actions: List[Tuple[str, Optional[str]]]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for kind, val in actions:
        if kind == "idle":
            ms = int(val or "0")
            page.wait_for_timeout(ms)
            results.append({"action": "idle", "ms": ms, "ok": True})
        elif kind == "click":
            sel = val or ""
            try:
                page.locator(sel).first.click(timeout=5000)
                results.append({"action": "click", "selector": sel, "ok": True})
            except Exception as e:
                results.append({"action": "click", "selector": sel, "ok": False, "error": repr(e)})
        elif kind == "scroll":
            try:
                page.evaluate(
                    """async () => {
                        const sleep = (ms) => new Promise(r => setTimeout(r, ms));
                        const total = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
                        const step = Math.max(200, Math.floor(window.innerHeight * 0.6));
                        let y = 0;
                        while (y < total) {
                            window.scrollTo(0, y);
                            await sleep(200);
                            y += step;
                        }
                        window.scrollTo(0, 0);
                    }"""
                )
                results.append({"action": "scroll", "ok": True})
            except Exception as e:
                results.append({"action": "scroll", "ok": False, "error": repr(e)})
        else:
            results.append({"action": kind, "ok": False, "error": "unknown"})
    return results

@dataclass
class ScanConfig:
    url: str
    out_dir: str
    headless: bool
    timeout_ms: int
    wait_until: str
    settle_ms: int
    max_events: int
    block_media: bool
    user_agent: Optional[str]
    viewport: str
    actions: List[str]
    consent: str
    reject_selector: Optional[str]
    accept_selector: Optional[str]
    report: bool

@dataclass
class _BrowserSession:
    browser: Any
    context: Any
    page: Any
    requests_log: List[Dict[str, Any]]
    responses_log: List[Dict[str, Any]]
    set_cookie_events: List[Dict[str, Any]]
    current_phase: Dict[str, str]

def viewport_settings(kind: str) -> Dict[str, Any]:
    if kind == "mobile":
        return {
            "viewport": {"width": 390, "height": 844},
            "is_mobile": True,
            "has_touch": True,
            "device_scale_factor": 2,
        }
    return {
        "viewport": {"width": 1365, "height": 900},
        "is_mobile": False,
        "has_touch": False,
        "device_scale_factor": 1,
    }

def write_report_md(out_path: Path, summary: Dict[str, Any], domains: Dict[str, Any], cookies_delta: Dict[str, Any]) -> None:
    lines: List[str] = []
    lines.append(f"# Tracking Surface Report\n")
    lines.append(f"- **URL:** {summary.get('scanned_url')}")
    lines.append(f"- **Scenario:** {summary.get('scenario')}")
    lines.append(f"- **Viewport:** {summary.get('viewport')}")
    lines.append(f"- **Timestamp:** {summary.get('timestamp')}")
    lines.append(f"- **Final URL:** {summary.get('final_url')}\n")

    lines.append("## Totals\n")
    lines.append(f"- Requests: **{summary.get('requests_total')}**")
    lines.append(f"- Responses: **{summary.get('responses_total')}**")
    lines.append(f"- Script tags: **{summary.get('script_tags_total')}**")
    lines.append(f"- Iframe tags: **{summary.get('iframe_tags_total')}**")
    lines.append(f"- Cookies (before): **{summary.get('cookies_before_total')}**")
    lines.append(f"- Cookies (after actions): **{summary.get('cookies_after_actions_total')}**\n")

    lines.append("## Cookie Changes\n")
    counts = cookies_delta.get("counts", {})
    lines.append(f"- Added: **{counts.get('added', 0)}**")
    lines.append(f"- Removed: **{counts.get('removed', 0)}**")
    lines.append(f"- Changed: **{counts.get('changed', 0)}**\n")

    tp = domains.get("third_party", {})
    top_tp = tp.get("top_by_requests", [])
    lines.append("## Top Third-Party Domains (by request count)\n")
    if top_tp:
        for d, c in top_tp[:15]:
            lines.append(f"- {d}: {c}")
    else:
        lines.append("- (none detected)")

    lines.append("\n## Artifacts\n")
    art = summary.get("artifacts", {})
    for k, v in art.items():
        lines.append(f"- {k}: `{v}`")

    (out_path / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

def write_report_html(out_path: Path, summary: Dict[str, Any], domains: Dict[str, Any], cookies_delta: Dict[str, Any]) -> None:
    tp = domains.get("third_party", {}).get("top_by_requests", [])
    cookie_counts = cookies_delta.get("counts", {})

    def e(v: Any) -> str:
        return html.escape(str(v)) if v is not None else ""

    rows = "".join(
        f"<tr><td>{e(d)}</td><td style='text-align:right'>{e(c)}</td></tr>"
        for d, c in tp[:20]
    ) or "<tr><td colspan='2'>(none detected)</td></tr>"

    artifact_items = "".join(
        f"<li>{e(k)}: <code>{e(v)}</code></li>"
        for k, v in (summary.get("artifacts") or {}).items()
    )

    html_out = f"""<!doctype html>
                <html>
                <head>
                <meta charset="utf-8"/>
                <title>Tracking Surface Report</title>
                <style>
                    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }}
                    .card {{ border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin-bottom: 16px; }}
                    table {{ border-collapse: collapse; width: 100%; }}
                    td, th {{ border-bottom: 1px solid #eee; padding: 8px; }}
                    th {{ text-align: left; }}
                    code {{ background: #f6f6f6; padding: 2px 6px; border-radius: 6px; }}
                </style>
                </head>
                <body>
                <h1>Tracking Surface Report</h1>

                <div class="card">
                    <div><b>URL:</b> {e(summary.get('scanned_url'))}</div>
                    <div><b>Scenario:</b> {e(summary.get('scenario'))}</div>
                    <div><b>Viewport:</b> {e(summary.get('viewport'))}</div>
                    <div><b>Timestamp:</b> {e(summary.get('timestamp'))}</div>
                    <div><b>Final URL:</b> {e(summary.get('final_url'))}</div>
                </div>

                <div class="card">
                    <h2>Totals</h2>
                    <ul>
                    <li>Requests: <b>{e(summary.get('requests_total'))}</b></li>
                    <li>Responses: <b>{e(summary.get('responses_total'))}</b></li>
                    <li>Script tags: <b>{e(summary.get('script_tags_total'))}</b></li>
                    <li>Iframe tags: <b>{e(summary.get('iframe_tags_total'))}</b></li>
                    <li>Cookies (before): <b>{e(summary.get('cookies_before_total'))}</b></li>
                    <li>Cookies (after actions): <b>{e(summary.get('cookies_after_actions_total'))}</b></li>
                    </ul>
                </div>

                <div class="card">
                    <h2>Cookie Changes</h2>
                    <ul>
                    <li>Added: <b>{e(cookie_counts.get('added', 0))}</b></li>
                    <li>Removed: <b>{e(cookie_counts.get('removed', 0))}</b></li>
                    <li>Changed: <b>{e(cookie_counts.get('changed', 0))}</b></li>
                    </ul>
                </div>

                <div class="card">
                    <h2>Top Third-Party Domains (by request count)</h2>
                    <table>
                    <thead><tr><th>Domain</th><th style="text-align:right">Requests</th></tr></thead>
                    <tbody>{rows}</tbody>
                    </table>
                </div>

                <div class="card">
                    <h2>Artifacts</h2>
                    <ul>{artifact_items}</ul>
                </div>

                <div class="card">
                    <h2>Screenshot</h2>
                    <div><img src="screenshot.png" style="max-width:100%; border:1px solid #eee; border-radius:12px;"></div>
                </div>
                </body>
                </html>
                """
    (out_path / "report.html").write_text(html_out, encoding="utf-8")

def _setup_browser(pw, cfg: ScanConfig, out_path: Path, site_etld1: str) -> _BrowserSession:
    requests_log: List[Dict[str, Any]] = []
    responses_log: List[Dict[str, Any]] = []
    set_cookie_events: List[Dict[str, Any]] = []
    current_phase = {"name": "baseline"}
    event_count = {"n": 0}

    browser = pw.chromium.launch(headless=cfg.headless)

    ctx_kwargs: Dict[str, Any] = {}
    if cfg.user_agent:
        ctx_kwargs["user_agent"] = cfg.user_agent
    ctx_kwargs.update(viewport_settings(cfg.viewport))

    har_path = out_path / "scan.har"
    context = browser.new_context(record_har_path=str(har_path), record_har_content="omit", **ctx_kwargs)

    if cfg.block_media:
        def route_handler(route, request):
            if request.resource_type in ("image", "media", "font"):
                return route.abort()
            return route.continue_()
        context.route("**/*", route_handler)

    page = context.new_page()
    context.tracing.start(screenshots=True, snapshots=True, sources=False)

    def log_request(req: Request) -> None:
        try:
            if event_count["n"] >= cfg.max_events:
                return
            event_count["n"] += 1

            post_data = req.post_data or ""
            try:
                frame_url = req.frame.url if req.frame else None
            except Exception:
                frame_url = None

            redirect_chain = []
            try:
                r = req
                while True:
                    prev = r.redirected_from
                    if not prev:
                        break
                    redirect_chain.append(prev.url)
                    r = prev
                redirect_chain = list(reversed(redirect_chain))
            except Exception:
                redirect_chain = []

            referer = None
            try:
                for k, v in req.headers.items():
                    if k.lower() == "referer":
                        referer = v
                        break
            except Exception:
                pass

            h = host_of(req.url)
            host_, r_etld1, party = classify_party(site_etld1, h)

            requests_log.append({
                "phase": current_phase["name"],
                "ts_ms": int(time.time() * 1000),
                "url": req.url,
                "host": host_,
                "etld1": r_etld1,
                "party": party,
                "method": req.method,
                "resource_type": req.resource_type,
                "is_navigation_request": req.is_navigation_request(),
                "frame_url": frame_url,
                "referer": referer,
                "headers": req.headers,
                "post_data_bytes": len(post_data.encode("utf-8", errors="ignore")) if post_data else 0,
                "redirect_chain": redirect_chain,
            })
        except Exception as ex:
            requests_log.append({
                "phase": current_phase["name"],
                "ts_ms": int(time.time() * 1000),
                "url": getattr(req, "url", None),
                "error": f"log_request_failed: {repr(ex)}",
            })

    def log_response(res: Response) -> None:
        try:
            if event_count["n"] >= cfg.max_events:
                return
            event_count["n"] += 1

            req = res.request
            headers = res.headers

            set_cookie = None
            for k, v in headers.items():
                if k.lower() == "set-cookie":
                    set_cookie = v
                    break
            if set_cookie:
                set_cookie_events.append({
                    "phase": current_phase["name"],
                    "ts_ms": int(time.time() * 1000),
                    "response_url": res.url,
                    "request_url": req.url,
                    "set_cookie": set_cookie,
                })

            try:
                frame_url = req.frame.url if req.frame else None
            except Exception:
                frame_url = None

            content_type = headers.get("content-type") or headers.get("Content-Type")

            h = host_of(res.url)
            host_, r_etld1, party = classify_party(site_etld1, h)

            responses_log.append({
                "phase": current_phase["name"],
                "ts_ms": int(time.time() * 1000),
                "url": res.url,
                "host": host_,
                "etld1": r_etld1,
                "party": party,
                "status": res.status,
                "status_text": res.status_text,
                "request_url": req.url,
                "method": req.method,
                "resource_type": req.resource_type,
                "frame_url": frame_url,
                "headers": headers,
                "content_type": content_type,
            })
        except Exception as ex:
            responses_log.append({
                "phase": current_phase["name"],
                "ts_ms": int(time.time() * 1000),
                "url": getattr(res, "url", None),
                "error": f"log_response_failed: {repr(ex)}",
            })

    page.on("request", log_request)
    page.on("response", log_response)

    return _BrowserSession(
        browser=browser,
        context=context,
        page=page,
        requests_log=requests_log,
        responses_log=responses_log,
        set_cookie_events=set_cookie_events,
        current_phase=current_phase,
    )

def _navigate(page, cfg: ScanConfig) -> Tuple[bool, Optional[str], str]:
    try:
        page.goto(cfg.url, wait_until=cfg.wait_until, timeout=cfg.timeout_ms)
        return True, None, page.url
    except PWTimeoutError as ex:
        return False, f"Timeout: {ex}", page.url
    except Exception as ex:
        return False, f"Error: {ex}", page.url

def _collect_scripts(page, site_etld1: str) -> List[Dict[str, Any]]:
    try:
        scripts = page.evaluate(
            """() => Array.from(document.scripts).map(s => ({
                src: s.src || null,
                inline: !s.src,
                type: s.type || null,
                async: !!s.async,
                defer: !!s.defer,
                nomodule: !!s.noModule,
                textLen: s.text ? s.text.length : 0,
                textSample: (s.text && s.text.length) ? s.text.slice(0, 200) : null
            }))"""
        )
    except Exception:
        return []

    for s in scripts:
        if s.get("inline") and s.get("textSample") is not None:
            s["inline_sha256_sample"] = sha256_text(s.get("textSample") or "")
        if s.get("src"):
            h = host_of(s["src"])
            host_, r_etld1, party = classify_party(site_etld1, h)
            s["host"] = host_
            s["etld1"] = r_etld1
            s["party"] = party
        else:
            s["host"] = None
            s["etld1"] = None
            s["party"] = "first"
    return scripts

def _collect_iframes(page, site_etld1: str) -> List[Dict[str, Any]]:
    try:
        iframes = page.evaluate(
            """() => Array.from(document.querySelectorAll("iframe")).map(f => ({
                src: f.src || null,
                id: f.id || null,
                name: f.name || null,
                title: f.title || null
            }))"""
        )
    except Exception:
        return []

    for fr in iframes:
        if fr.get("src"):
            h = host_of(fr["src"])
            host_, r_etld1, party = classify_party(site_etld1, h)
            fr["host"] = host_
            fr["etld1"] = r_etld1
            fr["party"] = party
        else:
            fr["host"] = None
            fr["etld1"] = None
            fr["party"] = "first"
    return iframes

def _post_nav_collect(
    page,
    context,
    cfg: ScanConfig,
    current_phase: Dict[str, str],
    site_etld1: str,
    screenshot_path: Path,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]]]:
    consent_result: Dict[str, Any] = {"attempted": False}
    if cfg.consent in ("try", "reject", "accept"):
        mode = "accept" if cfg.consent == "accept" else "reject"
        if cfg.consent == "try":
            r1 = try_click_consent(page, "reject", cfg.reject_selector, cfg.accept_selector)
            if not r1.get("clicked"):
                r2 = try_click_consent(page, "accept", cfg.reject_selector, cfg.accept_selector)
                consent_result = {"attempted": True, "sequence": [r1, r2]}
            else:
                consent_result = {"attempted": True, "sequence": [r1]}
        else:
            consent_result = try_click_consent(page, mode, cfg.reject_selector, cfg.accept_selector)
        page.wait_for_timeout(800)

    if cfg.settle_ms > 0:
        try:
            page.wait_for_timeout(cfg.settle_ms)
        except Exception:
            pass

    cookies_after_settle = context.cookies()

    try:
        page.screenshot(path=str(screenshot_path), full_page=True)
    except Exception:
        pass

    scripts = _collect_scripts(page, site_etld1)
    iframes = _collect_iframes(page, site_etld1)

    action_results: List[Dict[str, Any]] = []
    cookies_after_actions = cookies_after_settle
    actions = parse_actions(cfg.actions or [])
    if actions:
        current_phase["name"] = "interaction"
        action_results = perform_actions(page, actions)
        page.wait_for_timeout(800)
        cookies_after_actions = context.cookies()
        try:
            page.screenshot(path=str(screenshot_path), full_page=True)
        except Exception:
            pass

    return cookies_after_settle, cookies_after_actions, scripts, iframes, consent_result, action_results

def _write_scan_artifacts(
    out_path: Path,
    summary: Dict[str, Any],
    requests_log: List[Dict[str, Any]],
    responses_log: List[Dict[str, Any]],
    set_cookie_events: List[Dict[str, Any]],
    cookies_before_e: List[Dict[str, Any]],
    cookies_after_nav_e: List[Dict[str, Any]],
    cookies_after_settle_e: List[Dict[str, Any]],
    cookies_after_actions_e: List[Dict[str, Any]],
    cookie_deltas: Dict[str, Any],
    scripts: List[Dict[str, Any]],
    iframes: List[Dict[str, Any]],
    domains: Dict[str, Any],
    cfg: ScanConfig,
) -> None:
    json_dump(out_path / "summary.json", summary)
    json_dump(out_path / "requests.json", requests_log)
    json_dump(out_path / "responses.json", responses_log)
    json_dump(out_path / "set_cookie_events.json", set_cookie_events)
    json_dump(out_path / "cookies_before.json", cookies_before_e)
    json_dump(out_path / "cookies_after_nav.json", cookies_after_nav_e)
    json_dump(out_path / "cookies_after_settle.json", cookies_after_settle_e)
    json_dump(out_path / "cookies_after_actions.json", cookies_after_actions_e)
    json_dump(out_path / "cookie_deltas.json", cookie_deltas)
    json_dump(out_path / "scripts.json", scripts)
    json_dump(out_path / "iframes.json", iframes)
    json_dump(out_path / "domains.json", domains)

    if cfg.report:
        report_delta = cookie_deltas.get("before_to_after_actions", {})
        write_report_md(out_path, summary, domains, report_delta)
        write_report_html(out_path, summary, domains, report_delta)

def run_single_scan(
    pw,
    cfg: ScanConfig,
    out_path: Path,
    scenario_name: str,
) -> Dict[str, Any]:
    scan_start = time.time()

    scanned_host = host_of(cfg.url)
    site_etld1 = registrable(scanned_host)
    screenshot_path = out_path / "screenshot.png"

    session = _setup_browser(pw, cfg, out_path, site_etld1)

    cookies_before = session.context.cookies()
    nav_ok, nav_error, final_url = _navigate(session.page, cfg)
    cookies_after_nav = session.context.cookies()

    cookies_after_settle, cookies_after_actions, scripts, iframes, consent_result, action_results = (
        _post_nav_collect(
            session.page, session.context, cfg, session.current_phase,
            site_etld1, screenshot_path,
        )
    )

    trace_path = out_path / "trace.zip"
    session.context.tracing.stop(path=str(trace_path))
    session.context.close()
    session.browser.close()

    duration_ms = int((time.time() - scan_start) * 1000)

    cookies_before_e = enrich_cookies(cookies_before, site_etld1)
    cookies_after_nav_e = enrich_cookies(cookies_after_nav, site_etld1)
    cookies_after_settle_e = enrich_cookies(cookies_after_settle, site_etld1)
    cookies_after_actions_e = enrich_cookies(cookies_after_actions, site_etld1)

    cookie_deltas = {
        "before_to_after_nav": diff_cookies(cookies_before_e, cookies_after_nav_e),
        "after_nav_to_after_settle": diff_cookies(cookies_after_nav_e, cookies_after_settle_e),
        "after_settle_to_after_actions": diff_cookies(cookies_after_settle_e, cookies_after_actions_e),
        "before_to_after_actions": diff_cookies(cookies_before_e, cookies_after_actions_e),
    }

    request_etld1s = [r.get("etld1") for r in session.requests_log if r.get("etld1")]
    tp_etld1s = [r.get("etld1") for r in session.requests_log if r.get("party") == "third" and r.get("etld1")]

    top_tp = top_counts(tp_etld1s, limit=25)
    top_all = top_counts([x for x in request_etld1s if x], limit=25)

    domains_data = {
        "site": {"host": scanned_host, "etld1": site_etld1},
        "all": {
            "unique_etld1": sorted(set(x for x in request_etld1s if x)),
            "top_by_requests": top_all,
        },
        "third_party": {
            "unique_etld1": sorted(set(x for x in tp_etld1s if x)),
            "top_by_requests": top_tp,
        }
    }

    summary = {
        "scanned_url": cfg.url,
        "final_url": final_url,
        "nav_ok": nav_ok,
        "nav_error": nav_error,
        "timestamp": now_ts(),
        "duration_ms": duration_ms,
        "scenario": scenario_name,
        "viewport": cfg.viewport,
        "requests_total": len(session.requests_log),
        "responses_total": len(session.responses_log),
        "cookies_before_total": len(cookies_before_e),
        "cookies_after_actions_total": len(cookies_after_actions_e),
        "script_tags_total": len(scripts),
        "iframe_tags_total": len(iframes),
        "third_party_request_domains": len(domains_data["third_party"]["unique_etld1"]),
        "consent_result": consent_result,
        "actions": action_results,
        "artifacts": {
            "requests": "requests.json",
            "responses": "responses.json",
            "cookies_before": "cookies_before.json",
            "cookies_after_nav": "cookies_after_nav.json",
            "cookies_after_settle": "cookies_after_settle.json",
            "cookies_after_actions": "cookies_after_actions.json",
            "cookie_deltas": "cookie_deltas.json",
            "scripts": "scripts.json",
            "iframes": "iframes.json",
            "domains": "domains.json",
            "set_cookie_events": "set_cookie_events.json",
            "summary": "summary.json",
            "screenshot": "screenshot.png",
            "trace": "trace.zip",
            "har": "scan.har",
            "report_md": "report.md",
            "report_html": "report.html",
        },
        "config": asdict(cfg),
    }

    _write_scan_artifacts(
        out_path, summary,
        session.requests_log, session.responses_log, session.set_cookie_events,
        cookies_before_e, cookies_after_nav_e, cookies_after_settle_e, cookies_after_actions_e,
        cookie_deltas, scripts, iframes, domains_data, cfg,
    )

    return summary

def make_scenario_out(out_root: Path, scenario: str, viewport: str) -> Path:
    p = out_root / f"{scenario}_{viewport}"
    p.mkdir(parents=True, exist_ok=True)
    return p

def extract_domain_sets(summary_dir: Path) -> Tuple[set, set]:
    domains = json.loads((summary_dir / "domains.json").read_text(encoding="utf-8"))
    tp = set(domains.get("third_party", {}).get("unique_etld1", []) or [])

    cookies = json.loads((summary_dir / "cookies_after_actions.json").read_text(encoding="utf-8"))
    ck = set(cookie_key(c) for c in cookies)
    return tp, ck

def main():
    ap = argparse.ArgumentParser(description="Comprehensive Playwright tracking surface scanner.")
    ap.add_argument("url", help="URL to scan (https://example.com or example.com)")
    ap.add_argument("--out", default="scans", help="Output directory (default: scans)")
    ap.add_argument("--headed", action="store_true", help="Run headed (not headless)")
    ap.add_argument("--timeout", type=int, default=45000, help="Navigation timeout ms (default: 45000)")
    ap.add_argument("--wait-until", default="networkidle", choices=["load", "domcontentloaded", "networkidle"],
                    help="Playwright wait_until (default: networkidle)")
    ap.add_argument("--settle-ms", type=int, default=2000, help="Extra settle time after navigation (default: 2000)")
    ap.add_argument("--max-events", type=int, default=4000, help="Stop logging after N events (default: 4000)")
    ap.add_argument("--block-media", action="store_true", help="Block images/video/fonts to reduce noise")
    ap.add_argument("--ua", default=None, help="Custom User-Agent string")

    ap.add_argument("--viewport", default="desktop", choices=["desktop", "mobile", "both"],
                    help="Viewport mode (default: desktop)")

    ap.add_argument("--action", action="append", default=[],
                    help="Interaction action(s): scroll | idle:<ms> | click:<css>. Can be repeated.")

    ap.add_argument("--consent", default="none", choices=["none", "try", "reject", "accept", "compare"],
                    help="Consent mode. 'compare' runs baseline/reject/accept (default: none).")
    ap.add_argument("--reject-selector", default=None, help="CSS selector to click Reject (overrides heuristics)")
    ap.add_argument("--accept-selector", default=None, help="CSS selector to click Accept (overrides heuristics)")

    ap.add_argument("--no-report", action="store_true", help="Disable report.md/report.html generation")

    args = ap.parse_args()

    try:
        parse_actions(args.action or [])
    except ValueError as exc:
        ap.error(str(exc))

    url = ensure_scheme(args.url)
    host = host_of(url)
    if is_local_or_private_host(host):
        raise SystemExit(f"Refusing to scan local/private host: {host}")

    out_root = build_out_path(args.out, url)
    console.print(f"[bold]Output root:[/bold] {out_root}")

    viewports = ["desktop", "mobile"] if args.viewport == "both" else [args.viewport]

    base_cfg = {
        "url": url,
        "out_dir": str(out_root),
        "headless": not args.headed,
        "timeout_ms": args.timeout,
        "wait_until": args.wait_until,
        "settle_ms": args.settle_ms,
        "max_events": args.max_events,
        "block_media": args.block_media,
        "user_agent": args.ua,
        "actions": args.action or [],
        "reject_selector": args.reject_selector,
        "accept_selector": args.accept_selector,
        "report": not args.no_report,
    }

    if args.consent == "compare":
        scenarios = [
            ("baseline", "none"),
            ("reject", "reject"),
            ("accept", "accept"),
        ]
    else:
        scenarios = [("single", args.consent)]

    all_run_summaries: List[Dict[str, Any]] = []
    consent_compare_output: Dict[str, Any] = {}

    with sync_playwright() as pw:
        for viewport in viewports:
            scenario_dirs: Dict[str, Path] = {}

            for scenario_name, consent_mode in scenarios:
                scenario_out = make_scenario_out(out_root, scenario_name, viewport)
                scenario_dirs[scenario_name] = scenario_out

                cfg = ScanConfig(
                    **base_cfg,
                    viewport=viewport,
                    consent=consent_mode,
                )
                summary = run_single_scan(pw, cfg, scenario_out, scenario_name)
                summarize_console(summary)
                all_run_summaries.append(summary)

            if args.consent == "compare":
                try:
                    tp_base, ck_base = extract_domain_sets(scenario_dirs["baseline"])
                    tp_rej, ck_rej = extract_domain_sets(scenario_dirs["reject"])
                    tp_acc, ck_acc = extract_domain_sets(scenario_dirs["accept"])

                    consent_compare_output[viewport] = {
                        "third_party_domains": {
                            "baseline": sorted(tp_base),
                            "reject": sorted(tp_rej),
                            "accept": sorted(tp_acc),
                            "reject_minus_baseline": sorted(tp_rej - tp_base),
                            "baseline_minus_reject": sorted(tp_base - tp_rej),
                            "accept_minus_reject": sorted(tp_acc - tp_rej),
                        },
                        "cookies": {
                            "baseline": sorted(ck_base),
                            "reject": sorted(ck_rej),
                            "accept": sorted(ck_acc),
                            "reject_minus_baseline": sorted(ck_rej - ck_base),
                            "baseline_minus_reject": sorted(ck_base - ck_rej),
                            "accept_minus_reject": sorted(ck_acc - ck_rej),
                        }
                    }
                except Exception as ex:
                    consent_compare_output[viewport] = {"error": repr(ex)}

    json_dump(out_root / "runs_summary.json", {"runs": all_run_summaries})

    if args.consent == "compare":
        json_dump(out_root / "consent_comparison.json", consent_compare_output)
        console.print(f"[green]Wrote[/green] {out_root / 'consent_comparison.json'}")

    console.print("[green]Done.[/green]")

if __name__ == "__main__":
    main()

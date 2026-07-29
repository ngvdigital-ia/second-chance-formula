#!/usr/bin/env python3
"""Deterministic local gate for the sanitized Second Chance Formula clone."""

from __future__ import annotations

import asyncio
import functools
import hashlib
import http.server
import json
import socketserver
import threading
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright


ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "vsl" / "index.html"
SOURCE = ROOT / "evidence" / "source.html"
EVIDENCE = ROOT / "evidence"

FORBIDDEN = {
    "competitor domain": "razeresearch.com",
    "competitor identity": "Diego Raze",
    "competitor player": "converteai.net",
    "competitor/player markup": "vturb-smartplayer",
    "UTMify": "utmify",
    "Meta Pixel": "fbq(",
    "TikTok": "tiktok",
    "checkout": "checkout-ds24.com",
    "operational button": "<button",
    "operational link": "<a ",
}


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args: object) -> None:
        return


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


async def run() -> dict:
    html = PAGE.read_text(encoding="utf-8")
    source_size = SOURCE.stat().st_size
    static = {
        "source_capture_bytes": source_size,
        "source_capture_sha256": sha256(SOURCE),
        "page_bytes": PAGE.stat().st_size,
        "source_layout_markers": {
            "page_max_width_460": SOURCE.read_text(
                encoding="utf-8", errors="replace"
            ).count("max-width:460px"),
            "player_max_width_400": SOURCE.read_text(
                encoding="utf-8", errors="replace"
            ).count("max-width:400px"),
            "background_0e0f13": SOURCE.read_text(
                encoding="utf-8", errors="replace"
            ).casefold().count("#0e0f13"),
            "font_inter": SOURCE.read_text(
                encoding="utf-8", errors="replace"
            ).count("'Inter'"),
        },
        "forbidden_occurrences": {
            label: html.casefold().count(needle.casefold())
            for label, needle in FORBIDDEN.items()
        },
        "waiting_video": 'data-delivery-state="waiting-video"' in html,
        "waiting_tracking": 'data-tracking-state="waiting-tracking"' in html,
        "has_csp_meta": "content-security-policy" in html.casefold(),
    }

    handler = functools.partial(QuietHandler, directory=str(ROOT))
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    screenshots = []
    browser_domains: set[str] = set()
    console_errors: list[str] = []

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            for label, width, height in (
                ("mobile-390x844", 390, 844),
                ("desktop-1440x900", 1440, 900),
            ):
                page = await browser.new_page(viewport={"width": width, "height": height})
                page.on(
                    "request",
                    lambda request: browser_domains.add(urlparse(request.url).hostname or ""),
                )
                page.on(
                    "console",
                    lambda message: console_errors.append(message.text)
                    if message.type == "error"
                    else None,
                )
                await page.goto(
                    f"http://127.0.0.1:{port}/vsl/index.html",
                    wait_until="load",
                    timeout=15_000,
                )
                await page.wait_for_timeout(500)
                probe = await page.evaluate(
                    """() => {
                      const root = document.documentElement;
                      const player = document.querySelector('.video-wrap');
                      const rect = player.getBoundingClientRect();
                      const images = [...document.images];
                      return {
                        title: document.title,
                        viewport: { width: innerWidth, height: innerHeight },
                        document: {
                          clientWidth: root.clientWidth,
                          scrollWidth: root.scrollWidth,
                          clientHeight: root.clientHeight,
                          scrollHeight: root.scrollHeight
                        },
                        horizontalOverflow: root.scrollWidth > root.clientWidth,
                        player: {
                          width: Math.round(rect.width),
                          height: Math.round(rect.height),
                          top: Math.round(rect.top)
                        },
                        controls: {
                          anchors: document.querySelectorAll('a').length,
                          buttons: document.querySelectorAll('button').length,
                          forms: document.querySelectorAll('form').length
                        },
                        assets: {
                          images: images.length,
                          broken: images.filter(img => img.naturalWidth === 0).length
                        },
                        state: {
                          delivery: document.body.dataset.deliveryState,
                          tracking: document.body.dataset.trackingState
                        }
                      };
                    }"""
                )
                shot = EVIDENCE / f"{label}.png"
                await page.screenshot(path=str(shot), full_page=True)
                probe["screenshot"] = {
                    "path": str(shot.relative_to(ROOT)).replace("\\", "/"),
                    "sha256": sha256(shot),
                }
                screenshots.append(probe)
                await page.close()
            await browser.close()
    finally:
        server.shutdown()
        server.server_close()

    allowed_domains = {"127.0.0.1", "fonts.googleapis.com", "fonts.gstatic.com"}
    unexpected_domains = sorted(d for d in browser_domains if d not in allowed_domains)
    failures = []
    if source_size <= 5000:
        failures.append("source capture is too small")
    if any(static["forbidden_occurrences"].values()):
        failures.append("forbidden competitor or operational code remains")
    if not static["waiting_video"] or not static["waiting_tracking"]:
        failures.append("pending states are not explicit")
    if static["has_csp_meta"]:
        failures.append("CSP meta found")
    if unexpected_domains:
        failures.append("unexpected network domains were contacted")
    for probe in screenshots:
        if probe["horizontalOverflow"]:
            failures.append(f"horizontal overflow at {probe['viewport']}")
        if any(probe["controls"].values()):
            failures.append(f"operational control found at {probe['viewport']}")
        if probe["assets"]["broken"]:
            failures.append(f"broken image found at {probe['viewport']}")
        if probe["state"] != {
            "delivery": "waiting-video",
            "tracking": "waiting-tracking",
        }:
            failures.append(f"wrong delivery state at {probe['viewport']}")

    result = {
        "schema": "ngv-local-clone-gate.v1",
        "status": "PASS" if not failures else "FAIL",
        "page": str(PAGE.relative_to(ROOT)).replace("\\", "/"),
        "static": static,
        "browser": {
            "one_shot_closed": True,
            "domains": sorted(browser_domains),
            "unexpected_domains": unexpected_domains,
            "console_errors": console_errors,
            "viewports": screenshots,
        },
        "gates": {
            "scope": "PASS",
            "source_capture": "PASS" if source_size > 5000 else "FAIL",
            "static_sanitization": (
                "PASS" if not any(static["forbidden_occurrences"].values()) else "FAIL"
            ),
            "mobile_390x844": (
                "PASS" if not screenshots[0]["horizontalOverflow"] else "FAIL"
            ),
            "desktop_1440x900": (
                "PASS" if not screenshots[1]["horizontalOverflow"] else "FAIL"
            ),
            "assets_natural_width": (
                "PASS" if all(not item["assets"]["broken"] for item in screenshots) else "FAIL"
            ),
            "affected_cta_flow": (
                "PASS"
                if all(not any(item["controls"].values()) for item in screenshots)
                else "FAIL"
            ),
        },
        "failures": failures,
    }
    output = EVIDENCE / "local-gate.json"
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    raise SystemExit(0 if asyncio.run(run())["status"] == "PASS" else 1)

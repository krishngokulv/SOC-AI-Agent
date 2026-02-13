#!/usr/bin/env python3
"""
SOC-AI-Agent — Automated Screenshot Capture

Submits all 10 sample alerts through the backend API, captures the live
investigation stream, and screenshots every key page in the dashboard.

Usage:
    python take_screenshots.py            # headless (for CI)
    python take_screenshots.py --visible  # watch in real-time

Prerequisites:
    pip install -r requirements_screenshots.txt
    playwright install chromium
    docker compose up --build   # SOC-AI-Agent must be running
"""

import argparse
import asyncio
import sys
from pathlib import Path

try:
    import aiohttp
except ImportError:
    sys.exit("Missing dependency.  Run:  pip install aiohttp")

try:
    from playwright.async_api import async_playwright, TimeoutError as PwTimeout
except ImportError:
    sys.exit(
        "Missing dependency.  Run:\n"
        "  pip install playwright\n"
        "  playwright install chromium"
    )


# ═══════════════════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════════════════

BASE_DIR    = Path(__file__).resolve().parent
FRONT       = "http://localhost:3000"
SS_DIR      = BASE_DIR / "demo_screenshots"
SAMPLE_DIR  = BASE_DIR / "sample_alerts"
VIEWPORT    = {"width": 1920, "height": 1080}
INV_TIMEOUT = 300   # max seconds to wait per investigation
POLL_SEC    = 3     # polling interval

# Submission order — mimikatz saved for LAST so we can capture its live stream
ALERTS = [
    ("sysmon_powershell_encoded.xml", "auto"),
    ("brute_force_auth.log",         "auto"),
    ("phishing_email.eml",           "auto"),
    ("suspicious_dns.log",           "auto"),
    ("ransomware_sysmon.xml",        "auto"),
    ("lateral_movement.xml",         "auto"),
    ("c2_beacon.log",                "auto"),
    ("data_exfiltration.log",        "auto"),
    ("insider_threat.log",           "auto"),
    ("sysmon_mimikatz.xml",          "auto"),   # 10th — live screenshot target
]

n_shots = 0          # running total of screenshots saved


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════

def p(msg=""):
    """Print with immediate flush."""
    print(msg, flush=True)


# ── Service health ────────────────────────────────────────────────────

async def services_healthy() -> bool:
    """Return True when both frontend and backend respond."""
    timeout = aiohttp.ClientTimeout(total=8)
    async with aiohttp.ClientSession(timeout=timeout) as s:
        # Frontend
        try:
            async with s.get(FRONT) as r:
                if r.status != 200:
                    p(f"  ✗ Frontend returned HTTP {r.status}")
                    return False
            p(f"  ✓ Frontend OK  ({FRONT})")
        except Exception as exc:
            p(f"  ✗ Frontend unreachable at {FRONT}: {exc}")
            p("    → Run: docker compose up --build")
            return False

        # Backend (through the nginx proxy)
        try:
            async with s.get(f"{FRONT}/api/health") as r:
                d = await r.json()
                p(f"  ✓ Backend  OK  ({d.get('service', '?')} v{d.get('version', '?')})")
        except Exception as exc:
            p(f"  ✗ Backend API unreachable: {exc}")
            p("    → Run: docker compose up --build")
            return False
    return True


# ── API submit / poll ─────────────────────────────────────────────────

async def api_submit(session: aiohttp.ClientSession, content: str,
                     alert_type: str = "auto") -> str | None:
    """POST alert via backend Form API.  Returns alert_id or None."""
    fd = aiohttp.FormData()
    fd.add_field("content", content)
    fd.add_field("alert_type", alert_type)
    try:
        async with session.post(f"{FRONT}/api/investigate", data=fd) as r:
            if r.status in (200, 201, 202):
                return (await r.json()).get("alert_id")
            p(f"      ⚠ API returned {r.status}: {(await r.text())[:120]}")
    except Exception as exc:
        p(f"      ⚠ API error: {exc}")
    return None


async def api_poll(session: aiohttp.ClientSession, alert_id: str,
                   quiet: bool = False) -> dict | None:
    """Poll GET /api/investigations/{id} until status == complete.
    Returns the full result dict, or None on timeout."""
    for tick in range(INV_TIMEOUT // POLL_SEC):
        try:
            async with session.get(
                f"{FRONT}/api/investigations/{alert_id}"
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    if data.get("status") == "complete":
                        if not quiet:
                            v = data.get("verdict", "?")
                            c = data.get("confidence")
                            cpct = (f"{c:.1f}%"
                                    if isinstance(c, (int, float)) and c is not None
                                    else "?")
                            p(f"      ✓ {v} ({cpct} confidence)")
                        return data
                # 404 = record not created yet; keep waiting
        except Exception:
            pass
        await asyncio.sleep(POLL_SEC)
    if not quiet:
        p(f"      ⚠ timed out after {INV_TIMEOUT}s")
    return None


# ── Screenshot wrapper ────────────────────────────────────────────────

async def snap(page, filename: str, label: str) -> bool:
    """Take a viewport screenshot.  Returns True on success."""
    global n_shots
    path = str(SS_DIR / filename)
    try:
        await page.screenshot(path=path, full_page=False)
        n_shots += 1
        p(f"  📸  {label}  →  {filename}")
        return True
    except Exception as exc:
        p(f"  ✗  {label}: {exc}")
        return False


# ═══════════════════════════════════════════════════════════════════════
#  Main automation flow
# ═══════════════════════════════════════════════════════════════════════

async def run(*, headless: bool = True):
    p()
    p("╔════════════════════════════════════════════════════════════╗")
    p("║   SOC-AI-Agent  —  Automated Screenshot Capture           ║")
    p("╚════════════════════════════════════════════════════════════╝")
    p()

    # ── Preflight checks ──────────────────────────────────────────
    p("[*] Checking services...")
    if not await services_healthy():
        sys.exit(1)

    missing = [fn for fn, _ in ALERTS if not (SAMPLE_DIR / fn).exists()]
    if missing:
        for m in missing:
            p(f"  ✗ Missing sample alert: {SAMPLE_DIR / m}")
        sys.exit(1)
    p(f"  ✓ All {len(ALERTS)} sample alerts found")
    p()

    SS_DIR.mkdir(exist_ok=True)
    last_alert_id: str | None = None

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=headless,
            args=["--disable-gpu", "--no-sandbox"],
        )
        ctx = await browser.new_context(
            viewport=VIEWPORT,
            device_scale_factor=1,
            color_scheme="dark",
        )
        page = await ctx.new_page()

        # ══════════════════════════════════════════════════════════
        #  Phase 1 — Screenshot the empty Alert Submit page
        # ══════════════════════════════════════════════════════════
        p("━" * 58)
        p("  Phase 1 — Alert Submit Page")
        p("━" * 58)

        await page.goto(f"{FRONT}/investigate", wait_until="networkidle")
        # Let CSS animations / transitions settle
        await page.wait_for_timeout(2000)
        await snap(page, "10_alert_submit.png", "Alert Submit (empty)")
        p()

        # ══════════════════════════════════════════════════════════
        #  Phase 2 — Submit all 10 sample alerts
        # ══════════════════════════════════════════════════════════
        p("━" * 58)
        p("  Phase 2 — Submitting 10 Sample Alerts")
        p("━" * 58)

        api_timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=api_timeout) as ses:

            for idx, (filename, atype) in enumerate(ALERTS, 1):
                content = (SAMPLE_DIR / filename).read_text(
                    encoding="utf-8", errors="replace"
                )
                is_last = (idx == len(ALERTS))

                p(f"\n  [{idx:>2}/{len(ALERTS)}] {filename}")

                # Submit via backend Form API
                alert_id = await api_submit(ses, content, atype)
                if not alert_id:
                    p("        ✗ Submission failed — skipping")
                    continue

                # ── Alert 10 (mimikatz, last) — capture live stream ──
                if is_last:
                    last_alert_id = alert_id
                    p(f"        → Navigating to live investigation page...")

                    # Navigate to the LiveInvestigation view immediately
                    await page.goto(
                        f"{FRONT}/investigate/{alert_id}",
                        wait_until="domcontentloaded",
                    )

                    # Wait for the streaming UI to begin showing stages
                    try:
                        await page.wait_for_function(
                            """() => {
                                const t = document.body.innerText;
                                return t.includes('CONNECTED')
                                    || t.includes('Parsing Alert')
                                    || t.includes('PROCESSING')
                                    || t.includes('Investigation Progress');
                            }""",
                            timeout=15000,
                        )
                    except PwTimeout:
                        # Page may show waiting state; screenshot it anyway
                        pass

                    # Give a few seconds for stages to stream in
                    await page.wait_for_timeout(4000)

                    await snap(
                        page,
                        "01_live_investigation_streaming.png",
                        "Live investigation (streaming)",
                    )

                    # Now wait for the verdict / download buttons
                    p("        Waiting for verdict...")
                    try:
                        await page.wait_for_function(
                            """() => {
                                const t = document.body.innerText;
                                return t.includes('Download HTML Report')
                                    || t.includes('View Details');
                            }""",
                            timeout=INV_TIMEOUT * 1000,
                        )
                    except PwTimeout:
                        # Fall back: poll the API and reload the page
                        p("        ⚠ Browser-side wait timed out — polling API...")
                        result = await api_poll(ses, alert_id, quiet=True)
                        if result:
                            v = result.get("verdict", "?")
                            c = result.get("confidence")
                            cpct = (f"{c:.1f}%"
                                    if isinstance(c, (int, float)) and c is not None
                                    else "?")
                            p(f"        ✓ API says: {v} ({cpct})")
                        # Reload so the page reflects completion
                        await page.reload(wait_until="networkidle")

                    await page.wait_for_timeout(2000)
                    await snap(
                        page,
                        "02_investigation_verdict.png",
                        "Investigation verdict",
                    )

                # ── Alerts 1-9 — just wait for completion ────────
                else:
                    await api_poll(ses, alert_id)

        p(f"\n  ✓ All {len(ALERTS)} alerts submitted.")
        p()

        # ══════════════════════════════════════════════════════════
        #  Phase 3 — Dashboard Screenshots
        # ══════════════════════════════════════════════════════════
        p("━" * 58)
        p("  Phase 3 — Dashboard Screenshots")
        p("━" * 58)
        p()

        # ── 3. Dashboard Overview ─────────────────────────────────
        await page.goto(FRONT, wait_until="networkidle")
        # Wait for stat cards or chart SVGs to appear
        try:
            await page.wait_for_function(
                """() => {
                    return document.querySelectorAll('.stat-card').length > 0
                        || document.querySelectorAll('svg').length > 2;
                }""",
                timeout=10000,
            )
        except PwTimeout:
            pass
        await page.wait_for_timeout(2500)
        await snap(page, "03_dashboard_overview.png", "Dashboard overview")

        # Scroll to bottom for charts / tables below the fold
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await page.wait_for_timeout(1500)
        await snap(page, "03b_dashboard_bottom.png", "Dashboard (scrolled)")
        await page.evaluate("window.scrollTo(0, 0)")
        p()

        # ── 4. MITRE ATT&CK Heatmap ──────────────────────────────
        await page.goto(f"{FRONT}/attack-map", wait_until="networkidle")
        await page.wait_for_timeout(3000)
        await snap(page, "04_mitre_attack_heatmap.png", "MITRE ATT&CK Heatmap")
        p()

        # ── 5. IOC Database ───────────────────────────────────────
        await page.goto(f"{FRONT}/iocs", wait_until="networkidle")
        try:
            await page.wait_for_function(
                "() => document.querySelectorAll('tbody tr').length > 0",
                timeout=10000,
            )
        except PwTimeout:
            pass
        await page.wait_for_timeout(1500)
        await snap(page, "05_ioc_database.png", "IOC Database")
        p()

        # ── 6. Investigation History ──────────────────────────────
        await page.goto(f"{FRONT}/history", wait_until="networkidle")
        try:
            await page.wait_for_function(
                "() => document.querySelectorAll('tbody tr').length > 0",
                timeout=10000,
            )
        except PwTimeout:
            pass
        await page.wait_for_timeout(1500)
        await snap(page, "06_investigation_history.png", "Investigation History")
        p()

        # ── 7. Investigation Detail (Mimikatz) ───────────────────
        if last_alert_id:
            await page.goto(
                f"{FRONT}/investigation/{last_alert_id}",
                wait_until="networkidle",
            )
            await page.wait_for_timeout(3000)
            await snap(
                page,
                "07_investigation_detail_top.png",
                "Investigation Detail (top)",
            )

            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1200)
            await snap(
                page,
                "07b_investigation_detail_bottom.png",
                "Investigation Detail (bottom)",
            )
        else:
            p("  ⚠ No last_alert_id — skipping detail screenshots")
        p()

        # ── 8. HTML Report ────────────────────────────────────────
        if last_alert_id:
            await page.goto(
                f"{FRONT}/api/reports/{last_alert_id}/html",
                wait_until="networkidle",
            )
            await page.wait_for_timeout(2000)
            await snap(page, "08_html_report.png", "HTML Report")
        else:
            p("  ⚠ No last_alert_id — skipping HTML report screenshot")
        p()

        # ── 9. PDF Report (screenshot the HTML report scrolled) ──
        if last_alert_id:
            # The HTML report is still loaded from step 8; scroll down
            await page.evaluate("window.scrollTo(0, 800)")
            await page.wait_for_timeout(1000)
            await snap(page, "09_pdf_report.png", "Report (scrolled section)")
        p()

        # ── 11. Threat Analytics ──────────────────────────────────
        await page.goto(f"{FRONT}/analytics", wait_until="networkidle")
        # Analytics may use mock data; give charts time to render
        await page.wait_for_timeout(3500)
        await snap(page, "11_threat_analytics.png", "Threat Analytics")
        p()

        await browser.close()

    # ══════════════════════════════════════════════════════════════
    #  Phase 4 — Summary & README Markdown
    # ══════════════════════════════════════════════════════════════
    p("━" * 58)
    p("  Phase 4 — Results")
    p("━" * 58)
    p()
    p(f"  ✅ {n_shots} screenshots saved to {SS_DIR.relative_to(BASE_DIR)}/")
    p()

    # List files saved
    for f in sorted(SS_DIR.glob("*.png")):
        size_kb = f.stat().st_size / 1024
        p(f"      {f.name:45s} {size_kb:>7.1f} KB")
    p()

    # README-ready markdown snippet
    markdown = """\
## Screenshots

### Dashboard
![Dashboard Overview](demo_screenshots/03_dashboard_overview.png)

### Live Investigation Stream
![Live Investigation](demo_screenshots/01_live_investigation_streaming.png)

### Investigation Verdict
![Verdict](demo_screenshots/02_investigation_verdict.png)

### MITRE ATT&CK Heatmap
![ATT&CK Heatmap](demo_screenshots/04_mitre_attack_heatmap.png)

### IOC Database
![IOC Database](demo_screenshots/05_ioc_database.png)

### Investigation History
![Investigation History](demo_screenshots/06_investigation_history.png)

### Investigation Detail
![Investigation Detail](demo_screenshots/07_investigation_detail_top.png)
![Investigation Detail - Continued](demo_screenshots/07b_investigation_detail_bottom.png)

### Generated Incident Report
![HTML Report](demo_screenshots/08_html_report.png)

### Alert Submission
![Alert Submit](demo_screenshots/10_alert_submit.png)

### Threat Analytics
![Threat Analytics](demo_screenshots/11_threat_analytics.png)
"""
    p("── README Markdown Snippet ─────────────────────────────")
    print(markdown)
    p("── End ─────────────────────────────────────────────────")
    p()
    p("To run:")
    p("  pip install -r requirements_screenshots.txt")
    p("  playwright install chromium")
    p("  python take_screenshots.py          # headless mode")
    p("  python take_screenshots.py --visible  # watch it in real-time")
    p()


# ═══════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="SOC-AI-Agent — Automated screenshot capture"
    )
    ap.add_argument(
        "--visible",
        action="store_true",
        help="Show the browser window (headless=False)",
    )
    args = ap.parse_args()
    asyncio.run(run(headless=not args.visible))


if __name__ == "__main__":
    main()

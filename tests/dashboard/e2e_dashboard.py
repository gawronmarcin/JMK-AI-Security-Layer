#!/usr/bin/env python3
"""Browser end-to-end checks for the AICL dashboard (Playwright, Chromium).

Prerequisites: `pip install playwright && playwright install chromium`, then start the mocks:

    python tests/dashboard/mock_admin_server.py --port 8080 --key dev-key-123 --live
    python tests/dashboard/mock_admin_server.py --port 8081 --open --scenario edge
    python tests/dashboard/mock_admin_server.py --port 8082 --key k --fail summary=500,latency=429,budgets=timeout,controls=403
    python tests/dashboard/mock_admin_server.py --port 8083 --open --scenario empty

Run:  python tests/dashboard/e2e_dashboard.py [--shots DIR] [--chromium PATH]
Exit code 0 = all checks passed. Screenshots are written for manual visual review.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from playwright.async_api import async_playwright

KEY = "dev-key-123"
VIEWS = ["overview", "threats", "controls", "budgets", "performance", "tests", "events", "policy"]
results: list[tuple[bool, str]] = []


def check(ok: bool, name: str, detail: str = ""):
    results.append((bool(ok), name + (f" — {detail}" if detail and not ok else "")))


async def new_page(browser, base, vp=(1440, 900), errors=None):
    ctx = await browser.new_context(viewport={"width": vp[0], "height": vp[1]}, accept_downloads=True)
    page = await ctx.new_page()
    errs = errors if errors is not None else []
    page.on("pageerror", lambda e: errs.append(f"pageerror: {e}"))
    page.on("console", lambda m: errs.append(f"console.{m.type}: {m.text}") if m.type in ("error", "warning") else None)
    dialogs = []
    page.on("dialog", lambda d: (dialogs.append(d.message), asyncio.ensure_future(d.dismiss())))
    page._dialogs = dialogs  # noqa: SLF001 — test-only bookkeeping
    await page.goto(base + "/dashboard/")
    return ctx, page, errs


async def login(page, key=KEY):
    await page.wait_for_selector("#login-dialog[open]")
    await page.fill("#admin-key", key)
    await page.click("#login-submit")


async def toasts_errors(page):
    return await page.eval_on_selector_all(".toast-error", "els => els.map(e => e.textContent)")


async def run(shots: Path, chromium: str | None):
    shots.mkdir(parents=True, exist_ok=True)
    async with async_playwright() as p:
        browser = await p.chromium.launch(executable_path=chromium) if chromium else await p.chromium.launch()

        # ------------------------------------------------------------- 1. login, views, leaks
        ctx, page, errs = await new_page(browser, "http://127.0.0.1:8080")
        check(await page.evaluate("document.getElementById('login-dialog').open"), "login dialog shown on open")
        await login(page, "wrong-key")
        await page.wait_for_timeout(700)
        msg = await page.text_content("#login-error")
        check("401" in (msg or ""), "wrong key → 401 message in dialog", msg)
        await login(page)
        for _ in range(50):  # (wait_for_function would need eval, which the page CSP forbids)
            if not await page.evaluate("document.getElementById('login-dialog').open"):
                break
            await page.wait_for_timeout(100)
        await page.wait_for_timeout(2500)
        check("Online" in (await page.text_content("#st-gateway") or ""), "gateway Online after sign-in")
        for v in VIEWS:
            await page.click(f"#nav-list a[data-view={v}]")
            await page.wait_for_timeout(1500)
            await page.screenshot(path=str(shots / f"desktop-{v}.png"), full_page=True)
            te = await toasts_errors(page)
            check(not any("Rendering" in t for t in te), f"view {v} renders without errors", "; ".join(te))
        storage = await page.evaluate("JSON.stringify([Object.keys(localStorage), Object.keys(sessionStorage), document.cookie, location.href])")
        check(KEY not in storage and storage.startswith('[[],[],""'), "token not in storage / cookies / URL", storage)
        check(KEY not in await page.content(), "token not in DOM")

        # ------------------------------------------------------------- 2. cross-filter + drawer + export
        await page.click("#nav-list a[data-view=overview]")
        await page.wait_for_timeout(1200)
        await page.click(".kpi:has-text('Blocked') .kpi-link")
        await page.wait_for_timeout(1200)
        url = page.url
        check("#/events" in url and "action=block" in url, "KPI 'Events ›' sets Audit filter in hash", url)
        acts = await page.eval_on_selector_all("section[aria-labelledby=v-events] tbody tr .badge-action", "els => els.map(e => e.textContent)")
        check(acts and all("Block" in a for a in acts), "audit table filtered to block", str(acts[:5]))
        await page.click("section[aria-labelledby=v-events] tbody tr.row-link >> nth=0")
        await page.wait_for_selector("#drawer:not([hidden])", timeout=3000)
        await page.wait_for_timeout(300)
        await page.screenshot(path=str(shots / "desktop-event-drawer.png"))
        inside = await page.evaluate("document.getElementById('drawer').contains(document.activeElement)")
        check(inside, "drawer receives focus")
        for _ in range(25):
            await page.keyboard.press("Tab")
        check(await page.evaluate("document.getElementById('drawer').contains(document.activeElement)"), "focus trapped in drawer")
        await page.keyboard.press("Escape")
        await page.wait_for_timeout(300)
        check(await page.evaluate("document.getElementById('drawer').hidden"), "Escape closes drawer")
        async with page.expect_download(timeout=15000) as dl:
            await page.click("button:has-text('Export audit JSONL')")
        d = await dl.value
        path = await d.path()
        first = Path(path).read_text().splitlines()[0]
        check(d.suggested_filename.endswith(".jsonl") and json.loads(first).get("ts"), "export downloads JSONL with auth", d.suggested_filename)

        # ------------------------------------------------------------- 3. 401 mid-session clears key
        await page.route("**/admin/metrics/summary", lambda r: r.fulfill(status=401, body='{"detail":"expired"}', content_type="application/json"))
        await page.click("#nav-list a[data-view=overview]")
        await page.click("#refresh-now")
        await page.wait_for_selector("#login-dialog[open]", timeout=8000)
        check(True, "401 during session → login dialog again")
        hdrs = []
        page.on("request", lambda r: hdrs.append(r.headers.get("authorization")))
        await page.wait_for_timeout(1500)
        check(not any(hdrs), "no Authorization header sent after 401", str(hdrs))
        await page.unroute("**/admin/metrics/summary")
        check(not [e for e in errs if "pageerror" in e], "no uncaught page errors (main)", "; ".join(errs[:5]))
        check(not [e for e in errs if "Content Security Policy" in e], "no CSP violations", "; ".join(errs[:5]))
        unexpected = [e for e in errs if e.startswith("console.") and "401" not in e]
        check(not unexpected, "no console errors/warnings besides expected 401 responses", "; ".join(unexpected[:5]))
        await ctx.close()

        # ------------------------------------------------------------- 4. mobile + keyboard
        ctx, page, errs = await new_page(browser, "http://127.0.0.1:8080", vp=(390, 844))
        await login(page)
        await page.wait_for_timeout(2500)
        await page.screenshot(path=str(shots / "mobile-overview.png"), full_page=True)
        sw = await page.evaluate("document.documentElement.scrollWidth")
        check(sw <= 392, "no horizontal page overflow on 390 px", f"scrollWidth={sw}")
        await page.click("#menu-toggle")
        await page.wait_for_timeout(300)
        await page.screenshot(path=str(shots / "mobile-nav.png"))
        check(await page.evaluate("document.body.classList.contains('nav-open')"), "mobile nav opens")
        await page.keyboard.press("Escape")
        await page.wait_for_timeout(200)
        check(not await page.evaluate("document.body.classList.contains('nav-open')"), "Escape closes mobile nav")
        await page.evaluate("location.hash = '#/budgets'")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=str(shots / "mobile-budgets.png"), full_page=True)
        await page.evaluate("location.hash = '#/events'")
        await page.wait_for_timeout(2000)
        await page.screenshot(path=str(shots / "mobile-events.png"), full_page=True)
        # keyboard-only navigation (fresh load: the skip link is the first focusable element)
        await page.reload()
        await login(page)
        await page.wait_for_timeout(1500)
        first_focus = await page.evaluate("(() => { const f = [...document.querySelectorAll('a[href], button, input, select, textarea, [tabindex]')].find((n) => !n.closest('dialog, [hidden], .toasts') && n.tabIndex >= 0); return f ? f.className : 'none'; })()")
        check("skip-link" in first_focus, "skip link is the first focusable element", first_focus)
        await page.focus(".skip-link")
        await page.keyboard.press("Enter")
        check(await page.evaluate("document.activeElement.id === 'main'"), "skip link moves focus to main")
        await ctx.close()

        # ------------------------------------------------------------- 5. demo mode
        ctx = await browser.new_context(viewport={"width": 1440, "height": 900})
        page = await ctx.new_page()
        derr = []
        page.on("pageerror", lambda e: derr.append(str(e)))
        await page.goto("http://127.0.0.1:8080/dashboard/?demo=1")
        await page.wait_for_timeout(3500)
        check(await page.is_visible(".demo-ribbon"), "DEMO DATA ribbon visible in demo mode")
        for v in VIEWS:
            await page.click(f"#nav-list a[data-view={v}]")
            await page.wait_for_timeout(1300)
            await page.screenshot(path=str(shots / f"demo-{v}.png"), full_page=True)
        check(not derr, "demo mode has no page errors", "; ".join(derr[:3]))
        await ctx.close()
        # demo never starts automatically after an API error
        ctx, page, errs = await new_page(browser, "http://127.0.0.1:8082")
        await login(page, "k")
        await page.wait_for_timeout(4000)
        check(not await page.is_visible(".demo-ribbon"), "API errors never switch to demo data")
        gw = await page.text_content("#st-gateway")
        check("Degraded" in (gw or ""), "partial outage → gateway Degraded", gw)
        await page.screenshot(path=str(shots / "faults-overview.png"), full_page=True)
        for v in ("controls", "budgets", "performance"):
            await page.click(f"#nav-list a[data-view={v}]")
            await page.wait_for_timeout(1500)
            await page.screenshot(path=str(shots / f"faults-{v}.png"), full_page=True)
        await ctx.close()

        # ------------------------------------------------------------- 6. edge payloads (XSS, unknown types, nulls)
        ctx, page, errs = await new_page(browser, "http://127.0.0.1:8081")
        await page.wait_for_selector("#login-dialog[open]")
        await page.click(".login-more summary")
        await page.click("#login-open")
        await page.wait_for_timeout(2500)
        for v in VIEWS:
            await page.click(f"#nav-list a[data-view={v}]")
            await page.wait_for_timeout(1200)
            await page.screenshot(path=str(shots / f"edge-{v}.png"), full_page=True)
            te = await toasts_errors(page)
            check(not any("Rendering" in t for t in te), f"edge view {v} renders", "; ".join(te))
        await page.click("#nav-list a[data-view=events]")
        await page.fill("section[aria-labelledby=v-events] input[type=search]", "evt_edge_xss")
        await page.wait_for_timeout(800)
        await page.click("section[aria-labelledby=v-events] tbody tr.row-link >> nth=0")
        await page.wait_for_timeout(500)
        await page.screenshot(path=str(shots / "edge-xss-drawer.png"))
        injected = await page.evaluate("document.querySelectorAll('img[src=\"x\"], #views script, #drawer script').length")
        check(injected == 0 and not page._dialogs, "XSS strings rendered as text only", f"elements={injected} dialogs={page._dialogs}")
        drawer_text = await page.text_content("#drawer")
        check("raw-secret@example.com" not in drawer_text and "LEAK" not in drawer_text and "sk-should-never-render" not in drawer_text,
              "raw match values / credentials never displayed")
        check("<img src=x" in drawer_text, "hostile text visible literally")
        check(not [e for e in errs if "pageerror" in e], "no uncaught page errors (edge)", "; ".join(errs[:5]))
        await ctx.close()

        # ------------------------------------------------------------- 7. empty responses
        ctx, page, errs = await new_page(browser, "http://127.0.0.1:8083")
        await page.wait_for_selector("#login-dialog[open]")
        await page.click(".login-more summary")
        await page.click("#login-open")
        await page.wait_for_timeout(2500)
        for v in VIEWS:
            await page.click(f"#nav-list a[data-view={v}]")
            await page.wait_for_timeout(1000)
            await page.screenshot(path=str(shots / f"empty-{v}.png"), full_page=True)
            te = await toasts_errors(page)
            check(not any("Rendering" in t for t in te), f"empty view {v} renders", "; ".join(te))
        check(not [e for e in errs if "pageerror" in e], "no uncaught page errors (empty)", "; ".join(errs[:5]))
        await ctx.close()
        await browser.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots", default="/tmp/aicl-shots")
    ap.add_argument("--chromium", default=None)
    a = ap.parse_args()
    try:
        asyncio.run(run(Path(a.shots), a.chromium))
    except Exception as exc:  # report what ran so far
        results.append((False, f"runner aborted: {type(exc).__name__}: {str(exc).splitlines()[0]}"))
    failed = [n for ok, n in results if not ok]
    for ok, n in results:
        print(("PASS " if ok else "FAIL ") + n)
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()

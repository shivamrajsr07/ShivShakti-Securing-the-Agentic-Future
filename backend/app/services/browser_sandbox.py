from app.models.security import BrowserVisit, Decision
from app.security.browser_guard import inspect_browser_visit


async def sandbox_visit(visit: BrowserVisit) -> dict:
    policy_event = inspect_browser_visit(visit)
    if policy_event.decision == Decision.blocked:
        return {"event": policy_event, "page": None}

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return {
            "event": policy_event,
            "page": {
                "status": "playwright_not_installed",
                "title": None,
                "final_url": visit.url,
                "note": "Install Playwright browsers with: python -m playwright install chromium",
            },
        }

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context(accept_downloads=False, java_script_enabled=True)
        page = await context.new_page()
        response = await page.goto(visit.url, wait_until="domcontentloaded", timeout=8000)
        title = await page.title()
        final_url = page.url
        await context.close()
        await browser.close()
        return {
            "event": policy_event,
            "page": {
                "status": response.status if response else None,
                "title": title,
                "final_url": final_url,
            },
        }


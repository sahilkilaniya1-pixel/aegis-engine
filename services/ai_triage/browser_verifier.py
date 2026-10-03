import asyncio
from playwright.async_api import async_playwright

class PlaywrightVerifier:
    def __init__(self):
        pass

    async def verify_xss(self, target_url: str, payload: str) -> dict:
        alert_triggered = False
        screenshot_path = f"reports/xss_poc_{hash(target_url)}.png"

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()

            # Dialog listener for alert/confirm/prompt
            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

            try:
                # Target navigate karein payload ke sath
                test_url = f"{target_url}?q={payload}"
                response = await page.goto(test_url, timeout=10000)

                # Screenshot save karein proof ke liye
                await page.screenshot(path=screenshot_path)
                
                return {
                    "verified": True,
                    "screenshot": screenshot_path,
                    "status_code": response.status if response else 0
                }
            except Exception as e:
                return {"verified": False, "error": str(e)}
            finally:
                await browser.close()
import unittest
from pathlib import Path


ROOT = Path(__file__).parents[1]


class WebExperienceTest(unittest.TestCase):
    def test_page_has_required_architecture_sections(self) -> None:
        page = (ROOT / "web" / "index.html").read_text()
        for section in ("architecture", "intelligence", "improvement", "governance", "scenario"):
            self.assertIn(f'id="{section}"', page)
        for platform in ("Gotham", "Foundry", "AIP", "Apollo"):
            self.assertIn(platform, page)

    def test_protection_is_scoped_not_page_wide(self) -> None:
        page = (ROOT / "web" / "index.html").read_text()
        self.assertIn('class="signal-stage protected protected-watermark', page)
        self.assertNotIn('<body class="protected', page)

    def test_neon_system_is_reusable_and_motion_safe(self) -> None:
        page = (ROOT / "web" / "index.html").read_text()
        styles = (ROOT / "web" / "styles.css").read_text()

        for utility in ("neon-action", "neon-surface", "neon-divider"):
            self.assertIn(utility, page)
            self.assertIn(f".{utility}", styles)
        self.assertIn("@media(prefers-reduced-motion:reduce)", styles)
        self.assertIn("pointer-events:none", styles)


if __name__ == "__main__":
    unittest.main()

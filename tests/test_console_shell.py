from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
import unittest

from jinja2 import Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parents[1]


class ShellElements(HTMLParser):
    def __init__(self, html: str):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class ConsoleShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = Environment(
            loader=FileSystemLoader(ROOT / "templates"),
            autoescape=select_autoescape(["html"]),
        ).get_template("components/admin_sidebar.html")

    def render_shell(self, protected=True, username="synthetic-admin"):
        return self.template.render(
            user=SimpleNamespace(
                username=username, role=SimpleNamespace(value="super_admin")
            ),
            firewall_active=protected,
        )

    def test_navigation_keeps_real_routes_and_shared_script_hooks(self):
        elements = ShellElements(self.render_shell()).elements
        navs = [attrs for tag, attrs in elements if tag == "nav"]
        self.assertEqual(1, len(navs))
        self.assertEqual("console-primary-navigation", navs[0]["id"])
        self.assertEqual("Primary navigation", navs[0]["aria-label"])
        self.assertIn("data-console-nav", navs[0])
        routes = {
            attrs["data-console-section"]: attrs["href"]
            for tag, attrs in elements
            if tag == "a" and "data-console-section" in attrs
        }
        self.assertEqual({
            "dashboard": "/admin/dashboard",
            "applications": "/admin/applications",
            "security": "/admin/soc/events",
            "evaluation": "/admin/evaluation",
        }, routes)
        brand_images = [attrs for tag, attrs in elements if tag == "img"]
        self.assertEqual(brand_images, [{
            "src": "/static/branding/llmguard-mark-64.png",
            "alt": "",
        }])
        self.assertNotIn("/static/university/images/logo.png", self.render_shell())

    def test_account_trigger_controls_the_hidden_menu_and_logout_button(self):
        elements = ShellElements(self.render_shell()).elements
        trigger = next(attrs for _, attrs in elements if "data-user-menu-toggle" in attrs)
        menu = next(attrs for _, attrs in elements if "data-user-menu" in attrs)
        logout = next(attrs for _, attrs in elements if "data-logout" in attrs)
        self.assertEqual(menu["id"], trigger["aria-controls"])
        self.assertEqual("false", trigger["aria-expanded"])
        self.assertEqual("Account for synthetic-admin", trigger["aria-label"])
        self.assertIn("hidden", menu)
        self.assertEqual("button", logout["type"])

    def test_status_and_identity_come_from_context(self):
        protected = self.render_shell()
        bypassed = self.render_shell(False)
        self.assertIn("is-secure", protected)
        self.assertNotIn("is-bypassed", protected)
        self.assertIn("is-bypassed", bypassed)
        self.assertNotIn("is-secure", bypassed)
        self.assertIn("Bypassed", bypassed)
        self.assertIn("Super Admin", protected)
        self.assertIn("synthetic-admin", protected)

    def test_identity_is_escaped_in_labels_and_account_details(self):
        html = self.render_shell(username='synthetic-<operator>"')
        self.assertNotIn("<operator>", html)
        self.assertIn("&lt;operator&gt;", html)
        self.assertIn("&#34;", html)


if __name__ == "__main__":
    unittest.main()

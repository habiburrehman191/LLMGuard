from html.parser import HTMLParser
from pathlib import Path
import unittest

from jinja2 import Environment, FileSystemLoader, select_autoescape


ROOT = Path(__file__).resolve().parents[1]


class LoginElements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.elements = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


class LoginPresentationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        template = Environment(
            loader=FileSystemLoader(ROOT / "templates"),
            autoescape=select_autoescape(["html"]),
        ).get_template("login.html")
        cls.html = template.render(
            page_title="LLMGuard", asset_version="test",
            url_for=lambda name, path: "/static/" + path,
        )
        cls.elements = LoginElements(cls.html).elements

    def test_native_form_and_auth_hooks_remain_unique(self):
        ids = [attrs.get("id") for _, attrs in self.elements]
        for hook in ("login-form", "username", "password", "login-message"):
            self.assertEqual(ids.count(hook), 1)
        inputs = {attrs["id"]: attrs for tag, attrs in self.elements if tag == "input"}
        self.assertEqual(set(inputs), {"username", "password"})
        for name, kind, autocomplete in (
            ("username", "text", "username"),
            ("password", "password", "current-password"),
        ):
            self.assertEqual(inputs[name]["name"], name)
            self.assertEqual(inputs[name]["type"], kind)
            self.assertEqual(inputs[name]["autocomplete"], autocomplete)
            self.assertIn("required", inputs[name])
            self.assertNotIn("value", inputs[name])
        labels = {attrs.get("for") for tag, attrs in self.elements if tag == "label"}
        self.assertEqual(labels, {"username", "password"})
        buttons = [attrs for tag, attrs in self.elements if tag == "button"]
        self.assertEqual(len(buttons), 1)
        self.assertEqual(buttons[0]["type"], "submit")

    def test_errors_are_announced_and_decoration_is_not_interactive(self):
        message = next(attrs for _, attrs in self.elements if attrs.get("id") == "login-message")
        self.assertEqual(message["role"], "status")
        self.assertEqual(message["aria-live"], "polite")
        radar = next(attrs for _, attrs in self.elements if attrs.get("class") == "login-radar")
        self.assertEqual(radar["aria-hidden"], "true")
        self.assertNotIn("tabindex", radar)
        self.assertFalse(any(tag in {"nav", "header", "img"} for tag, _ in self.elements))

    def test_only_existing_assets_and_real_login_content_are_used(self):
        scripts = [attrs["src"] for tag, attrs in self.elements if tag == "script"]
        self.assertEqual(scripts, ["/static/product.js?v=test"])
        self.assertFalse(any(key.startswith("on") for _, attrs in self.elements for key in attrs))
        for text in ("AI Security Firewall", "Administrator Sign In",
                     "Sign In to Security Console", "Controlled Research Environment"):
            self.assertIn(text, self.html)
        for text in ("SSO", "FIDO", "Yubikey", "TLS", "AES", "Gateway:",
                     "Latency:", "Nodes:", "Persist Session", "TTL:", "admin@uoh"):
            self.assertNotIn(text, self.html)


if __name__ == "__main__":
    unittest.main()

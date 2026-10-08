"""Route and dependency closure regressions for frontend cleanup."""
from html.parser import HTMLParser
from pathlib import Path
import re
import unittest
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree

from jinja2 import Environment, FileSystemLoader, meta
from app.security_events import list_incidents
from tests import test_soc_console as soc_fixtures

ROOT = Path(__file__).resolve().parents[1]
PAGES = ['/login', '/admin/dashboard', '/admin/applications',
         '/admin/applications/university-of-haripur', '/admin/soc/events',
         '/admin/soc/incidents', '/admin/soc/trace', '/admin/soc/quarantine',
         '/admin/evaluation', '/admin/compare', '/admin/redteam',
         '/admin/security-dashboard', '/admin/audit', '/admin/documents']

class Elements(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.items = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.items.append((tag, dict(attrs)))

class FrontendAssetIntegrityTests(unittest.TestCase):
    setUp = soc_fixtures.SocConsoleTests.setUp
    tearDown = soc_fixtures.SocConsoleTests.tearDown
    _login = soc_fixtures.SocConsoleTests._login
    _record = soc_fixtures.SocConsoleTests._record

    def pages(self):
        self._record(request_id='SYNTHETIC-CLEANUP-ASSET-CHECK', classification='malicious',
                     severity='critical', risk_score=0.95, action='block')
        incidents = list_incidents()
        self.assertTrue(incidents)
        return PAGES + [f'/admin/soc/incidents/{incidents[0].incident_id}']

    def test_every_rendered_page_has_a_complete_static_dependency_graph(self):
        checked = set()
        def check_asset(url):
            parsed = urlsplit(url)
            if not parsed.path.startswith('/static/') or parsed.path in checked:
                return
            checked.add(parsed.path)
            response = self.client.get(parsed.path)
            self.assertEqual(200, response.status_code, parsed.path)
            if parsed.path.endswith('.css'):
                for dependency in re.findall(r'url\(\s*[\"\']?([^\"\')\s]+)', response.text):
                    check_asset(urljoin('http://testserver' + parsed.path, dependency))
        for route in self.pages():
            with self.subTest(route=route):
                page = self.client.get(route)
                self.assertEqual(200, page.status_code)
                self.assertIn('<html', page.text)
                for tag, attrs in Elements(page.text).items:
                    for key in ('src', 'href'):
                        if attrs.get(key):
                            check_asset(attrs[key])
        self.assertGreaterEqual(len(checked), 20)

    def test_every_llmguard_page_uses_only_the_canonical_product_favicon(self):
        expected = "/static/branding/llmguard-mark-32.png"
        for route in self.pages():
            with self.subTest(route=route):
                page = self.client.get(route)
                icons = [
                    attrs.get("href", "")
                    for tag, attrs in Elements(page.text).items
                    if tag == "link" and attrs.get("rel") == "icon"
                ]
                self.assertEqual(1, len(icons))
                self.assertEqual(expected, urlsplit(icons[0]).path)
                self.assertNotIn("/static/university/images/logo.png", page.text)

    def test_canonical_branding_pngs_exist_with_expected_dimensions_and_alpha(self):
        from PIL import Image

        expected = {
            "llmguard-mark.png": (319, 362),
            "llmguard-mark-64.png": (64, 64),
            "llmguard-mark-32.png": (32, 32),
            "llmguard-wordmark-dark.png": (1210, 366),
        }
        for name, dimensions in expected.items():
            with self.subTest(name=name):
                with Image.open(ROOT / "static" / "branding" / name) as image:
                    self.assertEqual("PNG", image.format)
                    self.assertEqual("RGBA", image.mode)
                    self.assertEqual(dimensions, image.size)
                    self.assertEqual((0, 255), image.getchannel("A").getextrema())

    def test_current_rendered_sprite_symbols_exist(self):
        symbols = {node.attrib['id'] for node in ElementTree.parse(ROOT / 'static/llmguard-icons.svg').iter()
                   if 'id' in node.attrib}
        count = 0
        for route in self.pages():
            for tag, attrs in Elements(self.client.get(route).text).items:
                if tag == 'use' and '/static/llmguard-icons.svg#' in attrs.get('href', ''):
                    count += 1
                    self.assertIn(attrs['href'].split('#', 1)[1], symbols, route)
        self.assertGreater(count, 100)

    def test_template_inheritance_and_include_closures_for_both_applications(self):
        for directory in [ROOT / 'templates', ROOT / 'university_site/templates']:
            env = Environment(loader=FileSystemLoader(directory))
            for name in env.list_templates():
                with self.subTest(application=directory, template=name):
                    source = env.loader.get_source(env, name)[0]
                    for referenced in meta.find_referenced_templates(env.parse(source)):
                        self.assertIsNotNone(referenced, 'Dynamic include requires explicit closure coverage')
                        env.get_template(referenced)
                    env.get_template(name)

    def test_compatibility_entrypoints_still_redirect_without_legacy_rendering(self):
        authenticated = self.client.get('/', follow_redirects=False)
        self.assertEqual(307, authenticated.status_code)
        self.assertEqual('/admin/dashboard', authenticated.headers['location'])
        self.client.cookies.clear()
        for route in ['/', '/app']:
            response = self.client.get(route, follow_redirects=False)
            self.assertEqual(307, response.status_code)
            self.assertEqual('/login', response.headers['location'])

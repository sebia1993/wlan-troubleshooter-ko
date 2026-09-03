import unittest

from wlan_troubleshooter_ko.report.offline_html import (
    OfflineHtmlError,
    validate_offline_html,
)


class OfflineHtmlTests(unittest.TestCase):
    CSP = (
        '<meta http-equiv="Content-Security-Policy" '
        'content="default-src \'none\'; connect-src \'none\'; img-src data:; '
        'style-src \'unsafe-inline\'; script-src \'none\'; font-src \'none\'; '
        'frame-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">'
    )

    def test_static_inline_document_is_allowed(self):
        document = (
            "<!doctype html><html><head>"
            '<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; connect-src \'none\'; img-src data:; '
            'style-src \'unsafe-inline\'; script-src \'none\'; font-src \'none\'; '
            'frame-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">'
            "<style>body { color: black; }</style></head>"
            "<body><h1>정적 테스트</h1></body></html>"
        )

        validate_offline_html(document)

    def test_external_resource_and_script_are_rejected(self):
        prefix = (
            '<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; connect-src \'none\'; img-src data:; '
            'style-src \'unsafe-inline\'; script-src \'none\'; font-src \'none\'; '
            'frame-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">'
        )
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(prefix + '<img src="https://example.invalid/a.png">')
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(prefix + "<script>bad()</script>")

    def test_css_import_and_meta_refresh_are_rejected(self):
        required_csp = (
            '<meta http-equiv="Content-Security-Policy" '
            'content="default-src \'none\'; connect-src \'none\'; img-src data:; '
            'style-src \'unsafe-inline\'; script-src \'none\'; font-src \'none\'; '
            'frame-src \'none\'; object-src \'none\'; base-uri \'none\'; form-action \'none\'">'
        )
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(required_csp + "<style>@import 'local.css';</style>")
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(required_csp + '<meta http-equiv="refresh" content="1">')

    def test_csp_must_be_first_content_inside_head(self):
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html("<html><head></head><body>" + self.CSP + "</body></html>")
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(
                "<html><head><style>body{color:black}</style>"
                + self.CSP
                + "</head><body></body></html>"
            )

    def test_css_escape_namespaced_attributes_and_duplicate_attributes_are_rejected(self):
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(
                "<html><head>"
                + self.CSP
                + r"<style>@\69 mport 'local.css';</style></head><body></body></html>"
            )
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(
                "<html><head>"
                + self.CSP
                + '</head><body><img xlink:href="local.png"></body></html>'
            )
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(
                "<html><head>"
                + self.CSP
                + '</head><body><img src="data:image/png;base64,AA==" src="local.png"></body></html>'
            )
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(
                "<html><head>"
                + self.CSP
                + "<style>body{background:url(data:image/png;base64,AA==)}</style>"
                + "</head><body></body></html>"
            )
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(
                "<html><head>"
                + self.CSP
                + '<style>body{background-image:image-set("relative.png" 1x)}</style>'
                + "</head><body></body></html>"
            )

    def test_duplicate_or_weakened_csp_is_rejected(self):
        duplicate = "<html><head>" + self.CSP + self.CSP + "</head><body></body></html>"
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(duplicate)
        weakened = self.CSP.replace("script-src 'none'", "script-src 'none' https:")
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html("<html><head>" + weakened + "</head><body></body></html>")

        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(
                "<html><head>"
                + self.CSP
                + '</head><body><img src="data:image/svg+xml;base64,AA=="></body></html>'
            )
        with self.assertRaises(OfflineHtmlError):
            validate_offline_html(
                "<html><head>" + self.CSP + "</head><body><!-- hidden --></body></html>"
            )

    def test_document_topology_and_doctype_are_strict(self):
        invalid_documents = (
            "<head>" + self.CSP + "</head><html><body></body></html>",
            "<!doctype html><html><head>"
            + self.CSP
            + "<body></body></head></html>",
            "garbage<!doctype html><html><head>"
            + self.CSP
            + "</head><body></body></html>",
            "<!doctype html><!doctype html><html><head>"
            + self.CSP
            + "</head><body></body></html>",
            "<!doctype html><html><head>"
            + self.CSP
            + "</head><p>outside</p><body></body></html>",
        )
        for document in invalid_documents:
            with self.subTest(document=document):
                with self.assertRaises(OfflineHtmlError):
                    validate_offline_html(document)


if __name__ == "__main__":
    unittest.main()

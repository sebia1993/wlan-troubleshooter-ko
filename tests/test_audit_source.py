from pathlib import Path
import tempfile
import unittest

from scripts import audit_source


class SourceAuditTests(unittest.TestCase):
    def _audit_source(self, source: str, relative: str = "app/sample.py"):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
            return audit_source.audit_tree(root)

    def test_clean_source_passes(self):
        report = self._audit_source(
            "from pathlib import Path\n\nVALUE = Path('capture.bin').name\n"
        )
        self.assertEqual((), report.findings)
        self.assertEqual(1, report.scanned_files)

    def test_forbidden_network_import_fails(self):
        source = "import " + "sock" + "et\n"
        report = self._audit_source(source)
        self.assertIn("FORBIDDEN_IMPORT", {finding.code for finding in report.findings})

    def test_external_url_literal_fails(self):
        scheme = "ht" + "tps"
        separator = ":" + chr(47) + chr(47)
        source = "ENDPOINT = " + repr(scheme + separator + "example.invalid/upload") + "\n"
        report = self._audit_source(source)
        self.assertIn("EXTERNAL_URI", {finding.code for finding in report.findings})

    def test_scheme_without_slashes_unc_and_single_label_network_paths_fail(self):
        source = (
            "A = 'http:example.invalid'\n"
            "B = '//intranet/upload'\n"
            "C = r'\\\\server\\share'\n"
            "import os\nos.startfile(A)\n"
        )
        report = self._audit_source(source)
        codes = {finding.code for finding in report.findings}
        self.assertIn("EXTERNAL_URI", codes)
        self.assertIn("DYNAMIC_EXEC", codes)

    def test_concatenated_external_url_fails(self):
        source = (
            "SCHEME = 'ht' + 'tps'\n"
            "ENDPOINT = SCHEME + ':' + '/' + '/' + 'example.invalid/upload'\n"
        )
        report = self._audit_source(source)
        self.assertIn("EXTERNAL_URI", {finding.code for finding in report.findings})

    def test_joined_external_url_fails(self):
        source = "ENDPOINT = ''.join(['https', '://', 'example.invalid'])\n"
        report = self._audit_source(source)
        self.assertIn("EXTERNAL_URI", {finding.code for finding in report.findings})

    def test_incrementally_concatenated_external_url_fails(self):
        source = "ENDPOINT = 'https'\nENDPOINT += '://example.invalid'\n"
        report = self._audit_source(source)
        self.assertIn("EXTERNAL_URI", {finding.code for finding in report.findings})

    def test_dynamic_execution_fails(self):
        call_name = "ev" + "al"
        report = self._audit_source(call_name + "('1 + 1')\n")
        self.assertIn("DYNAMIC_EXEC", {finding.code for finding in report.findings})

    def test_subprocess_requires_explicit_shell_false(self):
        source = "import subprocess\nsubprocess.run(['tool'])\n"
        report = self._audit_source(source)
        self.assertIn("SHELL_NOT_EXPLICIT", {finding.code for finding in report.findings})

    def test_subprocess_rejects_string_command(self):
        source = "import subprocess\nsubprocess.run('tool --flag', shell=False)\n"
        report = self._audit_source(source)
        self.assertIn("COMMAND_NOT_SEQUENCE", {finding.code for finding in report.findings})

    def test_subprocess_sequence_with_shell_false_is_location_restricted(self):
        source = "import subprocess\nsubprocess.run(['tool', '--flag'], shell=False)\n"
        report = self._audit_source(source)
        codes = {finding.code for finding in report.findings}
        self.assertIn("UNAPPROVED_PROCESS", codes)
        self.assertNotIn("SHELL_ENABLED", codes)
        self.assertNotIn("SHELL_NOT_EXPLICIT", codes)

    def test_exact_repository_git_wrapper_process_location_passes(self):
        source = (
            "import subprocess\n"
            "def _run_git(command):\n"
            "    return subprocess.run(command, shell=False)\n"
        )
        report = self._audit_source(source, "scripts/audit_repository.py")
        self.assertEqual((), report.findings)

    def test_exact_tshark_probe_process_location_passes(self):
        source = (
            "import subprocess\n"
            "def probe_bundle_runtime(command):\n"
            "    return subprocess.Popen(command, shell=False)\n"
        )
        report = self._audit_source(
            source,
            "src/wlan_troubleshooter_ko/tshark/runner.py",
        )
        self.assertEqual((), report.findings)

    def test_network_command_in_argument_sequence_fails(self):
        command = "cu" + "rl"
        source = "import subprocess\nsubprocess.run([" + repr(command) + "], shell=False)\n"
        report = self._audit_source(source)
        self.assertIn("NET_COMMAND", {finding.code for finding in report.findings})

    def test_concatenated_network_command_and_os_exec_fail(self):
        source = (
            "import os\nimport subprocess\n"
            "subprocess.run(['cu' + 'rl', 'input'], shell=False)\n"
            "os.execv('/usr/bin/' + 'tool', ['tool'])\n"
        )
        report = self._audit_source(source)
        codes = {finding.code for finding in report.findings}
        self.assertIn("NET_COMMAND", codes)
        self.assertIn("DYNAMIC_EXEC", codes)

    def test_network_command_in_assigned_sequence_fails(self):
        source = (
            "import subprocess\n"
            "command = ['cu' + 'rl', 'input']\n"
            "runner = subprocess.run\n"
            "runner(command, shell=False)\n"
        )
        report = self._audit_source(source)
        self.assertIn("NET_COMMAND", {finding.code for finding in report.findings})

    def test_runtime_dependency_manifest_fails(self):
        package = "requ" + "ests"
        source = '[project]\ndependencies = ["' + package + '"]\n'
        report = self._audit_source(source, "pyproject.toml")
        self.assertIn("FORBIDDEN_PACKAGE", {finding.code for finding in report.findings})

    def test_aliased_subprocess_cannot_bypass_checks(self):
        source = "import subprocess as child\nchild.run('tool', shell=True)\n"
        report = self._audit_source(source)
        codes = {finding.code for finding in report.findings}
        self.assertIn("SHELL_ENABLED", codes)
        self.assertIn("COMMAND_NOT_SEQUENCE", codes)

    def test_from_import_subprocess_cannot_bypass_checks(self):
        source = "from subprocess import run\nrun(['tool'])\n"
        report = self._audit_source(source)
        self.assertIn("SHELL_NOT_EXPLICIT", {finding.code for finding in report.findings})

    def test_assigned_subprocess_module_alias_cannot_bypass_checks(self):
        source = (
            "import subprocess as child\n"
            "process_module = child\n"
            "process_module.run(['tool'], shell=True)\n"
        )
        report = self._audit_source(source)
        self.assertIn("SHELL_ENABLED", {finding.code for finding in report.findings})

    def test_indirect_subprocess_reference_still_fails_at_import(self):
        source = (
            "import subprocess\n"
            "runner = subprocess.__dict__['run']\n"
            "runner(['tool'], shell=False)\n"
        )
        report = self._audit_source(source)
        self.assertIn(
            "UNAPPROVED_PROCESS_IMPORT", {finding.code for finding in report.findings}
        )

    def test_assigned_subprocess_function_alias_cannot_bypass_checks(self):
        source = (
            "from subprocess import run as imported_run\n"
            "runner = imported_run\n"
            "runner(['tool'], shell=True)\n"
        )
        report = self._audit_source(source)
        self.assertIn("SHELL_ENABLED", {finding.code for finding in report.findings})

    def test_getattr_subprocess_alias_cannot_bypass_checks(self):
        source = (
            "import subprocess as child\n"
            "runner = getattr(child, 'run')\n"
            "runner(['tool'], shell=True)\n"
        )
        report = self._audit_source(source)
        self.assertIn("SHELL_ENABLED", {finding.code for finding in report.findings})

    def test_event_loop_connection_fails(self):
        source = (
            "import asyncio\n"
            "loop = asyncio.get_running_loop()\n"
            "loop.create_connection(lambda: None, 'example.invalid', 443)\n"
        )
        report = self._audit_source(source)
        self.assertIn("NETWORK_CALL", {finding.code for finding in report.findings})

    def test_chained_event_loop_connection_fails(self):
        source = (
            "import asyncio\n"
            "asyncio.get_running_loop().create_connection("
            "lambda: None, 'example.invalid', 443)\n"
        )
        report = self._audit_source(source)
        self.assertIn("NETWORK_CALL", {finding.code for finding in report.findings})

    def test_chained_event_loop_method_alias_fails(self):
        source = (
            "import asyncio\n"
            "connect = asyncio.get_running_loop().create_connection\n"
            "connect(lambda: None, 'example.invalid', 443)\n"
        )
        report = self._audit_source(source)
        self.assertIn("NETWORK_CALL", {finding.code for finding in report.findings})

    def test_aliased_event_loop_server_fails(self):
        source = (
            "import asyncio\n"
            "loop = asyncio.get_event_loop()\n"
            "serve = loop.create_server\n"
            "serve(lambda: None, '127.0.0.1', 8000)\n"
        )
        report = self._audit_source(source)
        self.assertIn("NETWORK_CALL", {finding.code for finding in report.findings})

    def test_html_script_and_external_reference_fail(self):
        scheme = "ht" + "tps"
        separator = ":" + chr(47) + chr(47)
        tag_name = "scr" + "ipt"
        html = (
            "<!doctype html><html><body><"
            + tag_name
            + "></"
            + tag_name
            + ">"
            + '<img src="'
            + scheme
            + separator
            + 'example.invalid/a.png"></body></html>'
        )
        report = self._audit_source(html, "templates/report.html")
        codes = {finding.code for finding in report.findings}
        self.assertIn("HTML_SCRIPT", codes)
        self.assertIn("EXTERNAL_URI", codes)

    def test_generated_html_in_python_string_is_audited(self):
        tag_name = "scr" + "ipt"
        template = "<" + tag_name + "></" + tag_name + ">"
        report = self._audit_source("TEMPLATE = " + repr(template) + "\n")
        self.assertIn("HTML_SCRIPT", {finding.code for finding in report.findings})

    def test_unquoted_relative_html_resource_fails(self):
        html = "<img " + "src=" + "local.png>"
        report = self._audit_source(html, "templates/report.html")
        self.assertIn(
            "HTML_EXTERNAL_ATTRIBUTE", {finding.code for finding in report.findings}
        )

    def test_data_image_and_internal_anchor_pass(self):
        html = '<a href="#detail">Detail</a><img src="data:image/png;base64,AA==">'
        report = self._audit_source(html, "templates/report.html")
        self.assertEqual((), report.findings)

    def test_css_data_url_is_rejected(self):
        css = "body { background: url(data:image/png;base64,AA==); }"
        report = self._audit_source(css, "templates/report.css")
        self.assertIn(
            "HTML_EXTERNAL_CSS_URL", {finding.code for finding in report.findings}
        )

        report = self._audit_source(
            'body { background: image-set("relative.png" 1x); }',
            "templates/report.css",
        )
        self.assertIn(
            "HTML_EXTERNAL_CSS_IMAGE", {finding.code for finding in report.findings}
        )

    def test_same_named_copy_is_not_self_excluded(self):
        source = "import " + "sock" + "et\n"
        report = self._audit_source(source, "scripts/audit_source.py")
        self.assertIn("FORBIDDEN_IMPORT", {finding.code for finding in report.findings})

    def test_only_top_level_test_tree_is_excluded(self):
        source = "import " + "sock" + "et\n"
        top_level = self._audit_source(source, "tests/canary.py")
        nested_runtime = self._audit_source(source, "src/tests/canary.py")
        self.assertEqual((), top_level.findings)
        self.assertIn(
            "FORBIDDEN_IMPORT", {finding.code for finding in nested_runtime.findings}
        )

    def test_build_named_directory_inside_runtime_is_not_excluded(self):
        report = self._audit_source(
            "import socket\n",
            "src/wlan_troubleshooter_ko/build/online.py",
        )
        self.assertEqual(1, report.scanned_files)
        self.assertIn("FORBIDDEN_IMPORT", {finding.code for finding in report.findings})

    def test_python_syntax_error_fails_closed(self):
        report = self._audit_source("def broken(:\n")
        self.assertIn("PYTHON_SYNTAX", {finding.code for finding in report.findings})

    def test_runtime_stdlib_and_own_package_imports_pass(self):
        source = (
            "import tkinter\n"
            "import hashlib\n"
            "from pathlib import Path\n"
            "from wlan_troubleshooter_ko.core import capture\n"
            "from . import sibling\n"
        )
        report = self._audit_source(source, "src/wlan_troubleshooter_ko/sample.py")
        self.assertEqual((), report.findings)

    def test_third_party_runtime_import_fails(self):
        report = self._audit_source(
            "from rich.console import Console\n",
            "src/wlan_troubleshooter_ko/sample.py",
        )
        self.assertIn(
            "UNAPPROVED_RUNTIME_IMPORT", {finding.code for finding in report.findings}
        )

    def test_unreviewed_network_capable_stdlib_imports_fail(self):
        for source in (
            "import antigravity\n",
            "from wsgiref.simple_server import make_server\n",
            "from multiprocessing.connection import Listener\n",
            "import ctypes\n",
        ):
            with self.subTest(source=source):
                report = self._audit_source(
                    source,
                    "src/wlan_troubleshooter_ko/sample.py",
                )
                self.assertIn(
                    "UNAPPROVED_RUNTIME_IMPORT",
                    {finding.code for finding in report.findings},
                )

    def test_asyncio_exec_subprocess_is_forbidden(self):
        report = self._audit_source(
            "import asyncio\n"
            "asyncio.create_subprocess_exec('curl', 'example.invalid')\n",
            "src/wlan_troubleshooter_ko/sample.py",
        )
        codes = {finding.code for finding in report.findings}
        self.assertIn("UNAPPROVED_RUNTIME_IMPORT", codes)
        self.assertIn("DYNAMIC_EXEC", codes)

    def test_approved_files_reject_indirect_subprocess_references(self):
        canary = (
            "import subprocess\n"
            "def probe_bundle_runtime():\n"
            "    runner = subprocess.__dict__['Popen']\n"
            "    return runner(['curl'], shell=True)\n"
        )
        report = self._audit_source(
            canary,
            "src/wlan_troubleshooter_ko/tshark/runner.py",
        )
        self.assertIn(
            "UNAPPROVED_PROCESS_REFERENCE",
            {finding.code for finding in report.findings},
        )

        aliased = (
            "import subprocess\n"
            "def _run_git(command):\n"
            "    runner = subprocess.run\n"
            "    return runner(command, shell=False)\n"
        )
        report = self._audit_source(aliased, "scripts/audit_repository.py")
        codes = {finding.code for finding in report.findings}
        self.assertIn("UNAPPROVED_PROCESS_REFERENCE", codes)
        self.assertIn("UNAPPROVED_PROCESS", codes)

    def test_approved_files_reject_reflective_subprocess_access(self):
        canaries = (
            (
                "src/wlan_troubleshooter_ko/tshark/runner.py",
                "def probe_bundle_runtime(command, member):\n"
                "    return getattr(subprocess, member)(command, shell=False)\n",
            ),
            (
                "scripts/audit_repository.py",
                "def _run_git(command):\n"
                "    return vars(subprocess)['run'](command, shell=False)\n",
            ),
            (
                "src/wlan_troubleshooter_ko/tshark/runner.py",
                "def probe_bundle_runtime(command):\n"
                "    namespace = subprocess.__dict__\n"
                "    return namespace['Popen'](command, shell=False)\n",
            ),
        )
        for relative, body in canaries:
            with self.subTest(relative=relative, body=body):
                report = self._audit_source("import subprocess\n" + body, relative)
                self.assertIn(
                    "UNAPPROVED_PROCESS_REFERENCE",
                    {finding.code for finding in report.findings},
                )

    def test_approved_files_reject_aliased_reflection_builtins(self):
        source = (
            "import subprocess\n"
            "reflect = vars\n"
            "def _run_git(command):\n"
            "    return reflect(subprocess)['run'](command, shell=False)\n"
        )
        report = self._audit_source(source, "scripts/audit_repository.py")
        self.assertIn(
            "UNAPPROVED_PROCESS_REFERENCE",
            {finding.code for finding in report.findings},
        )

    def test_arbitrary_runtime_dependency_fails(self):
        source = '[project]\ndependencies = ["rich>=13"]\n'
        report = self._audit_source(source, "pyproject.toml")
        self.assertIn("RUNTIME_DEPENDENCY", {finding.code for finding in report.findings})

    def test_optional_runtime_dependency_fails(self):
        source = '[project.optional-dependencies]\nanalysis = ["rich>=13"]\n'
        report = self._audit_source(source, "pyproject.toml")
        self.assertIn("RUNTIME_DEPENDENCY", {finding.code for finding in report.findings})

    def test_dynamic_runtime_dependency_fails(self):
        source = '[project]\ndynamic = ["dependencies"]\n'
        report = self._audit_source(source, "pyproject.toml")
        self.assertIn("RUNTIME_DEPENDENCY", {finding.code for finding in report.findings})

    def test_multiline_dynamic_runtime_dependency_fails(self):
        source = '[project]\ndynamic = [\n  "dependencies",\n]\n'
        report = self._audit_source(source, "pyproject.toml")
        self.assertIn("RUNTIME_DEPENDENCY", {finding.code for finding in report.findings})

    def test_dotted_runtime_dependency_key_fails(self):
        source = 'project.dependencies = ["rich>=13"]\n'
        report = self._audit_source(source, "pyproject.toml")
        self.assertIn("RUNTIME_DEPENDENCY", {finding.code for finding in report.findings})

    def test_tool_managed_runtime_dependency_table_fails(self):
        source = '[tool.poetry.dependencies]\nrich = "^13"\n'
        report = self._audit_source(source, "pyproject.toml")
        self.assertIn("RUNTIME_DEPENDENCY", {finding.code for finding in report.findings})

    def test_unicode_escaped_dependency_key_fails_closed(self):
        source = '[project]\n"dependenc\\u0069es" = ["rich>=13"]\n'
        report = self._audit_source(source, "pyproject.toml")
        codes = {finding.code for finding in report.findings}
        if audit_source._tomllib is None:
            self.assertIn("DEPENDENCY_DECLARATION_INVALID", codes)
        else:
            self.assertIn("RUNTIME_DEPENDENCY", codes)

    def test_root_inline_project_dependencies_fail_closed(self):
        source = 'project = { name = "sample", dependencies = ["rich>=13"] }\n'
        report = self._audit_source(source, "pyproject.toml")
        codes = {finding.code for finding in report.findings}
        if audit_source._tomllib is None:
            self.assertIn("DEPENDENCY_DECLARATION_INVALID", codes)
        else:
            self.assertIn("RUNTIME_DEPENDENCY", codes)

    def test_root_inline_tool_dependencies_fail_closed(self):
        source = 'tool = { poetry = { dependencies = { rich = "^13" } } }\n'
        report = self._audit_source(source, "pyproject.toml")
        codes = {finding.code for finding in report.findings}
        if audit_source._tomllib is None:
            self.assertIn("DEPENDENCY_DECLARATION_INVALID", codes)
        else:
            self.assertIn("RUNTIME_DEPENDENCY", codes)

    def test_semantic_dependency_walk_rejects_parsed_inline_shapes(self):
        project_findings = audit_source._semantic_dependency_findings(
            "pyproject.toml",
            {"project": {"dependencies": ["rich>=13"]}},
        )
        tool_findings = audit_source._semantic_dependency_findings(
            "pyproject.toml",
            {"tool": {"poetry": {"dependencies": {"rich": "^13"}}}},
        )
        self.assertIn("RUNTIME_DEPENDENCY", {item.code for item in project_findings})
        self.assertIn("RUNTIME_DEPENDENCY", {item.code for item in tool_findings})

    def test_literal_empty_runtime_dependency_arrays_pass(self):
        source = (
            "[project]\n"
            "dependencies = [\n"
            "]\n"
            "[tool.wlan-troubleshooter-ko]\n"
            "runtime-dependencies = []\n"
        )
        report = self._audit_source(source, "pyproject.toml")
        self.assertEqual((), report.findings)


if __name__ == "__main__":
    unittest.main()

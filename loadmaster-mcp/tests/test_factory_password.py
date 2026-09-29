"""Tests for runtime-only pre-license password handling."""

import io
import os
import unittest
from unittest.mock import patch

from loadmaster_mcp.tools.licensing import _get_factory_password


class FactoryPasswordTests(unittest.TestCase):
    def test_explicit_password_takes_precedence(self):
        with patch.dict(os.environ, {"LM_FACTORY_PASS": "from-env"}):
            self.assertEqual(_get_factory_password("explicit"), "explicit")

    def test_reads_password_from_environment(self):
        with patch.dict(os.environ, {"LM_FACTORY_PASS": "from-secrets"}):
            self.assertEqual(_get_factory_password(), "from-secrets")

    def test_reads_shared_sample_params_environment(self):
        with patch.dict(os.environ, {"Api_Pass": "from-shared-params"}, clear=True):
            self.assertEqual(_get_factory_password(), "from-shared-params")

    def test_prompts_hidden_on_interactive_stdin(self):
        with patch.dict(os.environ, {}, clear=True), patch(
            "loadmaster_mcp.tools.licensing.sys.stdin", io.StringIO()
        ) as stdin, patch(
            "loadmaster_mcp.tools.licensing.getpass.getpass", return_value="prompted"
        ) as prompt:
            stdin.isatty = lambda: True
            self.assertEqual(_get_factory_password(), "prompted")
            prompt.assert_called_once()

    def test_fails_clearly_without_secret_or_terminal(self):
        with patch.dict(os.environ, {}, clear=True), patch(
            "loadmaster_mcp.tools.licensing.sys.stdin", io.StringIO()
        ):
            with self.assertRaisesRegex(RuntimeError, "LM_FACTORY_PASS"):
                _get_factory_password()


if __name__ == "__main__":
    unittest.main()

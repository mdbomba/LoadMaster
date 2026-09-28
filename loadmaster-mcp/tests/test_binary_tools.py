import base64
import hashlib
import json
import unittest
from unittest.mock import patch

from loadmaster_mcp.client import LMBinaryResponse, LMResponse
from loadmaster_mcp.tools import certificates, system
from loadmaster_mcp.tools import waf
from loadmaster_mcp.tools._binary import decode_base64, format_binary_result, validate_base64


class FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def decorator(function):
            self.tools[function.__name__] = function
            return function

        return decorator


class FakeClient:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def execute(self, command, params=None, timeout=None, api_version=None):
        self.calls.append(("execute", command, params, timeout, api_version))
        if self.responses:
            return self.responses.pop(0)
        return LMResponse(200, True, "Command completed ok")

    def download_binary(self, command, params=None, timeout=None):
        self.calls.append(("download", command, params, timeout))
        return self.responses.pop(0)

    def upload_binary(self, command, data, params=None, content_type=None, timeout=None):
        self.calls.append(("upload", command, data, params, content_type, timeout))
        if self.responses:
            return self.responses.pop(0)
        return LMResponse(200, True, "Command completed ok")


class BinaryHelperTests(unittest.TestCase):
    def test_round_trip_preserves_every_byte_value(self):
        raw = bytes(range(256)) + b"\x00\xffarchive"
        encoded = base64.b64encode(raw).decode()
        self.assertEqual(decode_base64(encoded), raw)

        result = json.loads(format_binary_result(encoded, "backup.bin"))
        self.assertEqual(result["data"], encoded)
        self.assertEqual(result["size"], len(raw))
        self.assertEqual(result["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(result["filename"], "backup.bin")

    def test_invalid_and_empty_base64_are_rejected(self):
        for value in ("", "not base64!", "YWJj="):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    validate_base64(value)


class SystemToolTests(unittest.TestCase):
    def setUp(self):
        self.mcp = FakeMCP()
        system.register(self.mcp)

    def test_backup_output_can_feed_restore(self):
        raw = b"\x1f\x8b\x00LoadMaster backup\xff"
        encoded = base64.b64encode(raw).decode()
        backup_response = LMResponse(200, True, "Command completed ok", {"data": encoded})
        client = FakeClient([backup_response, LMResponse(200, True, "Command completed ok")])

        with patch.object(system, "require_client", return_value=client):
            backup_result = json.loads(self.mcp.tools["lm_backup"]())
            restore_result = self.mcp.tools["lm_restore"](
                backup_result["data"], 15, True
            )

        self.assertEqual(restore_result, "Success (code 200)")
        self.assertEqual(client.calls[0], ("execute", "backup", None, None, 2))
        self.assertEqual(
            client.calls[1],
            ("execute", "restore", {"type": 15, "data": encoded}, None, 2),
        )

    def test_restore_rejects_invalid_data_and_scope_before_client_access(self):
        with patch.object(system, "require_client") as require_client:
            self.assertIn(
                "restore_type", self.mcp.tools["lm_restore"]("YWJj", 0, True)
            )
            self.assertIn(
                "confirm_restore", self.mcp.tools["lm_restore"]("YWJj", 1, False)
            )
            self.assertIn(
                "valid base64", self.mcp.tools["lm_restore"]("bad!", 1, True)
            )
        require_client.assert_not_called()

    def test_api_v1_backup_and_restore_preserve_exact_bytes(self):
        raw = b"\x00\xffLoadMaster v1 archive"
        client = FakeClient([
            LMBinaryResponse(200, True, "ok", raw, "LMBackups_lm1"),
            LMResponse(200, True, "Command completed ok"),
        ])

        with patch.object(system, "require_client", return_value=client):
            result = json.loads(self.mcp.tools["lm_backup"](1))
            restore_result = self.mcp.tools["lm_restore"](
                result["data"], 15, True, 1
            )

        self.assertEqual(result["filename"], "LMBackups_lm1")
        self.assertEqual(restore_result, "Success (code 200)")
        self.assertEqual(client.calls[0], ("download", "backup", None, None))
        self.assertEqual(
            client.calls[1],
            (
                "upload",
                "restore",
                raw,
                {"type": 15},
                "application/octet-stream",
                None,
            ),
        )


class CertificateToolTests(unittest.TestCase):
    def setUp(self):
        self.mcp = FakeMCP()
        certificates.register(self.mcp)

    def test_certificate_backup_and_restore_request_shapes(self):
        encoded = base64.b64encode(b"certificate archive").decode()
        client = FakeClient([
            LMResponse(200, True, "Command completed ok", {"data": encoded}),
            LMResponse(200, True, "Command completed ok"),
        ])

        with patch.object(certificates, "require_client", return_value=client):
            backup_result = json.loads(
                self.mcp.tools["lm_backup_certificates"]("Secret123")
            )
            result = self.mcp.tools["lm_restore_certificates"](
                backup_result["data"], "Secret123", "full", True
            )

        self.assertEqual(result, "Success (code 200)")
        self.assertEqual(
            client.calls,
            [
                ("execute", "backupcert", {"password": "Secret123"}, 60, 2),
                (
                    "execute",
                    "restorecert",
                    {"password": "Secret123", "type": "full", "data": encoded},
                    60,
                    2,
                ),
            ],
        )

    def test_certificate_restore_validates_before_client_access(self):
        restore = self.mcp.tools["lm_restore_certificates"]
        backup = self.mcp.tools["lm_backup_certificates"]
        with patch.object(certificates, "require_client") as require_client:
            self.assertIn("one of", restore("YWJj", "Secret123", "all", True))
            self.assertIn(
                "confirm_restore", restore("YWJj", "Secret123", "full", False)
            )
            self.assertIn("7-64", restore("YWJj", "bad!", "full", True))
            self.assertIn("7-64", backup("short"))
        require_client.assert_not_called()

    def test_certificate_upload_uses_base64_api_v2_data(self):
        encoded = base64.b64encode(b"certificate bytes").decode()
        client = FakeClient()
        with patch.object(certificates, "require_client", return_value=client):
            result = self.mcp.tools["lm_add_certificate"](
                "web-cert",
                encoded,
                password="bundlepass",
                replace=True,
            )

        self.assertEqual(result, "Success (code 200)")
        self.assertEqual(
            client.calls[0],
            (
                "execute",
                "addcert",
                {
                    "cert": "web-cert",
                    "data": encoded,
                    "replace": "1",
                    "password": "bundlepass",
                },
                60,
                2,
            ),
        )

    def test_api_v1_certificate_upload_decodes_exact_bytes(self):
        raw = b"\x00\xffPKCS12 certificate bytes"
        encoded = base64.b64encode(raw).decode()
        client = FakeClient()
        with patch.object(certificates, "require_client", return_value=client):
            result = self.mcp.tools["lm_add_certificate"](
                "web-cert", encoded, "p12", "bundlepass", True, 1
            )

        self.assertEqual(result, "Success (code 200)")
        self.assertEqual(
            client.calls[0],
            (
                "upload",
                "addcert",
                raw,
                {"cert": "web-cert", "replace": 1, "password": "bundlepass"},
                "application/octet-stream",
                60,
            ),
        )

    def test_api_v1_certificate_restore_decodes_exact_bytes(self):
        raw = b"\x00\xffcertificate archive"
        encoded = base64.b64encode(raw).decode()
        client = FakeClient()
        with patch.object(certificates, "require_client", return_value=client):
            result = self.mcp.tools["lm_restore_certificates"](
                encoded, "Secret123", "third", True, 1
            )

        self.assertEqual(result, "Success (code 200)")
        self.assertEqual(
            client.calls[0],
            (
                "upload",
                "restorecert",
                raw,
                {"password": "Secret123", "type": "third"},
                "application/octet-stream",
                60,
            ),
        )


class WafCompatibilityTests(unittest.TestCase):
    def test_deprecated_rules_data_is_rejected_before_client_access(self):
        mcp = FakeMCP()
        waf.register(mcp)
        with patch.object(waf, "require_client") as require_client:
            result = mcp.tools["lm_waf_install_rules"]("old-upload-data")
        self.assertIn("no longer accepted", result)
        require_client.assert_not_called()


if __name__ == "__main__":
    unittest.main()

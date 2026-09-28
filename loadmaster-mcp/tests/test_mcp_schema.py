import asyncio
import unittest

from loadmaster_mcp.server import mcp


class McpSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tools = asyncio.run(mcp.list_tools())
        cls.schemas = {tool.name: tool.inputSchema for tool in tools}

    def test_configuration_restore_schema_requires_confirmation_and_scope(self):
        schema = self.schemas["lm_restore"]
        self.assertIn("confirm_restore", schema["required"])
        restore_type = schema["properties"]["restore_type"]
        self.assertEqual(restore_type["minimum"], 1)
        self.assertEqual(restore_type["maximum"], 15)
        self.assertEqual(schema["properties"]["api_version"]["enum"], [1, 2])

    def test_certificate_restore_schema_exposes_constraints(self):
        schema = self.schemas["lm_restore_certificates"]
        self.assertIn("confirm_restore", schema["required"])
        self.assertEqual(
            schema["properties"]["restore_type"]["enum"],
            ["full", "third", "vs"],
        )
        password = schema["properties"]["password"]
        self.assertEqual(password["minLength"], 7)
        self.assertEqual(password["maxLength"], 64)
        self.assertEqual(password["pattern"], "^[A-Za-z0-9]+$")

    def test_waf_schema_retains_deprecated_argument(self):
        schema = self.schemas["lm_waf_install_rules"]
        self.assertIn("rules_data", schema["properties"])
        self.assertEqual(schema["properties"]["rules_data"]["default"], "")


if __name__ == "__main__":
    unittest.main()

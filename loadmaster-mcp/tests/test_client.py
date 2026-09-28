import json
import unittest

import httpx

from loadmaster_mcp.client import LoadMasterClient, parse_lm_json, parse_lm_response


SUCCESS_XML = b'<?xml version="1.0"?><Response stat="200" code="ok"><Success>Command completed ok</Success></Response>'


class ClientTests(unittest.TestCase):
    def test_api_v2_is_default_and_uses_api_key_in_json(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"code": 200, "hostname": "lm1", "status": "ok"})

        client = LoadMasterClient("lm.example", api_key="key-value", transport=httpx.MockTransport(handler))
        response = client.execute("get", params={"param": "hostname"})

        self.assertTrue(response.success)
        self.assertEqual(response.data, {"hostname": "lm1"})
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0].method, "POST")
        self.assertEqual(requests[0].url.path, "/accessv2")
        self.assertNotIn("authorization", requests[0].headers)
        self.assertEqual(
            json.loads(requests[0].content),
            {"cmd": "get", "apikey": "key-value", "param": "hostname"},
        )

    def test_api_v2_uses_username_and_password_in_json(self):
        def handler(request):
            self.assertEqual(
                json.loads(request.content),
                {"cmd": "listapi", "apiuser": "bal", "apipass": "secret"},
            )
            return httpx.Response(200, json={"code": 200, "commands": [], "status": "ok"})

        client = LoadMasterClient(
            "lm.example",
            username="bal",
            password="secret",
            transport=httpx.MockTransport(handler),
        )
        self.assertTrue(client.execute("listapi").success)

    def test_prelicense_command_uses_api_v1_and_encodes_query(self):
        def handler(request):
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.url.path, "/access/accepteula")
            self.assertEqual(request.url.params["magic"], "a&b=c")
            self.assertEqual(request.url.params["apikey"], "key/value")
            self.assertNotIn("authorization", request.headers)
            return httpx.Response(200, content=SUCCESS_XML)

        client = LoadMasterClient(
            "lm.example",
            api_key="key/value",
            transport=httpx.MockTransport(handler),
        )
        self.assertTrue(client.execute("accepteula", params={"magic": "a&b=c"}).success)

    def test_binary_download_preserves_arbitrary_bytes(self):
        archive = b"\x1f\x8b\x08\x00\x00\xff\x80\x00backup\x00"

        def handler(request):
            return httpx.Response(
                200,
                content=archive,
                headers={
                    "Content-Type": "application/octet-stream",
                    "Content-Disposition": 'inline; filename="LMBackups_lm1"',
                },
            )

        client = LoadMasterClient("lm.example", api_key="key", transport=httpx.MockTransport(handler))
        response = client.download_binary("backup")

        self.assertTrue(response.success)
        self.assertEqual(response.content, archive)
        self.assertEqual(response.filename, "LMBackups_lm1")

    def test_binary_upload_decodes_nothing_and_includes_scope(self):
        archive = b"\x00\xfforiginal archive bytes"

        def handler(request):
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.url.path, "/access/restore")
            self.assertEqual(request.url.params["type"], "15")
            self.assertEqual(request.url.params["apikey"], "key")
            self.assertEqual(request.content, archive)
            return httpx.Response(200, content=SUCCESS_XML)

        client = LoadMasterClient("lm.example", api_key="key", transport=httpx.MockTransport(handler))
        response = client.upload_binary("restore", archive, params={"type": 15})
        self.assertTrue(response.success)

    def test_xml_parser_uses_stat_attribute(self):
        response = parse_lm_response(SUCCESS_XML.decode(), 200)
        self.assertTrue(response.success)
        self.assertEqual(response.status_code, 200)

    def test_json_parser_reports_failure(self):
        response = parse_lm_json('{"code":422,"message":"bad type","status":"fail"}', 422)
        self.assertFalse(response.success)
        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.message, "bad type")

    def test_use_api_v1_flag_forces_v1_for_every_command(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, content=SUCCESS_XML)

        client = LoadMasterClient(
            "lm.example",
            api_key="key",
            transport=httpx.MockTransport(handler),
            use_api_v1=True,
        )
        # get is normally APIv2, but the flag must force v1 for pre-license use.
        self.assertTrue(client.get("get", param="version").success)
        self.assertEqual(requests[0].url.path, "/access/get")
        self.assertTrue(client.execute("alsilicensetypes").success)
        self.assertTrue(all(r.url.path.startswith("/access/") for r in requests))

    def test_addcert_v2_sends_encoded_bundle_and_password(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"code": 200, "status": "ok"})

        client = LoadMasterClient("lm.example", api_key="key", transport=httpx.MockTransport(handler))
        self.assertTrue(client.execute("addcert", params={
            "cert": "vlm99",
            "password": "pfx-password",
            "replace": "0",
            "data": "Y2VydGlmaWNhdGU=",
        }).success)
        payload = json.loads(requests[0].content)
        self.assertEqual(requests[0].url.path, "/accessv2")
        self.assertEqual(payload["data"], "Y2VydGlmaWNhdGU=")
        self.assertEqual(payload["password"], "pfx-password")
        self.assertEqual(payload["apikey"], "key")


if __name__ == "__main__":
    unittest.main()

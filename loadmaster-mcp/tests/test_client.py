import json
import unittest
from unittest.mock import patch

import httpx

from loadmaster_mcp.client import LoadMasterClient, parse_lm_json_response, parse_lm_response
from loadmaster_mcp.tools.licensing import _make_prelicense_client, _select_license_type
from loadmaster_mcp.tools.certificates import _decode_base64 as decode_certificate
from loadmaster_mcp.tools.real_servers import _rs_selector
from loadmaster_mcp.tools.virtual_services import _vs_selector


class _MockClient:
    def __init__(self, handler):
        self.handler = handler

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def post(self, url, **kwargs):
        request = httpx.Request("POST", url, headers=kwargs.get("headers"), content=json.dumps(kwargs.get("json", {})))
        return self.handler(request)

    def get(self, url, **kwargs):
        request = httpx.Request("GET", url, params=kwargs.get("params"))
        return self.handler(request)


class LoadMasterClientTests(unittest.TestCase):
    def test_v2_uses_json_post_and_preserves_special_characters(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"code": 200, "status": "ok"})

        with patch("loadmaster_mcp.client.httpx.Client", return_value=_MockClient(handler)):
            response = LoadMasterClient("loadmaster", username="bal", password="a&b").execute(
                "modvs", {"CheckUrl": "/health?full=true&region=us"}
            )

        self.assertTrue(response.success)
        self.assertEqual(requests[0].url.path, "/accessv2")
        payload = json.loads(requests[0].content)
        self.assertEqual(payload["CheckUrl"], "/health?full=true&region=us")
        self.assertEqual(payload["apipass"], "a&b")

    def test_v1_encodes_query_parameters(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, text='<Response code="200"><Success /></Response>')

        with patch("loadmaster_mcp.client.httpx.Client", return_value=_MockClient(handler)):
            LoadMasterClient("loadmaster", use_api_v1=True).get("get", value="a&b")

        self.assertEqual(requests[0].url.params["value"], "a&b")

    def test_http_and_api_errors_are_failures(self):
        self.assertFalse(parse_lm_response('<Response code="401"><Success /></Response>').success)
        self.assertFalse(parse_lm_json_response('{"code": 401, "message": "Unauthorized"}', 200).success)

    def test_certificate_data_must_be_base64(self):
        self.assertEqual(decode_certificate("Y2VydGlmaWNhdGU="), b"certificate")
        with self.assertRaises(ValueError):
            decode_certificate("not base64!")

    def test_v2_certificate_upload_preserves_base64_bundle_and_password(self):
        requests = []

        def handler(request):
            requests.append(request)
            return httpx.Response(200, json={"code": 200, "status": "ok"})

        with patch("loadmaster_mcp.client.httpx.Client", return_value=_MockClient(handler)):
            response = LoadMasterClient("loadmaster", api_key="temporary-key").execute(
                "addcert",
                {
                    "cert": "vlm99",
                    "password": "pfx-password",
                    "replace": "0",
                    "data": "Y2VydGlmaWNhdGU=",
                },
            )

        self.assertTrue(response.success)
        self.assertEqual(requests[0].url.path, "/accessv2")
        payload = json.loads(requests[0].content)
        self.assertEqual(payload["data"], "Y2VydGlmaWNhdGU=")
        self.assertEqual(payload["password"], "pfx-password")
        self.assertEqual(payload["apikey"], "temporary-key")

    def test_resource_selectors_require_complete_identity(self):
        self.assertEqual(_vs_selector("", "", "", "12"), {"vs": "12"})
        self.assertEqual(
            _rs_selector("10.0.0.1", "443", "tcp", "", "10.0.0.2", "8443"),
            {"vs": "10.0.0.1", "port": "443", "prot": "tcp", "rs": "10.0.0.2", "rsport": "8443"},
        )
        with self.assertRaises(ValueError):
            _vs_selector("10.0.0.1", "", "tcp", "")
        with self.assertRaises(ValueError):
            _rs_selector("", "", "", "", "10.0.0.2", "8443")

    def test_prelicense_client_uses_api_v1(self):
        with patch("loadmaster_mcp.tools.licensing.require_client", return_value=LoadMasterClient("loadmaster")):
            self.assertTrue(_make_prelicense_client().use_api_v1)

    def test_license_type_selection_distinguishes_free_trial_and_paid(self):
        response = json.dumps({"categories": [{"licenseTypes": [
            {"id": "free-id", "description": "Free LoadMaster", "free": True},
            {"id": "trial-id", "description": "Trial License"},
            {"id": "paid-id", "description": "Enterprise License"},
        ]}]})
        self.assertEqual(_select_license_type(response, "free"), "free-id")
        self.assertEqual(_select_license_type(response, "trial"), "trial-id")
        self.assertEqual(_select_license_type(response, "paid"), "paid-id")


if __name__ == "__main__":
    unittest.main()

# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import types
import unittest
from unittest import mock


class _ActionResult:
    def __init__(self, parameters=None):
        self.parameters = parameters or {}
        self.status = True

    def set_status(self, status, _message=None):
        self.status = status
        return status


class _BaseConnector:
    def __init__(self):
        self._asset_id = "asset-id"

    def get_asset_id(self):
        return self._asset_id

    def debug_print(self, *_args):
        pass

    def save_progress(self, *_args):
        pass

    def _get_error_message_from_exception(self, exc):
        return str(exc)


phantom = types.ModuleType("phantom")
phantom_app = types.ModuleType("phantom.app")
phantom_app.APP_SUCCESS = True
phantom_app.APP_ERROR = False
phantom_app.is_fail = lambda value: value is False
phantom_action_result = types.ModuleType("phantom.action_result")
phantom_action_result.ActionResult = _ActionResult
phantom_base_connector = types.ModuleType("phantom.base_connector")
phantom_base_connector.BaseConnector = _BaseConnector
encryption_helper = types.ModuleType("encryption_helper")
encryption_helper.encrypt = lambda value, salt: f"encrypted:{salt}:{value}"
encryption_helper.decrypt = lambda value, salt: value.removeprefix(f"encrypted:{salt}:")
requests = types.ModuleType("requests")
requests.get = lambda *_args, **_kwargs: None
bs4 = types.ModuleType("bs4")
bs4.BeautifulSoup = object

sys.modules.setdefault("phantom", phantom)
sys.modules.setdefault("phantom.app", phantom_app)
sys.modules.setdefault("phantom.action_result", phantom_action_result)
sys.modules.setdefault("phantom.base_connector", phantom_base_connector)
sys.modules.setdefault("encryption_helper", encryption_helper)
sys.modules.setdefault("requests", requests)
sys.modules.setdefault("bs4", bs4)

from sophosendpointprotection_connector import SophosEndpointProtectionConnector
from sophosendpointprotection_consts import (
    SOPHOS_JWT_JSON,
    SOPHOS_JWT_TOKEN,
    SOPHOS_JWT_TOKEN_IS_ENCRYPTED,
)


class SecurityTests(unittest.TestCase):
    def test_accepts_only_documented_sophos_api_origins(self):
        valid = (
            "https://api.central.sophos.com",
            "https://api-us03.central.sophos.com",
            "https://API-EU01.CENTRAL.SOPHOS.COM/",
        )
        invalid = (
            None,
            "http://api.central.sophos.com",
            "https://api.central.sophos.com.evil.example",
            "https://api.central.sophos.com:443",
            "https://user@api.central.sophos.com",
            "https://api.central.sophos.com/path",
            "https://api.central.sophos.com?next=https://evil.example",
            "https://central.sophos.com",
        )

        for value in valid:
            self.assertIsNotNone(SophosEndpointProtectionConnector._validate_api_host(value))
        for value in invalid:
            self.assertIsNone(SophosEndpointProtectionConnector._validate_api_host(value))

    def test_rejects_invalid_whoami_shapes(self):
        connector = SophosEndpointProtectionConnector()
        self.assertIsNone(connector._select_api_host(None))
        self.assertIsNone(connector._select_api_host({"idType": "tenant", "apiHosts": "invalid"}))
        self.assertIsNone(connector._select_api_host({"idType": "unexpected", "apiHosts": {"global": "https://api.central.sophos.com"}}))

    def test_path_identifiers_are_encoded_as_single_segments(self):
        self.assertEqual(SophosEndpointProtectionConnector._quote_path_identifier("../sites/1"), "..%2Fsites%2F1")
        self.assertEqual(SophosEndpointProtectionConnector._quote_path_identifier("a?b#c"), "a%3Fb%23c")

    def test_legacy_plaintext_jwt_is_migrated_to_encrypted_state(self):
        connector = SophosEndpointProtectionConnector()
        connector._state = {SOPHOS_JWT_JSON: {SOPHOS_JWT_TOKEN: "plaintext-token", "expires_in": 3600}}

        connector._load_jwt_from_state()

        self.assertEqual(connector._JWT_token, "plaintext-token")
        self.assertEqual(connector._state[SOPHOS_JWT_JSON][SOPHOS_JWT_TOKEN], "encrypted:asset-id:plaintext-token")
        self.assertTrue(connector._state[SOPHOS_JWT_TOKEN_IS_ENCRYPTED])

    def test_undecryptable_jwt_is_discarded(self):
        connector = SophosEndpointProtectionConnector()
        connector._state = {
            SOPHOS_JWT_JSON: {SOPHOS_JWT_TOKEN: "corrupt"},
            SOPHOS_JWT_TOKEN_IS_ENCRYPTED: True,
        }

        with mock.patch("sophosendpointprotection_connector.encryption_helper.decrypt", side_effect=ValueError("bad ciphertext")):
            connector._load_jwt_from_state()

        self.assertIsNone(connector._JWT_token)
        self.assertNotIn(SOPHOS_JWT_JSON, connector._state)
        self.assertNotIn(SOPHOS_JWT_TOKEN_IS_ENCRYPTED, connector._state)

    def test_rest_calls_do_not_follow_redirects(self):
        connector = SophosEndpointProtectionConnector()
        action_result = _ActionResult()
        response = object()

        with (
            mock.patch("sophosendpointprotection_connector.requests.get", return_value=response) as request,
            mock.patch.object(connector, "_process_response", return_value=(True, {})),
        ):
            connector._make_rest_call("https://api.central.sophos.com/test", action_result)

        request.assert_called_once_with(
            "https://api.central.sophos.com/test",
            json=None,
            data=None,
            headers=None,
            params=None,
            allow_redirects=False,
        )

    def test_sensitive_responses_are_not_added_to_debug_data(self):
        connector = SophosEndpointProtectionConnector()
        action_result = mock.Mock()
        response = mock.Mock(headers={"Content-Type": "application/json"}, status_code=200)
        response.json.return_value = {"access_token": "secret"}

        connector._process_response(response, action_result, sensitive=True)

        action_result.add_debug_data.assert_not_called()

    def test_whoami_requires_nonempty_identity(self):
        connector = SophosEndpointProtectionConnector()
        connector._JWT_token = "token"
        connector._state = {}
        action_result = _ActionResult()
        token_response = {"access_token": "token"}
        invalid_whoami = {
            "idType": "tenant",
            "apiHosts": {"dataRegion": "https://api-us03.central.sophos.com"},
        }

        with (
            mock.patch.object(connector, "_make_rest_call", side_effect=[(True, token_response), (True, invalid_whoami)]),
            mock.patch.object(connector, "_store_encrypted_jwt", return_value=True),
        ):
            status = connector._get_token(action_result)

        self.assertFalse(status)
        self.assertIsNone(connector._base_url)
        self.assertNotIn("pt_json", connector._state)


if __name__ == "__main__":
    unittest.main()

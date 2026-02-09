import pathlib
import subprocess
import time
import httpx
import pytest
import os
from unittest import mock
from tempfile import NamedTemporaryFile

from dss_sdk import credentials, utilities, exceptions

env_vars = utilities.EnvironmentVariables

class TestProviders:

    @pytest.mark.parametrize(["env", "can_resolve", "is_windows"], [
        ({}, False, False),
        ({env_vars.TENANT_ID.value: "test", env_vars.CLIENT_ID.value: "test", env_vars.CLIENT_SECRET.value: "test"}, True, False),
        ({}, False, True),
        ({env_vars.TENANT_ID.value: "test", env_vars.CLIENT_ID.value: "test", env_vars.CLIENT_SECRET.value: "test"}, True, True),
        ({env_vars.WINDOWS_CREDENTIAL.value: "test"}, False, True),
        ({env_vars.TENANT_ID.value: "test", env_vars.WINDOWS_CREDENTIAL.value: "test"}, True, True),
    ])
    @mock.patch("dss_sdk.credentials.Windows")
    @mock.patch("dss_sdk.credentials.platform")
    def test_environment_provider(self, mock_plat: mock.MagicMock, mock_win: mock.MagicMock, env: dict, can_resolve: bool, is_windows: bool):
        mock_plat.platform.return_value = "Windows" if is_windows else "Test"
        mock_win.get_from_windows_credential.return_value = ("test", "test")
        environ = mock.patch.dict(os.environ, env, clear=True)
        environ.start()

        provider = credentials.EnvironmentProvider()
        assert provider.resolveable == can_resolve
        assert provider.tenant_id == env.get(env_vars.TENANT_ID.value, "")
        assert provider.client_id == env.get(env_vars.CLIENT_ID.value, "")
        assert provider.client_secret == env.get(env_vars.CLIENT_SECRET.value, "")
        assert provider.api_token == env.get(env_vars.API_TOKEN.value, "")
        assert provider.win_cred == env.get(env_vars.WINDOWS_CREDENTIAL.value, "")
        grant = provider.client_grant()
        if provider.resolveable:
            assert grant
            assert grant["grant_type"] == "client_credentials"
            assert grant["scope"] == "xpmheadless"
            assert grant["client_id"] == "test"
            assert grant["client_secret"] == "test"
        else:
            assert not grant
        environ.stop()

    @pytest.mark.parametrize(["config", "can_resolve", "is_windows"], [
        ({}, False, False),
        ({"tenant_id": "test", "client_id": "test", "client_secret": "test"}, True, False),
        ({"tenant_id": "test"}, False, True),
        ({"tenant_id": "test", "win_cred": "test"}, True, True),
    ])
    @mock.patch("dss_sdk.credentials.Windows")
    @mock.patch("dss_sdk.credentials.platform")
    def test_cred_file_provider(self, mock_plat: mock.MagicMock, mock_win: mock.MagicMock, config: dict, can_resolve: bool, is_windows: bool):
        mock_plat.platform.return_value = "Windows" if is_windows else "Test"
        mock_win.get_from_windows_credential.return_value = ("test", "test")
        mock_cred_file = NamedTemporaryFile(mode="wt", delete=False)

        with mock.patch("dss_sdk.credentials.CredFileProvider.cred_file", pathlib.Path(mock_cred_file.name)):
            if config:
                credentials.CredFileProvider.write_file({"default": config})
            provider = credentials.CredFileProvider()
            assert provider.resolveable == can_resolve
            assert provider.tenant_id == config.get("tenant_id", "")
            assert provider.client_id == config.get("client_id", "")
            assert provider.client_secret == config.get("client_secret", "")
            assert provider.api_token == config.get("api_token", "")
            assert provider.win_cred == config.get("win_cred", "")
            grant = provider.client_grant()
            if provider.resolveable:
                assert grant
                assert grant["grant_type"] == "client_credentials"
                assert grant["scope"] == "xpmheadless"
                assert grant["client_id"] == "test"
                assert grant["client_secret"] == "test"
            else:
                assert not grant
            credentials.CredFileProvider.cred_file.unlink()


class TestProviderChain:
    def test_no_credentials(self):
        with pytest.raises(exceptions.NoCredentialsFoundError):
            credentials.ProviderChain(profile="test").resolve()

    @pytest.mark.parametrize(["endpoint"], [("https://example.test",), ("https://example.test/",)])
    @mock.patch("dss_sdk.credentials.httpx")
    @mock.patch("dss_sdk.credentials.pathlib")
    def test_resolve_api_token(self, mock_pathlib: mock.MagicMock, mock_httpx: mock.MagicMock, endpoint: str):
        mock_response = mock.MagicMock()
        mock_response.content = f'"{endpoint}"'.encode()

        mock_client: mock.MagicMock = mock_httpx.Client.return_value
        mock_client.get.return_value = mock_response

        mock_provider_bad = mock.MagicMock()
        mock_provider_bad.api_token = ""
        mock_provider_bad.resolveable = False

        mock_provider_good = mock.MagicMock()
        mock_provider_good.api_token = "test"

        mock_cache = NamedTemporaryFile(mode="wt", delete=False)
        with mock.patch("dss_sdk.credentials.ProviderChain._cache_", pathlib.Path(mock_cache.name)):
            pathlib.Path(mock_cache.name).unlink()

            provider_chain = credentials.ProviderChain(profile="test")
            provider_chain.providers = [mock_provider_bad, mock_provider_good]
            token, endpoint = provider_chain.resolve()
            assert token == "test"
            assert endpoint == "https://example.test"

    @mock.patch("dss_sdk.credentials.httpx")
    @mock.patch("dss_sdk.credentials.pathlib")
    def test_resolve_client_credentials(self, mock_pathlib: mock.MagicMock, mock_httpx: mock.MagicMock):
        mock_endpoint_response = mock.MagicMock()
        mock_endpoint_response.content = f'"https://example.test/"'.encode()

        mock_token_response = mock.MagicMock()
        mock_token_response.json.side_effect = [
            {
                "expires_in": 0,
                "session_expires_in": 0,
                "access_token": "test",
                "refresh_token": "test",
            },
            {
                "expires_in": 5,
                "session_expires_in": 10,
                "access_token": "test",
                "refresh_token": "test",
            },
            {
                "expires_in": 10,
                "session_expires_in": 10,
                "access_token": "test",
                "refresh_token": "test",
            },
        ]

        mock_client: mock.MagicMock = mock_httpx.Client.return_value
        mock_client.get.return_value = mock_endpoint_response
        mock_client.post.return_value = mock_token_response

        mock_provider = mock.MagicMock()
        mock_provider.api_token = ""
        mock_provider.resolveable = True
        mock_provider.tenant_id = "test"
        mock_provider.clien_id = "test"
        mock_provider.client_secret = "test"

        mock_cache = NamedTemporaryFile(mode="wt", delete=False)
        with mock.patch("dss_sdk.credentials.ProviderChain._cache_", pathlib.Path(mock_cache.name)):
            pathlib.Path(mock_cache.name).unlink()

            provider_chain = credentials.ProviderChain(profile="test")
            provider_chain.providers.insert(0, mock_provider)
            token, endpoint = provider_chain.resolve() # Initially set
            assert token == "test"
            assert endpoint == "https://example.test"
            token, endpoint = provider_chain.resolve() # session expired (new http get)
            assert token == "test"
            assert endpoint == "https://example.test"
            token, endpoint = provider_chain.resolve() # pulled from cache
            assert token == "test"
            assert endpoint == "https://example.test"
            token, endpoint = provider_chain.resolve() # refreshed token
            assert token == "test"
            assert endpoint == "https://example.test"

    @pytest.mark.parametrize(["json_data"], [(b"",), ({"error": "test"},)])
    @mock.patch("dss_sdk.credentials.httpx.Client")
    def test_access_token_exceptions(self, mock_client: mock.MagicMock, json_data):
        mock_client.return_value.post.return_value = httpx.Response(status_code=400, request=httpx.Request(method="POST", url="https://blah.test"))

        mock_provider = mock.MagicMock()
        mock_provider.api_token = ""
        mock_provider.resolveable = True
        mock_provider.tenant_id = "test"
        mock_provider.clien_id = "test"
        mock_provider.client_secret = "test"

        with pytest.raises(exceptions.ClientTokenGrantError):
            provider_chain = credentials.ProviderChain(profile="test")
            provider_chain.providers.insert(0, mock_provider)
            provider_chain.resolve()


class TestPowershell:
    @pytest.mark.parametrize(["method", "kwargs", "expected"], [
        ("find_all_by_resource", {"name": "test", "save_as": "test", "select_first": False}, "$test = $vault.FindAllByResource('test')"),
        ("find_all_by_resource", {"name": "test", "save_as": "test"}, "$test = $vault.FindAllByResource('test') | select -First 1"),
        ("retrieve_password", {"from_var": "test"}, "$test.retrievePassword()"),
        ("retrieve_cred", {"from_var": "test", "save_as": "test"}, "$test = $vault.Retrieve($test.resource, $test.username)"),
        ("remove_cred", {"var": "test"}, "$vault.Remove($test)"),
        ("access_property", {"var": "test", "prop": "test"}, "$test.test"),
        (
            "create_credential",
            {"name": "test", "username": "test-user", "password": "test-password", "save_as": "test"},
            "$test = New-Object Windows.Security.Credentials.PasswordCredential('test', 'test-user', 'test-password')",
        ),
        ("add_cred", {"var": "test"}, "$vault.Add($test)"),
    ])
    def test_all(self, method: str, kwargs: dict, expected: str):
        pwsh: credentials.Powershell = getattr(credentials.Powershell(), method)(**kwargs)
        assert pwsh.__commands__[1] == expected
        assert pwsh.command
        assert pwsh.import_and_create_password_vault in pwsh.command


class TestWindows:
    @pytest.mark.parametrize(["output", "expected_client_id", "expected_client_secret"], [
        (b"Test Exception", "", ""),
        (b"test\ntest\nextra", "test", "test")
    ])
    @mock.patch("dss_sdk.credentials.subprocess.check_output")
    def test_get_from_windows_credential(self, mock_check_output: mock.MagicMock, output, expected_client_id, expected_client_secret):
        mock_check_output.return_value = output
        client_id, client_secret = credentials.Windows.get_from_windows_credential(name="test")
        assert client_id == expected_client_id
        assert client_secret == expected_client_secret

    @pytest.mark.parametrize(["output", "exception"], [
        (b"Test Exception", True),
        (b"test\ntest\nextra", False)
    ])
    @mock.patch("dss_sdk.credentials.subprocess.check_output")
    def test_delete_credential(self, mock_check_output: mock.MagicMock, output, exception):
        mock_check_output.return_value = output

        if exception:
            with pytest.raises(exceptions.DeleteCredentialError):
                credentials.Windows.delete_credential(name="test")
        else:
            credentials.Windows.delete_credential(name="test")

    @pytest.mark.parametrize("exists", [True, False])
    @mock.patch("dss_sdk.credentials.subprocess.check_output")
    def test_windows_credential_exists(self, mock_check_output: mock.MagicMock, exists):
        if not exists:
            mock_check_output.side_effect = subprocess.CalledProcessError(returncode=1, cmd="test")
        assert credentials.Windows.windows_credential_exists(name="test") == exists

    @pytest.mark.parametrize("exception", [None, exceptions.SetCredentialError])
    @mock.patch("dss_sdk.credentials.subprocess.check_output")
    def test_set_windows_credential(self, mock_check_output: mock.MagicMock, exception):
        if exception:
            mock_check_output.return_value = b"Exception"
            with pytest.raises(exception):
                credentials.Windows.set_windows_credential(name="test", client_id="test", client_secret="test")
        else:
            credentials.Windows.set_windows_credential(name="test", client_id="test", client_secret="test")

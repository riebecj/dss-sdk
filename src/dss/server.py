"""The Delinea Secret Server SDK."""
import datetime
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import cached_property
from typing import Annotated

import httpx
from click import ClickException
from httpx import HTTPStatusError
from pydantic import BaseModel, Field, PlainValidator, SecretStr


class SecretServer(ABC):
    """The Secret Server Abstract Class."""
    token: str

    def __init__(self, server: str) -> None:
        """Initialize the class."""
        self.__server__ = server

    @property
    def headers(self) -> dict[str, str]:
        """The headers used by the Delinea API."""
        headers = {
            "Accept": "application/json",
            "Accept-Language": "en-US",
            "Accept-Charset": "ISO-8859-l,utf-8",
            "Content-Type": "application/json",
        }
        if hasattr(self, "token") and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @cached_property
    def endpoint(self) -> str:
        """The Delinea Secret Server endpoint."""
        # noinspection HttpUrlsUsage
        if self.__server__.startswith("http://") or self.__server__.startswith("https://"):
            return self.__server__
        return f"https://{self.__server__}"

    @property
    @abstractmethod
    def client(self) -> httpx.Client | httpx.AsyncClient:
        """Client abstract property."""
        ...


@dataclass(frozen=True)
class DelineaClientCredentials:
    """Frozen dataclass used to contain Delinea Credentials."""
    client_id: str
    client_secret: str


class RegisterClient:
    """Registers a new client with Delinea."""

    def __new__(
            cls, server: str, service_account: str, onboarding_key: str, description: str,
    ) -> DelineaClientCredentials:
        """Registers the new client and returns the credentials.

        Args:
            server: The Delinea server FQDN.
            service_account: The Delinea Service Account.
            onboarding_key: The onboarding key for the service account.
            description: The description of the client.
        """
        server = cls.__format_server_name__(server=server)

        json = {
            "onboardingKey": onboarding_key,
            "ruleName": service_account,
            "clientId": str(uuid.uuid4()),
            "description": description,
            "name": service_account,
        }
        data = cls.__register__(server=server, json=json)

        client_secret = data["clientSecret"]
        client_id = data["clientId"]
        return DelineaClientCredentials(client_id=client_id, client_secret=client_secret)

    @classmethod
    def __format_server_name__(cls, server: str) -> str:
        """Formats the Delinea server name."""
        # noinspection HttpUrlsUsage
        if not server.startswith("http://") or server.startswith("https://"):
            server = f"https://{server}"

        if server.endswith("/"):
            # Remove the trailing slash
            server = server[:-1]

        return server

    @classmethod
    def __register__(cls, server: str, json: dict[str, str]) -> dict:
        """Registers the new client."""
        with httpx.Client() as client:
            response = client.post(
                f"{server}/api/v1/sdk-client-accounts",
                headers={
                    "Accept": "application/json",
                    "Accept-Language": "en-US",
                    "Accept-Charset": "ISO-8859-l,utf-8",
                    "Content-Type": "application/json",
                },
                json=json,
            )
            response.raise_for_status()
            return response.json()


class SecretItem(BaseModel):
    """The Secret Item Model."""
    item_id: Field(int | None, alias="itemId") = None  # Sometimes there is no itemId in the JSON response.
    file_attachment_id: Field(int | None, alias="fileAttachmentId")
    filename: Field(str | None)
    item_value: Field(SecretStr, alias="itemValue")
    field_id: Field(int, alias="fieldId")
    field_name: Field(str, alias="fieldName")
    slug: Field(str, alias="")
    field_description: Field(str, alias="fieldDescription")
    is_file: Field(bool, alias="isFile")
    is_notes: Field(bool, alias="isNotes")
    is_password: Field(bool, alias="isPassword")
    is_list: Field(bool, alias="isList")
    list_type: Field(str, alias="listType")


class Secret(BaseModel):
    """The Secret Model."""
    secret_id: Field(int, alias="id")
    name: Field(str, alias="")
    secret_template_id: Field(int, alias="secretTemplateId")
    folder_id: Field(int, alias="folderId")
    active: Field(bool, alias="")
    items: Field(list[SecretItem])
    launcher_connect_as_secret_id: Field(int, alias="launcherConnectAsSecretId")
    check_out_minutes_remaining: Field(int, alias="checkOutMinutesRemaining")
    checked_out: Field(bool, alias="checkedOut")
    check_out_user_display_name: Field(str, alias="checkOutUserDisplayName")
    check_out_user_id: Field(int, alias="checkOutUserId")
    is_restricted: Field(bool, alias="isRestricted")
    is_out_of_sync: Field(bool, alias="isOutOfSync")
    out_of_sync_reason: Field(str, alias="outOfSyncReason")
    auto_change_enabled: Field(bool, alias="autoChangeEnabled")
    auto_change_next_password: Field(str, alias="autoChangeNextPassword")
    requires_approval_for_access: Field(bool, alias="requiresApprovalForAccess")
    requires_comment: Field(bool, alias="requiresComment")
    check_out_enabled: Field(bool, alias="checkOutEnabled")
    check_out_interval_minutes: Field(int, alias="checkOutIntervalMinutes")
    check_out_change_password_enabled: Field(bool, alias="checkOutChangePasswordEnabled")
    access_request_workflow_map_id: Field(int, alias="accessRequestWorkflowMapId")
    proxy_enabled: Field(bool, alias="proxyEnabled")
    session_recording_enabled: Field(bool, alias="sessionRecordingEnabled")
    restrict_ssh_commands: Field(bool, alias="restrictSshCommands")
    jumpbox_route_id: Field(str | None, alias="jumpboxRouteId")
    allow_owners_unrestricted_ssh_commands: Field(bool, alias="allowOwnersUnrestrictedSshCommands")
    is_double_lock: Field(bool, alias="isDoubleLock")
    double_lock_id: Field(int, alias="doubleLockId")
    enable_inherit_permissions: Field(bool, alias="enableInheritPermissions")
    password_type_web_script_id: Field(int, alias="passwordTypeWebScriptId")
    site_id: Field(int, alias="siteId")
    enable_inherit_secret_policy: Field(bool, alias="enableInheritSecretPolicy")
    secret_policy_id: Field(int, alias="secretPolicyId")
    last_heart_beat_status: Field(str, alias="lastHeartBeatStatus")
    last_heart_beat_check: Field(Annotated[datetime.datetime, PlainValidator(
        lambda v: datetime.datetime.strptime(v, "%Y-%m-%d_t%_h:%_m:%_s").astimezone(datetime.UTC)),
                                 ] | None, alias="lastHeartBeatCheck")
    failed_password_change_attempts: Field(int, alias="failedPasswordChangeAttempts")
    last_password_change_attempt: Field(Annotated[datetime.datetime, PlainValidator(
        lambda v: datetime.datetime.strptime(v, "%Y-%m-%d_t%_h:%_m:%_s").astimezone(datetime.UTC)),
                                        ] | None, alias="lastPasswordChangeAttempt")
    secret_template_name: Field(str, alias="secretTemplateName")
    response_codes: Field(list, alias="responseCodes")
    web_launcher_requires_incognito_mode: Field(bool, alias="webLauncherRequiresIncognitoMode")

    def get_password(self) -> str:
        """Gets the password."""
        for item in self.items:
            if item.isPassword:
                return item.itemValue.get_secret_value()
        return ""

    def get_username(self) -> str:
        """Gets the username."""
        for item in self.items:
            if item.fieldName.lower() == "username":
                return item.itemValue.get_secret_value()
        return ""


class SecretInfo(BaseModel):
    """The Secret Info Model."""
    secret_id: Field(int, alias="id")
    name: Field(str)
    secret_template_id: Field(int, alias="secretTemplateId")
    secret_template_name: Field(str, alias="secretTemplateName")
    folder_id: Field(int, alias="folderId")
    folder_path: Field(str, alias="folderPath")
    site_id: Field(int, alias="siteId")
    active: Field(bool)
    checked_out: Field(bool, alias="checkedOut")
    is_restricted: Field(bool, alias="isRestricted")
    is_out_of_sync: Field(bool, alias="isOutOfSync")
    out_of_sync_reason: Field(str, alias="outOfSyncReason")
    last_heart_beat_status: Field(str, alias="lastHeartBeatStatus")
    last_password_change_attempt: Field(Annotated[datetime.datetime, PlainValidator(
        lambda v: datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%S").astimezone(datetime.UTC)),
                                        ], alias="lastPasswordChangeAttempt")
    response_codes: Field(None, alias="responseCodes")
    last_accessed: Field(Annotated[datetime.datetime, PlainValidator(
        lambda v: datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%f").astimezone(datetime.UTC)),
                         ] | None, alias="lastAccessed")
    extended_fields: Field(None, alias="extendedFields")
    check_out_enabled: Field(bool, alias="checkOutEnabled")
    auto_change_enabled: Field(bool, alias="autoChangeEnabled")
    double_lock_enabled: Field(bool, alias="doubleLockEnabled")
    requires_approval: Field(bool, alias="requiresApproval")
    requires_comment: Field(bool, alias="requiresComment")
    inherits_permissions: Field(bool, alias="inheritsPermissions")
    hide_password: Field(bool, alias="hidePassword")
    create_date: Field(Annotated[datetime.datetime, PlainValidator(
        lambda v: datetime.datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%f").astimezone(datetime.UTC)),
                       ], alias="createDate")
    days_until_expiration: Field(int | None, alias="daysUntilExpiration")
    has_launcher: Field(bool, alias="hasLauncher")
    check_out_user_id: Field(int, alias="checkOutUserId")
    check_out_user_name: Field(str | None, alias="checkOutUserName")


class SecretServerClient(SecretServer):
    """The Synchronous Delinea Secret Server Client."""

    def __init__(self, server: str, client_id: str, client_secret: str, *, mode: str = "sdk") -> None:
        """Initialize the class."""
        super().__init__(server=server)
        self.__client_id__ = client_id
        self.__client_secret__ = client_secret
        self.__mode__ = mode

    @cached_property
    def token(self) -> str:
        """Gets and caches the OAuth2 token based on the client credentials."""
        if not self.__client_id__.startswith("sdk-client-"):
            self.__client_id__ = f"sdk-client-{self.__client_id__}"

        response = self.client.post(
            f"{self.endpoint}/oauth2/token",
            headers={
                "Accept": "application/json",
                "Accept-Language": "en-US",
                "Accept-Charset": "ISO-8859-l,utf-8",
            },
            data={
                "grant_type": "client_credentials",
                "client_id": self.__client_id__,
                "client_secret": self.__client_secret__,
            },
        )
        if self.__mode__ == "cli":
            try:
                response.raise_for_status()
            except HTTPStatusError as err:
                reason = err.response.json().get("error", "No error message received")
                msg = f"HTTP {err.response.status_code}: {reason}"
                raise ClickException(msg) from err
        else:
            response.raise_for_status()
        return response.json()["access_token"]

    @cached_property
    def client(self) -> httpx.Client:
        """Creates and caches the httpx Client."""
        return httpx.Client()

    def __get__(self, url: str, *, params: dict[str, str] | None = None) -> dict:
        """Performs an HTTPX GET.

        Args:
            url: The URL to GET.
            params: The optional query parameters.

        Returns:
            The JSON response.
        """
        response = self.client.get(url, headers=self.headers, params=params)
        response.raise_for_status()
        return response.json()

    def search_secrets(self, params: dict) -> list[SecretInfo]:
        """Search Delinea Secrets.

        Args:
            params: The query parameters.

        Returns:
            The list of information on available Secrets.
        """
        if not params:
            params = None

        response = self.__get__(url=f"{self.endpoint}/api/v2/secrets", params=params)
        return [SecretInfo(**record) for record in response.get("records", [])]

    def get_secret_id(self, secret_name: str) -> int:
        """Gets a secret ID for a given name.

        Args:
            secret_name: The name of the secret in Delinea.

        Returns:
            The Secret ID.
        """
        response = self.__get__(url=f"{self.endpoint}/api/v2/secrets", params={"filter.searchText": secret_name})

        records = response.get("records", [])
        for record in records:
            return record["id"]

        msg = f"Secret with name {secret_name} not found."
        raise ValueError(msg)

    def get_secret(self, secret_id: int) -> Secret:
        """Gets a secret.

        Args:
            secret_id: The ID of the Secret.

        Returns:
            The secret.
        """
        response = self.__get__(url=f"{self.endpoint}/api/v2/secrets/{secret_id}")
        return Secret(**response)

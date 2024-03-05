"""DSS-SDK Models."""
import datetime
from typing import Annotated, TypeVar

from pydantic import UUID4, BaseModel, ConfigDict, Field, SecretStr, field_serializer, field_validator

_T = TypeVar("_T")


class SecretInfo(BaseModel):
    """The Secret Info Model."""
    secret_id: Annotated[int, Field(alias="id")]
    name: Annotated[str, Field()]
    active: Annotated[bool, Field()]
    secret_template_id: Annotated[int, Field(alias="secretTemplateId")]
    secret_template_name: Annotated[str, Field(alias="secretTemplateName")]
    folder_id: Annotated[int, Field(alias="folderId")]
    folder_path: Annotated[str, Field(alias="folderPath")]
    site_id: Annotated[int, Field(alias="siteId")]
    checked_out: Annotated[bool, Field(alias="checkedOut")]
    is_restricted: Annotated[bool, Field(alias="isRestricted")]
    is_out_of_sync: Annotated[bool, Field(alias="isOutOfSync")]
    out_of_sync_reason: Annotated[str, Field(alias="outOfSyncReason")]
    last_heart_beat_status: Annotated[str, Field(alias="lastHeartBeatStatus")]
    last_password_change_attempt: Annotated[datetime.datetime, Field(alias="lastPasswordChangeAttempt")]
    response_codes: Annotated[list[str] | None, Field(alias="responseCodes")]
    last_accessed: Annotated[datetime.datetime | None, Field(alias="lastAccessed")]
    extended_fields: Annotated[list[dict] | None, Field(alias="extendedFields")]
    check_out_enabled: Annotated[bool, Field(alias="checkOutEnabled")]
    auto_change_enabled: Annotated[bool, Field(alias="autoChangeEnabled")]
    double_lock_enabled: Annotated[bool, Field(alias="doubleLockEnabled")]
    requires_approval: Annotated[bool, Field(alias="requiresApproval")]
    requires_comment: Annotated[bool, Field(alias="requiresComment")]
    inherits_permissions: Annotated[bool, Field(alias="inheritsPermissions")]
    hide_password: Annotated[bool, Field(alias="hidePassword")]
    create_date: Annotated[datetime.datetime, Field(alias="createDate")]
    days_until_expiration: Annotated[int | None, Field(alias="daysUntilExpiration")]
    has_launcher: Annotated[bool, Field(alias="hasLauncher")]
    check_out_user_id: Annotated[int, Field(alias="checkOutUserId")]
    check_out_user_name: Annotated[str | None, Field(alias="checkOutUserName")]

    # noinspection PyNestedDecorators
    @field_validator("last_password_change_attempt", "last_accessed", "create_date")
    @classmethod
    def datetime_stripping(cls, v: _T) -> datetime.datetime | None:
        """Strips the datatime."""
        if isinstance(v, datetime.datetime):
            return v
        return None


class SecretsInfo(BaseModel):
    """Contains a list of SecretInfo models."""
    records: list[SecretInfo]

    def get_secret_info_by_name(self, name: str) -> SecretInfo:
        """Gets Secret info by secret name."""
        return next(secret for secret in self.records if secret.name == name)


class SecretItem(BaseModel):
    """The Secret Item Model."""
    model_config = ConfigDict(populate_by_name=True)
    item_id: Annotated[int | None, Field(alias="itemId")] = None  # Sometimes there is no itemId in the JSON response.
    file_attachment_id: Annotated[int | None, Field(alias="fileAttachmentId")]
    filename: Annotated[str | None, Field()]
    item_value: Annotated[SecretStr | None, Field(alias="itemValue")]
    field_id: Annotated[int, Field(alias="fieldId")]
    field_name: Annotated[str, Field(alias="fieldName")]
    slug: Annotated[str, Field()]
    field_description: Annotated[str, Field(alias="fieldDescription")]
    is_file: Annotated[bool, Field(alias="isFile")]
    is_notes: Annotated[bool, Field(alias="isNotes")]
    is_password: Annotated[bool, Field(alias="isPassword")]
    is_list: Annotated[bool, Field(alias="isList")]
    list_type: Annotated[str, Field(alias="listType")]

    @field_serializer("item_value", when_used="json")
    def dump_secret(self, v: _T) -> str:
        """Dumps the actual value on JSON serialization."""
        if isinstance(v, SecretStr):
            return v.get_secret_value()
        return v


class Secret(BaseModel):
    """The Secret Model."""
    secret_id: Annotated[int, Field(alias="id")]
    name: Annotated[str, Field()]
    secret_template_id: Annotated[int, Field(alias="secretTemplateId")]
    folder_id: Annotated[int, Field(alias="folderId")]
    active: Annotated[bool, Field()]
    items: Annotated[list[SecretItem], Field()]
    launcher_connect_as_secret_id: Annotated[int, Field(alias="launcherConnectAsSecretId")]
    check_out_minutes_remaining: Annotated[int, Field(alias="checkOutMinutesRemaining")]
    checked_out: Annotated[bool, Field(alias="checkedOut")]
    check_out_user_display_name: Annotated[str, Field(alias="checkOutUserDisplayName")]
    check_out_user_id: Annotated[int, Field(alias="checkOutUserId")]
    is_restricted: Annotated[bool, Field(alias="isRestricted")]
    is_out_of_sync: Annotated[bool, Field(alias="isOutOfSync")]
    out_of_sync_reason: Annotated[str, Field(alias="outOfSyncReason")]
    auto_change_enabled: Annotated[bool, Field(alias="autoChangeEnabled")]
    auto_change_next_password: Annotated[str | None, Field(alias="autoChangeNextPassword")]
    requires_approval_for_access: Annotated[bool, Field(alias="requiresApprovalForAccess")]
    requires_comment: Annotated[bool, Field(alias="requiresComment")]
    check_out_enabled: Annotated[bool, Field(alias="checkOutEnabled")]
    check_out_interval_minutes: Annotated[int, Field(alias="checkOutIntervalMinutes")]
    check_out_change_password_enabled: Annotated[bool, Field(alias="checkOutChangePasswordEnabled")]
    access_request_workflow_map_id: Annotated[int, Field(alias="accessRequestWorkflowMapId")]
    proxy_enabled: Annotated[bool, Field(alias="proxyEnabled")]
    session_recording_enabled: Annotated[bool, Field(alias="sessionRecordingEnabled")]
    restrict_ssh_commands: Annotated[bool, Field(alias="restrictSshCommands")]
    jumpbox_route_id: Annotated[str | None, Field(alias="jumpboxRouteId")]
    allow_owners_unrestricted_ssh_commands: Annotated[bool, Field(alias="allowOwnersUnrestrictedSshCommands")]
    is_double_lock: Annotated[bool, Field(alias="isDoubleLock")]
    double_lock_id: Annotated[int, Field(alias="doubleLockId")]
    enable_inherit_permissions: Annotated[bool, Field(alias="enableInheritPermissions")]
    password_type_web_script_id: Annotated[int, Field(alias="passwordTypeWebScriptId")]
    site_id: Annotated[int, Field(alias="siteId")]
    enable_inherit_secret_policy: Annotated[bool, Field(alias="enableInheritSecretPolicy")]
    secret_policy_id: Annotated[int, Field(alias="secretPolicyId")]
    last_heart_beat_status: Annotated[str, Field(alias="lastHeartBeatStatus")]
    last_heart_beat_check: Annotated[datetime.datetime | None, Field(alias="lastHeartBeatCheck")]
    failed_password_change_attempts: Annotated[int, Field(alias="failedPasswordChangeAttempts")]
    last_password_change_attempt: Annotated[datetime.datetime | None, Field(alias="lastPasswordChangeAttempt")]
    secret_template_name: Annotated[str, Field(alias="secretTemplateName")]
    response_codes: Annotated[list, Field(alias="responseCodes")]
    web_launcher_requires_incognito_mode: Annotated[bool, Field(alias="webLauncherRequiresIncognitoMode")]

    # noinspection PyNestedDecorators
    @field_validator("last_password_change_attempt", "last_heart_beat_check")
    @classmethod
    def datetime_stripping(cls, v: _T) -> datetime.datetime | None:
        """Strips the datetime."""
        if isinstance(v, datetime.datetime):
            return v
        return None

    def get_password(self) -> str:
        """Gets the password."""
        return self.get_password_field().item_value.get_secret_value()

    def get_username(self) -> str:
        """Gets the username."""
        username = self.get_item_by_name(name="username")
        if not username:
            username = self.get_item_by_name(name="ClientID")
        return username.item_value.get_secret_value()

    def get_item_by_slug(self, slug: str) -> SecretItem:
        """Gets the field item by slug."""
        return next(item for item in self.items if item.slug == slug)

    def get_item_by_name(self, name: str) -> SecretItem | None:
        """Gets the field item by name."""
        try:
            return next(item for item in self.items if item.field_name.lower() == name.lower())
        except StopIteration:
            return None

    def get_password_field(self) -> SecretItem:
        """Gets the password field."""
        return next(item for item in self.items if item.is_password)


class TemplateField(BaseModel):
    """Template Field model."""
    secret_template_field_id: Annotated[int, Field(alias="secretTemplateFieldId")]
    is_expiration_field: Annotated[bool, Field(alias="isExpirationField")]
    display_name: Annotated[str, Field(alias="displayName")]
    description: Annotated[str, Field(alias="description")]
    name: Annotated[str, Field(alias="name")]
    must_encrypt: Annotated[bool | None, Field(alias="mustEncrypt")]
    is_url: Annotated[bool, Field(alias="isUrl")]
    is_password: Annotated[bool, Field(alias="isPassword")]
    is_notes: Annotated[bool, Field(alias="isNotes")]
    is_file: Annotated[bool, Field(alias="isFile")]
    is_list: Annotated[bool, Field(alias="isList")]
    list_type: Annotated[str, Field(alias="listType")]
    generate_password_character_set: Annotated[str | None, Field(alias="generatePasswordCharacterSet")]
    generate_password_length: Annotated[int | None, Field(alias="generatePasswordLength")]
    history_length: Annotated[int, Field(alias="historyLength")]
    is_indexable: Annotated[bool, Field(alias="isIndexable")]
    is_required: Annotated[bool, Field(alias="isRequired")]
    edit_requires: Annotated[str, Field(alias="editRequires")]
    hide_on_view: Annotated[bool, Field(alias="hideOnView")]
    password_type_field_id: Annotated[int, Field(alias="passwordTypeFieldId")]
    password_requirement_id: Annotated[int, Field(alias="passwordRequirementId")]
    sort_order: Annotated[int, Field(alias="sortOrder")]
    editable_permission: Annotated[int, Field(alias="editablePermission")]
    field_slug_name: Annotated[str, Field(alias="fieldSlugName")]


class SecretTemplate(BaseModel):
    """Secret Template model."""
    template_id: Annotated[int, Field(alias="id")]
    concurrency_id: Annotated[UUID4, Field(alias="concurrencyId")]
    name: Annotated[str, Field()]
    password_type_id: Annotated[int | None, Field(alias="passwordTypeId")]
    fields: Annotated[list[TemplateField], Field()]


class CreateSecret(BaseModel):
    """Model used when creating a new secret."""
    model_config = ConfigDict(populate_by_name=True)
    template_id: Annotated[int, Field(alias="secretTemplateId")]
    name: Annotated[str, Field()]
    folder_id: Annotated[int, Field(alias="folderId")]
    site_id: Annotated[int, Field(alias="siteId")]
    items: Annotated[list[SecretItem], Field()] = []

    def add_item(self, item: SecretItem) -> None:
        """Adds a new item to the secret items.

        Args:
            item: The SecretItem to add.
        """
        self.items.append(item)


class Folder(BaseModel):
    """The Folder model."""
    model_config = ConfigDict(populate_by_name=True)
    folder_id: Annotated[int, Field(alias="id")]
    name: Annotated[str, Field(alias="folderName")]
    path: Annotated[str, Field(alias="folderPath")]
    parent_folder_id: Annotated[int, Field(alias="parentFolderId")]
    folder_type_id: Annotated[int, Field(alias="folderTypeId")]
    secret_policy_id: Annotated[int, Field(alias="secretPolicyId")]
    inherit_secret_policy: Annotated[bool, Field(alias="inheritSecretPolicy")]
    inherit_permissions: Annotated[bool, Field(alias="inheritPermissions")]


class Folders(BaseModel):
    """The Folders model, containing a list of Folder models."""
    folders: list[Folder]

    def get_folder_by_name(self, name: str) -> Folder:
        """Gets a folder by its name."""
        return next(folder for folder in self.folders if folder.name == name)


class SearchSecretsParams(BaseModel):
    """Model used to generate formatted params for searching for secrets."""
    model_config = ConfigDict(populate_by_name=True)
    folder_id: Annotated[int | None, Field(alias="filter.folderId")] = None
    search_text: Annotated[str | None, Field(alias="filter.searchText")] = None
    secret_template_ids: Annotated[list[int] | None, Field(alias="filter.secretTemplateIds")] = None
    scope: Annotated[str | None, Field(alias="filter.scope")] = None


class SearchFoldersParams(BaseModel):
    """Model used to generate formatted params for searching for folders."""
    model_config = ConfigDict(populate_by_name=True)
    parent_folder_id: Annotated[int | None, Field(alias="filter.parentFolderId")] = None
    search_text: Annotated[str | None, Field(alias="filter.searchText")] = None


class Site(BaseModel):
    """The Site model."""
    site_id: Annotated[int, Field(alias="siteId")]
    name: Annotated[str, Field(alias="siteName")]
    active: Annotated[bool, Field()]


class Sites(BaseModel):
    """Contains the list of Site models."""
    sites: list[Site]

    def get_site_by_name(self, name: str) -> Site:
        """Gets a site model by its name."""
        return next(site for site in self.sites if site.name == name)


class AllowedTemplate(BaseModel):
    """An allowed template model that is used in FolderDetails model."""
    template_id: Annotated[int, Field(alias="id")]
    name: Annotated[str, Field()]


class FolderDetails(BaseModel):
    """Folder Details model."""
    folder_id: Annotated[int, Field(alias="id")]
    name: Annotated[str, Field()]
    actions: Annotated[list[str], Field()]
    allowed_templates: Annotated[list[AllowedTemplate], Field(alias="allowedTemplates")]
    folder_warning: Annotated[bool | None, Field(alias="folderWarning")]

    def get_allowed_template_id(self, template_name: str) -> int | None:
        """Gets an allowed template by its name."""
        try:
            return next(template.template_id for template in self.allowed_templates if template.name == template_name)
        except StopIteration:
            return None

    def template_is_allowed(self, template_id: int) -> bool:
        """Checks if a template is allowed."""
        return template_id in [allowed.template_id for allowed in self.allowed_templates]


class UpdateSecret(BaseModel):
    """Model used to Update a secret."""
    model_config = ConfigDict(populate_by_name=True)
    secret_id: Annotated[int, Field(alias="id")]
    name: Annotated[str, Field()]
    site_id: Annotated[int, Field(alias="siteId")]
    folder_id: Annotated[int, Field(alias="folderId")]
    items: Annotated[list[SecretItem], Field()]

    def add_item(self, item: SecretItem) -> None:
        """Adds an item to the model."""
        self.items.append(item)

"""DSS-SDK Models."""
import datetime
import typing

import pydantic

_T = typing.TypeVar("_T")


class OneTimePasscode(pydantic.BaseModel):
    """The OTP Model."""
    code: str
    duration_seconds: typing.Annotated[int, pydantic.Field(alias="durationSeconds")]
    remaining_seconds: typing.Annotated[int, pydantic.Field(alias="remainingSeconds")]


class SecretInfo(pydantic.BaseModel):
    """The Secret Info Model."""
    secret_id: typing.Annotated[int, pydantic.Field(alias="id")]
    name: typing.Annotated[str, pydantic.Field()]
    active: typing.Annotated[bool, pydantic.Field()]
    secret_template_id: typing.Annotated[int, pydantic.Field(alias="secretTemplateId")]
    secret_template_name: typing.Annotated[str, pydantic.Field(alias="secretTemplateName")]
    folder_id: typing.Annotated[int, pydantic.Field(alias="folderId")]
    folder_path: typing.Annotated[str, pydantic.Field(alias="folderPath")]
    site_id: typing.Annotated[int, pydantic.Field(alias="siteId")]
    checked_out: typing.Annotated[bool, pydantic.Field(alias="checkedOut")]
    is_restricted: typing.Annotated[bool, pydantic.Field(alias="isRestricted")]
    is_out_of_sync: typing.Annotated[bool, pydantic.Field(alias="isOutOfSync")]
    out_of_sync_reason: typing.Annotated[str, pydantic.Field(alias="outOfSyncReason")]
    last_heart_beat_status: typing.Annotated[str, pydantic.Field(alias="lastHeartBeatStatus")]
    last_password_change_attempt: typing.Annotated[datetime.datetime, pydantic.Field(alias="lastPasswordChangeAttempt")]
    response_codes: typing.Annotated[list[str] | None, pydantic.Field(alias="responseCodes")]
    last_accessed: typing.Annotated[datetime.datetime | None, pydantic.Field(alias="lastAccessed")]
    extended_fields: typing.Annotated[list[dict] | None, pydantic.Field(alias="extendedFields")]
    check_out_enabled: typing.Annotated[bool, pydantic.Field(alias="checkOutEnabled")]
    auto_change_enabled: typing.Annotated[bool, pydantic.Field(alias="autoChangeEnabled")]
    double_lock_enabled: typing.Annotated[bool, pydantic.Field(alias="doubleLockEnabled")]
    requires_approval: typing.Annotated[bool, pydantic.Field(alias="requiresApproval")]
    requires_comment: typing.Annotated[bool, pydantic.Field(alias="requiresComment")]
    inherits_permissions: typing.Annotated[bool, pydantic.Field(alias="inheritsPermissions")]
    hide_password: typing.Annotated[bool, pydantic.Field(alias="hidePassword")]
    create_date: typing.Annotated[datetime.datetime, pydantic.Field(alias="createDate")]
    days_until_expiration: typing.Annotated[int | None, pydantic.Field(alias="daysUntilExpiration")]
    has_launcher: typing.Annotated[bool, pydantic.Field(alias="hasLauncher")]
    check_out_user_id: typing.Annotated[int, pydantic.Field(alias="checkOutUserId")]
    check_out_user_name: typing.Annotated[str | None, pydantic.Field(alias="checkOutUserName")]

    # noinspection PyNestedDecorators
    @pydantic.field_validator("last_password_change_attempt", "last_accessed", "create_date")
    @classmethod
    def datetime_stripping(cls, v: _T) -> datetime.datetime | None:
        """Strips the datatime."""
        if isinstance(v, datetime.datetime):
            return v
        return None


class SecretsInfo(pydantic.BaseModel):
    """Contains a list of SecretInfo models."""
    records: list[SecretInfo]

    def get_secret_info_by_name(self, name: str) -> SecretInfo:
        """Gets Secret info by secret name."""
        return next(secret for secret in self.records if secret.name == name)


class SecretItem(pydantic.BaseModel):
    """The Secret Item Model."""
    model_config = pydantic.ConfigDict(populate_by_name=True)
    item_id: typing.Annotated[int | None, pydantic.Field(alias="itemId")] = None  # Sometimes there is no itemId
    file_attachment_id: typing.Annotated[int | None, pydantic.Field(alias="fileAttachmentId")]
    filename: typing.Annotated[str | None, pydantic.Field()]
    item_value: typing.Annotated[pydantic.SecretStr | None, pydantic.Field(alias="itemValue")]
    field_id: typing.Annotated[int, pydantic.Field(alias="fieldId")]
    field_name: typing.Annotated[str, pydantic.Field(alias="fieldName")]
    slug: typing.Annotated[str, pydantic.Field()]
    field_description: typing.Annotated[str, pydantic.Field(alias="fieldDescription")]
    is_file: typing.Annotated[bool, pydantic.Field(alias="isFile")]
    is_notes: typing.Annotated[bool, pydantic.Field(alias="isNotes")]
    is_password: typing.Annotated[bool, pydantic.Field(alias="isPassword")]
    is_list: typing.Annotated[bool, pydantic.Field(alias="isList")]
    list_type: typing.Annotated[str, pydantic.Field(alias="listType")]

    @pydantic.field_serializer("item_value", when_used="json")
    def dump_secret(self, v: _T) -> str:
        """Dumps the actual value on JSON serialization."""
        if isinstance(v, pydantic.SecretStr):
            return v.get_secret_value()
        return v


class Secret(pydantic.BaseModel):
    """The Secret Model."""
    secret_id: typing.Annotated[int, pydantic.Field(alias="id")]
    name: typing.Annotated[str, pydantic.Field()]
    secret_template_id: typing.Annotated[int, pydantic.Field(alias="secretTemplateId")]
    folder_id: typing.Annotated[int, pydantic.Field(alias="folderId")]
    active: typing.Annotated[bool, pydantic.Field()]
    items: typing.Annotated[list[SecretItem], pydantic.Field()]
    launcher_connect_as_secret_id: typing.Annotated[int, pydantic.Field(alias="launcherConnectAsSecretId")]
    check_out_minutes_remaining: typing.Annotated[int, pydantic.Field(alias="checkOutMinutesRemaining")]
    checked_out: typing.Annotated[bool, pydantic.Field(alias="checkedOut")]
    check_out_user_display_name: typing.Annotated[str, pydantic.Field(alias="checkOutUserDisplayName")]
    check_out_user_id: typing.Annotated[int, pydantic.Field(alias="checkOutUserId")]
    is_restricted: typing.Annotated[bool, pydantic.Field(alias="isRestricted")]
    is_out_of_sync: typing.Annotated[bool, pydantic.Field(alias="isOutOfSync")]
    out_of_sync_reason: typing.Annotated[str, pydantic.Field(alias="outOfSyncReason")]
    auto_change_enabled: typing.Annotated[bool, pydantic.Field(alias="autoChangeEnabled")]
    auto_change_next_password: typing.Annotated[str | None, pydantic.Field(alias="autoChangeNextPassword")]
    requires_approval_for_access: typing.Annotated[bool, pydantic.Field(alias="requiresApprovalForAccess")]
    requires_comment: typing.Annotated[bool, pydantic.Field(alias="requiresComment")]
    check_out_enabled: typing.Annotated[bool, pydantic.Field(alias="checkOutEnabled")]
    check_out_interval_minutes: typing.Annotated[int, pydantic.Field(alias="checkOutIntervalMinutes")]
    check_out_change_password_enabled: typing.Annotated[bool, pydantic.Field(alias="checkOutChangePasswordEnabled")]
    access_request_workflow_map_id: typing.Annotated[int, pydantic.Field(alias="accessRequestWorkflowMapId")]
    proxy_enabled: typing.Annotated[bool, pydantic.Field(alias="proxyEnabled")]
    session_recording_enabled: typing.Annotated[bool, pydantic.Field(alias="sessionRecordingEnabled")]
    restrict_ssh_commands: typing.Annotated[bool, pydantic.Field(alias="restrictSshCommands")]
    jumpbox_route_id: typing.Annotated[str | None, pydantic.Field(alias="jumpboxRouteId")]
    allow_owners_unrestricted_ssh_commands: typing.Annotated[bool, pydantic.Field(
        alias="allowOwnersUnrestrictedSshCommands")]
    is_double_lock: typing.Annotated[bool, pydantic.Field(alias="isDoubleLock")]
    double_lock_id: typing.Annotated[int, pydantic.Field(alias="doubleLockId")]
    enable_inherit_permissions: typing.Annotated[bool, pydantic.Field(alias="enableInheritPermissions")]
    password_type_web_script_id: typing.Annotated[int, pydantic.Field(alias="passwordTypeWebScriptId")]
    site_id: typing.Annotated[int, pydantic.Field(alias="siteId")]
    enable_inherit_secret_policy: typing.Annotated[bool, pydantic.Field(alias="enableInheritSecretPolicy")]
    secret_policy_id: typing.Annotated[int, pydantic.Field(alias="secretPolicyId")]
    last_heart_beat_status: typing.Annotated[str, pydantic.Field(alias="lastHeartBeatStatus")]
    last_heart_beat_check: typing.Annotated[datetime.datetime | None, pydantic.Field(alias="lastHeartBeatCheck")]
    failed_password_change_attempts: typing.Annotated[int, pydantic.Field(alias="failedPasswordChangeAttempts")]
    last_password_change_attempt: typing.Annotated[datetime.datetime | None, pydantic.Field(
        alias="lastPasswordChangeAttempt")]
    secret_template_name: typing.Annotated[str, pydantic.Field(alias="secretTemplateName")]
    response_codes: typing.Annotated[list, pydantic.Field(alias="responseCodes")]
    web_launcher_requires_incognito_mode: typing.Annotated[bool, pydantic.Field(
        alias="webLauncherRequiresIncognitoMode")]

    # noinspection PyNestedDecorators
    @pydantic.field_validator("last_password_change_attempt", "last_heart_beat_check")
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


class TemplateField(pydantic.BaseModel):
    """Template pydantic.Field model."""
    secret_template_field_id: typing.Annotated[int, pydantic.Field(alias="secretTemplateFieldId")]
    is_expiration_field: typing.Annotated[bool, pydantic.Field(alias="isExpirationField")]
    display_name: typing.Annotated[str, pydantic.Field(alias="displayName")]
    description: typing.Annotated[str, pydantic.Field(alias="description")]
    name: typing.Annotated[str, pydantic.Field(alias="name")]
    must_encrypt: typing.Annotated[bool | None, pydantic.Field(alias="mustEncrypt")]
    is_url: typing.Annotated[bool, pydantic.Field(alias="isUrl")]
    is_password: typing.Annotated[bool, pydantic.Field(alias="isPassword")]
    is_notes: typing.Annotated[bool, pydantic.Field(alias="isNotes")]
    is_file: typing.Annotated[bool, pydantic.Field(alias="isFile")]
    is_list: typing.Annotated[bool, pydantic.Field(alias="isList")]
    list_type: typing.Annotated[str, pydantic.Field(alias="listType")]
    generate_password_character_set: typing.Annotated[str | None, pydantic.Field(alias="generatePasswordCharacterSet")]
    generate_password_length: typing.Annotated[int | None, pydantic.Field(alias="generatePasswordLength")]
    history_length: typing.Annotated[int, pydantic.Field(alias="historyLength")]
    is_indexable: typing.Annotated[bool, pydantic.Field(alias="isIndexable")]
    is_required: typing.Annotated[bool, pydantic.Field(alias="isRequired")]
    edit_requires: typing.Annotated[str, pydantic.Field(alias="editRequires")]
    hide_on_view: typing.Annotated[bool, pydantic.Field(alias="hideOnView")]
    password_type_field_id: typing.Annotated[int, pydantic.Field(alias="passwordTypeFieldId")]
    password_requirement_id: typing.Annotated[int, pydantic.Field(alias="passwordRequirementId")]
    sort_order: typing.Annotated[int, pydantic.Field(alias="sortOrder")]
    editable_permission: typing.Annotated[int, pydantic.Field(alias="editablePermission")]
    field_slug_name: typing.Annotated[str, pydantic.Field(alias="fieldSlugName")]


class SecretTemplate(pydantic.BaseModel):
    """Secret Template model."""
    template_id: typing.Annotated[int, pydantic.Field(alias="id")]
    concurrency_id: typing.Annotated[pydantic.UUID4, pydantic.Field(alias="concurrencyId")]
    name: typing.Annotated[str, pydantic.Field()]
    password_type_id: typing.Annotated[int | None, pydantic.Field(alias="passwordTypeId")]
    fields: typing.Annotated[list[TemplateField], pydantic.Field()]


class CreateSecret(pydantic.BaseModel):
    """Model used when creating a new secret."""
    model_config = pydantic.ConfigDict(populate_by_name=True)
    template_id: typing.Annotated[int, pydantic.Field(alias="secretTemplateId")]
    name: typing.Annotated[str, pydantic.Field()]
    folder_id: typing.Annotated[int, pydantic.Field(alias="folderId")]
    site_id: typing.Annotated[int, pydantic.Field(alias="siteId")]
    items: typing.Annotated[list[SecretItem], pydantic.Field()] = []

    def add_item(self, item: SecretItem) -> None:
        """Adds a new item to the secret items.

        Args:
            item: The SecretItem to add.
        """
        self.items.append(item)


class Folder(pydantic.BaseModel):
    """The Folder model."""
    model_config = pydantic.ConfigDict(populate_by_name=True)
    folder_id: typing.Annotated[int, pydantic.Field(alias="id")]
    name: typing.Annotated[str, pydantic.Field(alias="folderName")]
    path: typing.Annotated[str, pydantic.Field(alias="folderPath")]
    parent_folder_id: typing.Annotated[int, pydantic.Field(alias="parentFolderId")]
    folder_type_id: typing.Annotated[int, pydantic.Field(alias="folderTypeId")]
    secret_policy_id: typing.Annotated[int, pydantic.Field(alias="secretPolicyId")]
    inherit_secret_policy: typing.Annotated[bool, pydantic.Field(alias="inheritSecretPolicy")]
    inherit_permissions: typing.Annotated[bool, pydantic.Field(alias="inheritPermissions")]


class Folders(pydantic.BaseModel):
    """The Folders model, containing a list of Folder models."""
    folders: list[Folder]

    def get_folder_by_name(self, name: str) -> Folder:
        """Gets a folder by its name."""
        return next(folder for folder in self.folders if folder.name == name)


class SearchSecretsParams(pydantic.BaseModel):
    """Model used to generate formatted params for searching for secrets."""
    model_config = pydantic.ConfigDict(populate_by_name=True)
    folder_id: typing.Annotated[int | None, pydantic.Field(alias="filter.folderId")] = None
    search_text: typing.Annotated[str | None, pydantic.Field(alias="filter.searchText")] = None
    secret_template_ids: typing.Annotated[list[int] | None, pydantic.Field(alias="filter.secretTemplateIds")] = None
    scope: typing.Annotated[str | None, pydantic.Field(alias="filter.scope")] = None


class SearchFoldersParams(pydantic.BaseModel):
    """Model used to generate formatted params for searching for folders."""
    model_config = pydantic.ConfigDict(populate_by_name=True)
    parent_folder_id: typing.Annotated[int | None, pydantic.Field(alias="filter.parentFolderId")] = None
    search_text: typing.Annotated[str | None, pydantic.Field(alias="filter.searchText")] = None


class Site(pydantic.BaseModel):
    """The Site model."""
    site_id: typing.Annotated[int, pydantic.Field(alias="siteId")]
    name: typing.Annotated[str, pydantic.Field(alias="siteName")]
    active: typing.Annotated[bool, pydantic.Field()]


class Sites(pydantic.BaseModel):
    """Contains the list of Site models."""
    sites: list[Site]

    def get_site_by_name(self, name: str) -> Site:
        """Gets a site model by its name."""
        return next(site for site in self.sites if site.name == name)


class AllowedTemplate(pydantic.BaseModel):
    """An allowed template model that is used in FolderDetails model."""
    template_id: typing.Annotated[int, pydantic.Field(alias="id")]
    name: typing.Annotated[str, pydantic.Field()]


class FolderDetails(pydantic.BaseModel):
    """Folder Details model."""
    folder_id: typing.Annotated[int, pydantic.Field(alias="id")]
    name: typing.Annotated[str, pydantic.Field()]
    actions: typing.Annotated[list[str], pydantic.Field()]
    allowed_templates: typing.Annotated[list[AllowedTemplate], pydantic.Field(alias="allowedTemplates")]
    folder_warning: typing.Annotated[bool | None, pydantic.Field(alias="folderWarning")]

    def get_allowed_template_id(self, template_name: str) -> int | None:
        """Gets an allowed template by its name."""
        try:
            return next(template.template_id for template in self.allowed_templates if template.name == template_name)
        except StopIteration:
            return None

    def template_is_allowed(self, template_id: int) -> bool:
        """Checks if a template is allowed."""
        return template_id in [allowed.template_id for allowed in self.allowed_templates]


class UpdateSecret(pydantic.BaseModel):
    """Model used to Update a secret."""
    model_config = pydantic.ConfigDict(populate_by_name=True)
    secret_id: typing.Annotated[int, pydantic.Field(alias="id")]
    name: typing.Annotated[str, pydantic.Field()]
    site_id: typing.Annotated[int, pydantic.Field(alias="siteId")]
    folder_id: typing.Annotated[int, pydantic.Field(alias="folderId")]
    items: typing.Annotated[list[SecretItem], pydantic.Field()]

    def add_item(self, item: SecretItem) -> None:
        """Adds an item to the model."""
        self.items.append(item)

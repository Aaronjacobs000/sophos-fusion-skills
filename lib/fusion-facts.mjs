// Platform facts the offline validator checks against. Read from the Fusion
// schema (playbookTriggerTypesV2) on 21/11/2026. The live catalog script
// (authoring/scripts/catalog.mjs triggers) returns the current lists.

export const TRIGGER_TYPES = ['actions', 'platform', 'generic'];

// Fields only Sophos's own tenant may set on a template (import error, measured 21/11/2026).
export const SOPHOS_ONLY_FIELDS = ['isCentralTenantVisible', 'isMDRProviderSupportedResponseAction', 'isMDRProviderInternalResponseAction', 'isContextualLookupAction'];

export const PLATFORM_SOURCES = {
  case: ['Create', 'Update', 'Delete', 'Detections Added', 'Detections Removed', 'Events Added', 'Events Removed', 'Assets Added', 'Assets Removed', 'Searches Added', 'Searches Removed', 'Comment Added', 'Comment Updated', 'Comment Deleted', 'File Added', 'File Deleted', 'Link Added', 'Link Updated', 'Link Deleted'],
  investigationNotification: ['Create', 'Update', 'Alerts Added', 'Alerts Removed', 'Events Added', 'Events Removed', 'Assets Added', 'Assets Removed', 'Comment Added', 'Comment Updated', 'Comment Deleted', 'File Added', 'File Updated', 'File Deleted'],
  investigation: ['create', 'update', 'delete'],
  health: ['create', 'update', 'delete'],
  alert2: ['create', 'update'],
  tenant: ['create', 'update', 'delete'],
  tenantlabel: ['create', 'update', 'delete'],
  tenantuser: ['create', 'update', 'delete'],
  'auto-investigation': ['create', 'update'],
  execution: ['completed', 'failed'],
  identityFindings: ['created', 'updated', 'closed', 'reopened'],
  playbookAction: ['execute', 'bulk_execute'],
};

export const ACTION_CATEGORIES = ['lookup', 'response'];

export const ACTION_CONTEXTS = [
  'asset', 'event', 'investigation', 'investigationV2', 'user', 'alert2', 'vdr_vulnerability_group', 'CloudResource', 'CloudObject', 'Email', 'EmailAddress',
  'File', 'FileHash', 'Script', 'IpAddress', 'DomainName', 'AuthDomain', 'URL', 'Certificate', 'Process', 'Function', 'Host', 'User', 'RegistryKey',
  'ScheduledTask', 'TaskAction', 'Service', 'identityFindings', 'hosts', 'case',
];

export const GENERIC_USAGE = ['notification', 'schedule', 'other'];

// The only connector category Fusion lists (connectorCategories, measured
// 21/11/2026). Any other value fails the import: "Invalid Connector Categories".
export const CONNECTOR_CATEGORIES = ['Generic'];

export const TEMPLATE_TYPES = ['None', 'ResponseAction', 'ContextualLookup', 'System'];

export const AUTH_TYPES = ['None', 'Platform', 'Raw', 'Basic', 'APIKey', 'ClientCerts', 'OAuthClientCreds', 'OAuthPassword', 'OAuthAuthCode', 'OAuthJWT', 'AuroraJWT', 'Custom', 'RSA', 'AWSv4', 'Kerberos', 'LDAP', 'AzureClientCertificate', 'GithubInstallation', 'Duo'];

export const CONNECTOR_METHODS = ['http', 'taegis', 'central', 'ldap'];

// Names every playbook expression can read besides task names.
export const PLAYBOOK_ROOTS = ['inputs', 'TDR', 'tenant'];

// Names a connector action's templates can read.
export const CONNECTOR_ROOTS = ['inputs', 'config', 'status', 'body', 'headers', 'auth', 'TDR', 'request', 'response', 'sophos', 'tenant'];

// A task named like one of these breaks every expression in the playbook
// ("overlapping identifier", measured 21/11/2026).
export const RESERVED_TASK_NAMES = ['int', 'uint', 'double', 'bool', 'string', 'bytes', 'list', 'map', 'null_type', 'type', 'dyn', 'timestamp', 'duration', 'inputs', 'TDR', 'tenant', 'has', 'size', 'matches', 'in'];

// CEL reserved words. A task with one of these names can be declared but never
// read: Fusion answers "reserved identifier" (measured 21/11/2026).
export const CEL_RESERVED_WORDS = ['as', 'break', 'const', 'continue', 'else', 'false', 'for', 'function', 'if', 'import', 'let', 'loop', 'namespace', 'null', 'package', 'return', 'true', 'var', 'void', 'while'];

// Fusion's own rule for task names (warning text: lower case characters and
// underscores, starts with a lower case character). Digits are accepted.
export const TASK_NAME = /^[a-z][a-z0-9_]*$/;

export const TEMPLATE_NAME = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)*$/;

// CEL type names, which an expression may use as values (type(x) == map).
export const CEL_TYPE_IDENTS = ['int', 'uint', 'double', 'bool', 'string', 'bytes', 'list', 'map', 'null_type', 'type', 'dyn'];

// Connectors the platform provides to every playbook without a connectors entry
// (Sophos's own templates call Taegis.Secureworks.summarize this way).
export const IMPLICIT_CONNECTORS = ['Taegis.Secureworks'];

// Events offered only to partner tenants.
export const PARTNER_ONLY_EVENTS = { case: ['Create Draft'], investigationNotification: ['Create Draft'], investigation: ['create draft'] };

export const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?$/;

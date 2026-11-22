// Fixed addresses and names shared by every script.

export const VERSION = '0.2.0';

export const AUTH_URL = 'https://id.sophos.com/api/v2/oauth2/token';
export const GLOBAL_API = 'https://api.central.sophos.com';
export const FUSION_GRAPHQL_URL = 'https://api.taegis.sophos.com/graphql';

// The only hosts a script will send a request to. A bearer token or client
// secret never leaves for anything else, whatever an API answer names.
export const ALLOWED_HOSTS = [
  /^id\.sophos\.com$/,
  /^api\.central\.sophos\.com$/,
  /^api-[a-z]{2}\d{2}\.central\.sophos\.com$/,
  /^api\.taegis\.sophos\.com$/,
];

// Names the scripts give to test copies. Templates and connectors only take
// letters, digits, dots and underscores, so they get the underscore form.
export const TEST_PREFIX = 'ZZTest_';
export const TEST_DISPLAY_PREFIX = 'ZZ Test ';

// Fields that change from tenant to tenant or are set by the platform on
// import. Export-and-diff ignores them.
export const TENANT_FIELDS = [
  'tenantId',
  'tenant',
  'isPlatformGlobal',
  'isCentralTenantVisible',
  'isVisibleToChildren',
  'featureCodes',
  'licenseCapabilities',
  'serviceLabels',
  'requiredPermissions',
  'icon',
];

export const EXIT = {
  ok: 0,
  failed: 1,
  usage: 2,
  refused: 3,
};

// Sophos Fusion automation operations: the GraphQL documents and thin
// wrappers the scripts call. Reads and writes are separated; every write here
// is reached only through a script that passed the write gate.

import { GraphQLError, SfsError } from './errors.mjs';

// ---------------------------------------------------------------- reads

export async function permissions(client) {
  const { data } = await client.request('query { authzPermissions { object actions { action effect } } }', {}, { operation: 'authzPermissions' });
  return data.authzPermissions || [];
}

/** The automation permissions that matter here, as { object: [actions allowed] }. */
export function summarizePermissions(perms) {
  const wanted = /^(Playbook|PlaybookInstance|Orchestration|Investigation|Alert|Tenant)/;
  const out = {};
  for (const p of perms) {
    if (!wanted.test(p.object)) continue;
    out[p.object] = p.actions.filter((a) => a.effect).map((a) => a.action).sort();
  }
  return out;
}

/** What the credential can do with automations, in plain terms. */
export function automationAbilities(perms) {
  const has = (object, action) => perms.some((p) => p.object === object && p.actions.some((a) => a.action === action && a.effect));
  return {
    readPlaybooks: has('Playbook', 'read'),
    importPlaybooks: has('Playbook', 'create'),
    deletePlaybooks: has('Playbook', 'delete'),
    runPlaybooks: has('Playbook', 'execute') || has('PlaybookInstance', 'execute'),
    manageInstances: has('PlaybookInstance', 'create') && has('PlaybookInstance', 'update') && has('PlaybookInstance', 'delete'),
    manageConnectors: has('OrchestrationConnector', 'create') && has('OrchestrationConnector', 'delete'),
    manageConnections: has('OrchestrationConnection', 'create') && has('OrchestrationConnection', 'delete'),
    readCases: has('Investigation', 'read'),
  };
}

const PLAYBOOK_FIELDS = 'id name isGlobal tags createdAt updatedAt head { id version title published } versions { id version published }';

export async function listPlaybooks(client) {
  const { data } = await client.request(`query { playbooks { ${PLAYBOOK_FIELDS} } }`, {}, { operation: 'playbooks' });
  return data.playbooks || [];
}

export async function getPlaybook(client, id) {
  try {
    const { data } = await client.request(`query($id: ID!) { playbook(playbookId: $id) { ${PLAYBOOK_FIELDS} instances { id name enabled } } }`, { id }, { operation: 'playbook' });
    return data.playbook ?? null;
  } catch (error) {
    if (error instanceof GraphQLError && error.notFound) return null;
    throw error;
  }
}

export async function findPlaybookByName(client, name) {
  const all = await listPlaybooks(client);
  return all.find((p) => p.name === name) ?? null;
}

/** A playbook version by "Name:version", including platform playbooks the list hides. */
export async function playbookVersionByName(client, nameAndVersion) {
  try {
    const { data } = await client.request(
      'query($n: String) { playbookVersion(arguments: { playbookVersionName: $n }) { id name version title inputs outputs playbook { id name isGlobal } } }',
      { n: nameAndVersion },
      { operation: 'playbookVersion' },
    );
    return data.playbookVersion ?? null;
  } catch (error) {
    if (error instanceof GraphQLError && error.notFound) return null;
    throw error;
  }
}

export async function exportPlaybook(client, { id, name, version }) {
  const args = {};
  if (id) args.playbookId = id;
  if (name) args.name = name;
  if (version) args.version = version;
  const { data } = await client.request('query($a: PlaybookExportArguments!) { playbookExport(arguments: $a) { export } }', { a: args }, { operation: 'playbookExport' });
  if (!data.playbookExport?.export) throw new SfsError('Fusion returned an empty export.', { code: 'empty_export' });
  return data.playbookExport.export;
}

const CONNECTOR_FIELDS = 'id name isGlobal tags createdAt head { id version title vendorName vendorProduct authTypes } versions { id version published } connections { id name }';

export async function listConnectors(client) {
  const { data } = await client.request(`query { connectors { ${CONNECTOR_FIELDS} } }`, {}, { operation: 'connectors' });
  return data.connectors || [];
}

export async function getConnector(client, { id, name }) {
  try {
    const { data } = await client.request(
      `query($id: ID, $n: String) { connector(connectorId: $id, connectorName: $n) { ${CONNECTOR_FIELDS} } }`,
      { id: id ?? null, n: name ?? null },
      { operation: 'connector' },
    );
    return data.connector ?? null;
  } catch (error) {
    if (error instanceof GraphQLError && error.notFound) return null;
    throw error;
  }
}

/** Connector versions by "Name:version", with their actions and input and output schemas. */
export async function connectorVersions(client, names) {
  if (!names.length) return [];
  const { data } = await client.request(
    'query($n: [String!]) { connectorVersions(arguments: { connectorVersionNames: $n }) { id version name connector { id name } actions { name description inputs outputs config } parameters authTypes } }',
    { n: names },
    { operation: 'connectorVersions' },
  );
  return data.connectorVersions || [];
}

export async function exportConnector(client, { id, name, version }) {
  const args = {};
  if (id) args.connectorId = id;
  if (name) args.name = name;
  if (version) args.version = version;
  const { data } = await client.request('query($a: ConnectorExportArguments!) { connectorExport(arguments: $a) { export } }', { a: args }, { operation: 'connectorExport' });
  if (!data.connectorExport?.export) throw new SfsError('Fusion returned an empty export.', { code: 'empty_export' });
  return data.connectorExport.export;
}

export async function searchConnectors(client, query, limit = 10) {
  const { data } = await client.request(
    'query($i: ConnectorsSearchInput!) { connectorsSearch(input: $i) { totalCount results { score connector { id name isGlobal head { version title description vendorName vendorProduct } } } } }',
    { i: { query, limit } },
    { operation: 'connectorsSearch' },
  );
  return data.connectorsSearch;
}

export async function listConnections(client) {
  const { data } = await client.request(
    'query { connections { id name description authType createdAt connector { id name } version { id version } versionStrategy healthStatus } }',
    {},
    { operation: 'connections' },
  );
  return data.connections || [];
}

export async function getConnection(client, id) {
  try {
    const { data } = await client.request(
      'query($id: ID) { connection(connectionId: $id) { id name authType connector { id name } version { id version } healthStatus } }',
      { id },
      { operation: 'connection' },
    );
    return data.connection ?? null;
  } catch (error) {
    if (error instanceof GraphQLError && error.notFound) return null;
    throw error;
  }
}

const INSTANCE_FIELDS = 'id name description enabled createdAt playbook { id name } version { id version } versionStrategy trigger { id name config type { id name } } inputs connections { id name connector { name } } schedules { id name cron paused }';

export async function listInstances(client) {
  const { data } = await client.request(`query { playbookInstances { ${INSTANCE_FIELDS} } }`, {}, { operation: 'playbookInstances' });
  return data.playbookInstances || [];
}

export async function getInstance(client, id) {
  try {
    const { data } = await client.request(`query($id: ID!) { playbookInstance(playbookInstanceId: $id) { ${INSTANCE_FIELDS} } }`, { id }, { operation: 'playbookInstance' });
    return data.playbookInstance ?? null;
  } catch (error) {
    if (error instanceof GraphQLError && error.notFound) return null;
    throw error;
  }
}

export async function listSchedules(client) {
  const out = [];
  for (let page = 1; page <= 50; page++) {
    const { data } = await client.request(
      'query($a: PlaybookSchedulesArguments!) { playbookSchedules(arguments: $a) { count results { id name cron timeZone paused nextRun playbookInstance { id name } } } }',
      { a: { page, perPage: 100 } },
      { operation: 'playbookSchedules' },
    );
    const r = data.playbookSchedules;
    out.push(...(r?.results || []));
    if (!r || out.length >= r.count || (r.results || []).length === 0) break;
  }
  return out;
}

/** Object counts used before and after live tests. */
export async function counts(client) {
  const [playbooks, connectors, connections, instances, schedules] = await Promise.all([
    listPlaybooks(client),
    listConnectors(client),
    listConnections(client),
    listInstances(client),
    listSchedules(client),
  ]);
  return {
    templates: playbooks.length,
    customTemplates: playbooks.filter((p) => !p.isGlobal).length,
    connectors: connectors.length,
    customConnectors: connectors.filter((c) => !c.isGlobal).length,
    connections: connections.length,
    instances: instances.length,
    schedules: schedules.length,
  };
}

export async function connectorCategories(client) {
  const { data } = await client.request('query { connectorCategories { id name } }', {}, { operation: 'connectorCategories' });
  return data.connectorCategories || [];
}

export async function triggerTypes(client) {
  const { data } = await client.request(
    'query { playbookTriggerTypesV2(arguments: {}) { id name title description required properties definitions } }',
    {},
    { operation: 'playbookTriggerTypesV2' },
  );
  return data.playbookTriggerTypesV2 || [];
}

export async function actionsCatalog(client, { page = 1, perPage = 100 } = {}) {
  const { data } = await client.request(
    'query($a: PlaybookActionsV2Arguments!) { playbookActionsV2(arguments: $a) { totalCount actions { id name description isEnabled responseMode category { name } context { name } } } }',
    { a: { page, perPage } },
    { operation: 'playbookActionsV2' },
  );
  return data.playbookActionsV2;
}

export async function interfaces(client) {
  const { data } = await client.request(
    'query { playbookInterfaces(arguments: {}) { id name isPlatformGlobal head { id version title description inputs outputs } } }',
    {},
    { operation: 'playbookInterfaces' },
  );
  return data.playbookInterfaces || [];
}

export async function celFunctions(client, search = '') {
  const { data } = await client.request(
    'query($a: SuggestExpressionArguments!) { suggestExpression(arguments: $a) { results { name description returnType inputTypes usage { expression result } } } }',
    { a: { searchString: search } },
    { operation: 'suggestExpression' },
  );
  return data.suggestExpression?.results || [];
}

/** Run CEL in Fusion's own engine. Only `inputs` is bound. */
export async function evaluate(client, expression, inputs) {
  const { data } = await client.request(
    'query($i: ExprInput!) { evaluateExpr(input: $i) { output errorMessage } }',
    { i: { expression, ...(inputs !== undefined ? { inputs } : {}) } },
    { operation: 'evaluateExpr' },
  );
  return data.evaluateExpr;
}

export async function validateDsl(client, { yaml, connectors = [], playbooks = [], interfaces: ifaces = [], inputs }) {
  const a = { yaml };
  if (connectors.length) a.connectors = connectors;
  if (playbooks.length) a.playbooks = playbooks;
  if (ifaces.length) a.interfaces = ifaces;
  if (inputs) a.inputs = inputs;
  const { data } = await client.request(
    'query($a: PlaybookValidationArgumentsV2!) { playbookValidateDSLV2(arguments: $a) { errors { message lineno } warnings { message lineno } } }',
    { a },
    { operation: 'playbookValidateDSLV2' },
  );
  return data.playbookValidateDSLV2;
}

export async function interfaceVersions(client, names) {
  const all = await interfaces(client);
  const out = [];
  for (const n of names) {
    const [name, version] = n.split(':');
    const i = all.find((x) => x.name === name);
    if (i && (!version || i.head?.version === version)) out.push({ name: n, id: i.head.id });
    else out.push({ name: n, id: null });
  }
  return out;
}

const EXECUTION_FIELDS = 'id state outcomeStatus outcomeMessage createdAt updatedAt executionTime triggerCategory triggerContext reason targetResource instance { id name } version { id version name }';

export async function listExecutions(client, { instanceId, first = 20, states } = {}) {
  const a = { first, sortBy: 'createdAt', orderBy: 'DESCENDING' };
  if (instanceId) a.playbookInstanceId = instanceId;
  if (states?.length) a.states = states;
  const { data } = await client.request(
    `query($a: PlaybookExecutionsV2Arguments!) { playbookExecutionsV2(arguments: $a) { totalCount playbookExecutions { ${EXECUTION_FIELDS} } } }`,
    { a },
    { operation: 'playbookExecutionsV2' },
  );
  return data.playbookExecutionsV2;
}

export async function getExecution(client, id, { full = false } = {}) {
  const read = async (fields) => {
    try {
      const { data, warnings } = await client.request(`query($id: ID!) { playbookExecution(playbookExecutionId: $id) { ${EXECUTION_FIELDS} ${fields} } }`, { id }, { operation: 'playbookExecution' });
      return data.playbookExecution ? { ...data.playbookExecution, ...(warnings.length ? { readWarnings: warnings } : {}) } : null;
    } catch (error) {
      if (error instanceof GraphQLError && error.notFound) return null;
      throw error;
    }
  };
  if (!full) return read('');
  let eventsError = null;
  try {
    const e = await read('inputs outputs summary events { id name state timestamp reason attempt inputs outputs }');
    if (e) return e;
    eventsError = 'the run read as missing when its task events were included';
  } catch (error) {
    if (!(error instanceof GraphQLError)) throw error;
    eventsError = error.message;
  }
  // A task event that fails to resolve nulls the whole run in the answer; read it without events
  const e = await read('inputs outputs summary');
  return e ? { ...e, events: null, eventsError } : null;
}

/** A run right after it finishes can read as missing for a moment; poll briefly. */
export async function getExecutionSettled(client, id, { full = false, timeoutMs = 15_000 } = {}) {
  const r = await pollUntil(() => getExecution(client, id, { full }), { timeoutMs, intervalMs: 1500 });
  return r.value ?? null;
}

export async function executionLogs(client, id) {
  const { data } = await client.request(
    'query($id: ID!) { playbookExecutionLogs(playbookExecutionId: $id) { id taskID parentID message children statusLogs createdAt } }',
    { id },
    { operation: 'playbookExecutionLogs' },
  );
  return data.playbookExecutionLogs || [];
}

export const TERMINAL_STATES = ['Completed', 'Failed', 'Canceled', 'TimedOut', 'Dropped', 'Denied'];

// ---------------------------------------------------------------- writes

export async function importPlaybook(client, content, filename = 'template.yaml') {
  const { data } = await client.upload('mutation($input: ImportPlaybookInput!) { importPlaybookV2(input: $input) { id name head { id version published } } }', { filename, content }, { operation: 'importPlaybookV2' });
  return data.importPlaybookV2;
}

export async function importConnector(client, content, filename = 'connector.yaml') {
  const { data } = await client.upload('mutation($input: ImportConnectorInput!) { importConnector(input: $input) { id name head { id version published } } }', { filename, content }, { operation: 'importConnector' });
  return data.importConnector;
}

export async function deletePlaybook(client, id) {
  const { data } = await client.request('mutation($x: DeletePlaybookInput!) { deletePlaybook(input: $x) { id name } }', { x: { playbookId: id } }, { operation: 'deletePlaybook' });
  return data.deletePlaybook;
}

export async function deleteConnector(client, id) {
  const { data } = await client.request('mutation($x: DeleteConnectorInput!) { deleteConnector(input: $x) { id name } }', { x: { connectorId: id } }, { operation: 'deleteConnector' });
  return data.deleteConnector;
}

export async function createConnection(client, connectorId, connection) {
  const { data } = await client.request('mutation($c: ID!, $x: ConnectionInput!) { createConnection(connectorId: $c, connection: $x) { id name authType connector { name } version { version } } }', { c: connectorId, x: connection }, { operation: 'createConnection' });
  return data.createConnection;
}

export async function deleteConnection(client, id) {
  const { data } = await client.request('mutation($id: ID!) { deleteConnection(connectionId: $id) { id name } }', { id }, { operation: 'deleteConnection' });
  return data.deleteConnection;
}

/** Validate a connection that does not exist yet. Fusion may call the vendor to do it. */
export async function validateConnectionInput(client, connectorId, connection) {
  const { data } = await client.request('mutation($c: ID!, $x: ConnectionInput!) { validateConnectionInput(connectorId: $c, connection: $x) { id name } }', { c: connectorId, x: connection }, { operation: 'validateConnectionInput' });
  return data.validateConnectionInput;
}

export async function createInstance(client, playbookId, instance) {
  const { data } = await client.request(`mutation($p: ID!, $i: PlaybookInstanceInput!) { createPlaybookInstance(playbookId: $p, instance: $i) { ${INSTANCE_FIELDS} } }`, { p: playbookId, i: instance }, { operation: 'createPlaybookInstance' });
  return data.createPlaybookInstance;
}

export async function updateInstance(client, input) {
  const { data } = await client.request(`mutation($i: UpdatePlaybookInstanceInput!) { updatePlaybookInstanceV2(input: $i) { ${INSTANCE_FIELDS} } }`, { i: input }, { operation: 'updatePlaybookInstanceV2' });
  return data.updatePlaybookInstanceV2;
}

export async function deleteInstance(client, id) {
  const { data } = await client.request('mutation($id: ID!) { deletePlaybookInstance(playbookInstanceId: $id) { id name } }', { id }, { operation: 'deletePlaybookInstance' });
  return data.deletePlaybookInstance;
}

export async function createSchedule(client, input) {
  const { data } = await client.request('mutation($i: CreatePlaybookScheduleInput!) { createPlaybookSchedule(input: $i) { id name cron timeZone paused nextRun playbookInstance { id name } } }', { i: input }, { operation: 'createPlaybookSchedule' });
  return data.createPlaybookSchedule;
}

export async function deleteSchedule(client, id) {
  const { data } = await client.request('mutation($i: DeletePlaybookScheduleInput!) { deletePlaybookSchedule(input: $i) { id name } }', { i: { scheduleId: id } }, { operation: 'deletePlaybookSchedule' });
  return data.deletePlaybookSchedule;
}

export async function pauseSchedule(client, id, reason, pause = true) {
  const op = pause ? 'pausePlaybookSchedule' : 'unpausePlaybookSchedule';
  const { data } = await client.request(`mutation($i: PausePlaybookScheduleInput!) { ${op}(input: $i) { id name paused } }`, { i: { scheduleId: id, reason } }, { operation: op });
  return data[op];
}

export async function publishPlaybookVersion(client, versionId, version) {
  const { data } = await client.request('mutation($i: PublishPlaybookVersionInput!) { publishPlaybookVersion(input: $i) { id version published } }', { i: { playbookVersionId: versionId, version } }, { operation: 'publishPlaybookVersion' });
  return data.publishPlaybookVersion;
}

export async function executeInstance(client, input) {
  const { data } = await client.request(`mutation($i: ExecutePlaybookInstanceV2Input!) { executePlaybookInstanceV2(input: $i) { ${EXECUTION_FIELDS} } }`, { i: input }, { operation: 'executePlaybookInstanceV2' });
  return data.executePlaybookInstanceV2;
}

export async function cancelExecutions(client, ids, reason) {
  const { data } = await client.request('mutation($i: CancelPlaybookExecutionInput!) { cancelPlaybookExecution(input: $i) { id state } }', { i: { executionIDs: ids, reason } }, { operation: 'cancelPlaybookExecution' });
  return data.cancelPlaybookExecution;
}

/** Run one action on a live connection. Fusion calls the vendor for real. */
export async function executeConnectionAction(client, connectionId, actionName, inputs) {
  const { data } = await client.request('mutation($c: ID!, $a: String!, $i: Any) { executeConnectionAction(connectionId: $c, actionName: $a, inputs: $i) }', { c: connectionId, a: actionName, i: inputs ?? {} }, { operation: 'executeConnectionAction' });
  return data.executeConnectionAction;
}

/** Test an action definition against an ad hoc connection. Fusion calls the vendor for real. */
export async function verifyConnectorAction(client, connectorId, input) {
  const { data } = await client.request('mutation($c: ID!, $i: TestConnectorActionInputV2!) { verifyConnectorActionV2(connectorId: $c, input: $i) }', { c: connectorId, i: input }, { operation: 'verifyConnectorActionV2' });
  return data.verifyConnectorActionV2;
}

// ---------------------------------------------------------------- read-back

/** How long a read-back waits for a write to show. SOPHOS_FUSION_READBACK_MS overrides the 30 s default. */
export function readbackTimeoutMs(env = process.env) {
  const v = Number(env.SOPHOS_FUSION_READBACK_MS);
  return Number.isFinite(v) && v > 0 ? v : 30_000;
}

/**
 * Poll until `check` returns a truthy value or the deadline passes. Reads lag
 * writes on Fusion, so one disagreeing read proves nothing.
 */
export async function pollUntil(check, { timeoutMs = readbackTimeoutMs(), intervalMs, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) } = {}) {
  intervalMs = intervalMs ?? Math.min(2000, Math.max(50, Math.floor(timeoutMs / 10)));
  const start = Date.now();
  let last;
  for (;;) {
    last = await check();
    if (last) return { ok: true, value: last, waitedMs: Date.now() - start };
    if (Date.now() - start >= timeoutMs) return { ok: false, value: last, waitedMs: Date.now() - start };
    await sleep(intervalMs);
  }
}

/** Read an object by kind and ID; null when it is gone. */
export async function readObject(client, kind, id) {
  switch (kind) {
    case 'playbook':
      return getPlaybook(client, id);
    case 'connector':
      return getConnector(client, { id });
    case 'connection':
      return getConnection(client, id);
    case 'instance':
      return getInstance(client, id);
    case 'schedule':
      return (await listSchedules(client)).find((s) => s.id === id) ?? null;
    default:
      throw new SfsError(`Cannot read objects of kind ${kind}.`, { code: 'internal' });
  }
}

export async function deleteObject(client, kind, id) {
  switch (kind) {
    case 'playbook':
      return deletePlaybook(client, id);
    case 'connector':
      return deleteConnector(client, id);
    case 'connection':
      return deleteConnection(client, id);
    case 'instance':
      return deleteInstance(client, id);
    case 'schedule':
      return deleteSchedule(client, id);
    default:
      throw new SfsError(`Cannot delete objects of kind ${kind}.`, { code: 'internal' });
  }
}

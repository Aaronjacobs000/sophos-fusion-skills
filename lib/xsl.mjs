// The one import point for the vendored Unofficial Sophos Fusion XDR and SIEM Library code
// (vendor/xdr-siem-library, see its VENDORED.md). Scripts import from here, never from vendor/
// directly, so a re-sync with tools/sync-library.mjs touches this file only when the library's
// exports change.

export { runParsers, compileParser, expectedShape, schemaList, ENGINE_NOTE } from '../vendor/xdr-siem-library/studio/core/engine.js';
export { lintParsers } from '../vendor/xdr-siem-library/studio/core/lint.js';
export { parseScript } from '../vendor/xdr-siem-library/studio/core/language.js';
export { compileGo, checkRe2 } from '../vendor/xdr-siem-library/studio/core/goregex.js';
export { isIpv4, isIpv6 } from '../vendor/xdr-siem-library/studio/core/formats.js';
export {
  SCHEMA_DATA,
  SCHEMA_IDS,
  GENERIC,
  schemaInfo,
  fieldsByParser,
  enumMembers,
  enumNumbers,
  messageType,
  typeKind,
} from '../vendor/xdr-siem-library/studio/core/schemas.js';
export {
  parseQuery,
  conditions,
  topConjuncts,
  matches,
  qlName,
  schemaFromQlName,
  ruleQueryProblems,
  pinnedSensorTypes,
  regexLimits,
  fieldPath,
  QlError,
} from '../vendor/xdr-siem-library/studio/core/ql.js';
export {
  compileRules,
  ruleHits,
  compareTests,
  RULE_KINDS,
  SEVERITIES,
  CASE_SEVERITIES,
  CUSTOM_DETECTOR,
  RULE_PATH,
  PARSER_PATH,
} from '../vendor/xdr-siem-library/studio/core/rules.js';
export {
  validateEntry,
  validateMeta,
  expectedFrom,
  compareExpected,
  packBundle,
  unpackBundle,
  parseSamples,
  entryId,
  slug,
  toEngineParsers,
  LICENSES,
  FORMATS,
  SAMPLE_SOURCES,
  LIMITS as LIBRARY_LIMITS,
  ALLOWED_FILES,
} from '../vendor/xdr-siem-library/studio/core/library.js';
export { scanText, scanFiles } from '../vendor/xdr-siem-library/studio/core/scan.js';
export { findGenericApiKeys, gitleaksProblems } from '../vendor/xdr-siem-library/studio/core/gitleaks.js';
export { aboutProblems } from '../vendor/xdr-siem-library/studio/core/notes.js';
export { analyseSample } from '../vendor/xdr-siem-library/studio/core/detect.js';
export { analyse, buildPlan, writeParsers } from '../vendor/xdr-siem-library/studio/app/plan.js';
export { TOOL_VERSION as LIBRARY_TOOL_VERSION, REPO as LIBRARY_REPO } from '../vendor/xdr-siem-library/studio/core/version.js';

/** LOCAL METADATA PROTOTYPE ONLY. Not imported by any production server.
 *
 * Prepares a proposed OAuth scope request independently of API scope checks.
 * This function neither authenticates an owner nor proves consent/host support.
 * Input is trusted experiment configuration, never a world/tool-call argument.
 */
import {readFileSync} from 'node:fs';

const tools = JSON.parse(readFileSync(new URL('../../adapter-contract.json', import.meta.url)))['x-tools'];
const knownApiScopes = new Set(tools.flatMap(t => t.requiredScopes));
const byName = new Map(tools.map(t => [t.name, t]));
const credentialScopeAllowlist = new Set(['offline_access']);

function checkedStrings(value, allowlist, label) {
  const invalid = () => {throw new TypeError(`invalid ${label}`);};
  if (!Array.isArray(value) || value.length > allowlist.size) invalid();
  // A single dense data-property snapshot: do not validate one representation
  // and later copy a caller-controlled iterator/getter with different values.
  if (Reflect.ownKeys(value).some(k => k !== 'length'
      && (typeof k !== 'string' || !/^(0|[1-9][0-9]*)$/.test(k) || Number(k) >= value.length))) invalid();
  const snapshot = [];
  for (let i = 0; i < value.length; i++) {
    const property = Object.getOwnPropertyDescriptor(value, String(i));
    if (!property || !Object.hasOwn(property, 'value') || typeof property.value !== 'string'
        || !allowlist.has(property.value) || snapshot.includes(property.value)) invalid();
    snapshot.push(property.value);
  }
  return snapshot;
}

const frozenScheme = scopes => Object.freeze([
  Object.freeze({type: 'oauth2', scopes: Object.freeze([...scopes])})
]);

/**
 * Separate returned fields deliberately:
 * - apiRequiredScopes: existing authoritative operation requirements, unchanged.
 * - consentRequestScopes: proposed host consent metadata; NOT API requirements.
 * - credentialRequestScopes: explicit, optional experiment request, no grants.
 *
 * Optional credential scopes are restricted to existing read-only tools in this
 * prototype. A future adapter must keep its existing pre-dispatch authentication
 * gate and pass ONLY apiRequiredScopes to requireScopes/the resource verifier.
 */
export function prepareToolScopePolicy(toolName, options = {}) {
  if (typeof toolName !== 'string' || !byName.has(toolName)) {
    throw new TypeError('unknown canonical tool');
  }
  if (!options || typeof options !== 'object' || Array.isArray(options)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(options))
      || Reflect.ownKeys(options).some(k => k !== 'credentialRequestScopes')) {
    throw new TypeError('invalid policy options');
  }
  const requested = Object.getOwnPropertyDescriptor(options, 'credentialRequestScopes');
  if (requested && !Object.hasOwn(requested, 'value')) throw new TypeError('invalid policy options');
  const tool = byName.get(toolName);
  const apiRequiredScopes = checkedStrings(tool.requiredScopes, knownApiScopes, 'operation scopes');
  const credentialRequestScopes = checkedStrings(
    requested ? requested.value : [],
    credentialScopeAllowlist, 'credential request scopes');
  if (credentialRequestScopes.length && tool.mutates !== false) {
    throw new TypeError('credential request experiment is read-only');
  }
  const consentRequestScopes = [...apiRequiredScopes, ...credentialRequestScopes];
  return Object.freeze({
    toolName,
    requiresAuthentication: true,
    apiRequiredScopes: Object.freeze(apiRequiredScopes),
    credentialRequestScopes: Object.freeze(credentialRequestScopes),
    consentRequestScopes: Object.freeze(consentRequestScopes),
    securitySchemes: frozenScheme(consentRequestScopes),
    _meta: Object.freeze({securitySchemes: frozenScheme(consentRequestScopes)}),
  });
}

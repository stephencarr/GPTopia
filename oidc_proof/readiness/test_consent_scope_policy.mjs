// Synthetic, offline policy/installed-SDK regression only; no server or grant.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {prepareToolScopePolicy} from './consent_scope_policy.mjs';

// Reuse the already installed SDK; do not install a second version or dependency.
const require = createRequire(process.env.GPTOPIA_MCP_TEST_PACKAGE
  ?? new URL('../../mcp_adapter/package.json', import.meta.url));
const {requireScopes} = await import(require.resolve('@modelcontextprotocol/server'));
const contractPath = new URL('../../adapter-contract.json', import.meta.url);
const originalContract = readFileSync(contractPath, 'utf8');
const tools = JSON.parse(originalContract)['x-tools'];

function challenge(policy, scopes) {
  return requireScopes(...policy.apiRequiredScopes)({authInfo: {scopes}});
}

test('default policy preserves API and consent scopes for all nine canonical operations', () => {
  assert.equal(tools.length, 9);
  for (const tool of tools) {
    const policy = prepareToolScopePolicy(tool.name);
    assert.equal(policy.requiresAuthentication, true);
    assert.deepEqual(policy.apiRequiredScopes, tool.requiredScopes);
    assert.deepEqual(policy.consentRequestScopes, tool.requiredScopes);
    assert.deepEqual(policy.credentialRequestScopes, []);
    assert.deepEqual(policy.securitySchemes, [{type: 'oauth2', scopes: tool.requiredScopes}]);
    assert.deepEqual(policy._meta.securitySchemes, policy.securitySchemes);
    assert.equal(challenge(policy, tool.requiredScopes), undefined);
  }
});

test('opt-in read consent metadata includes offline_access but API requirements do not', () => {
  for (const tool of tools.filter(t => !t.mutates)) {
    const policy = prepareToolScopePolicy(tool.name, {credentialRequestScopes: ['offline_access']});
    assert.deepEqual(policy.apiRequiredScopes, tool.requiredScopes);
    assert.deepEqual(policy.consentRequestScopes, [...tool.requiredScopes, 'offline_access']);
    assert.deepEqual(policy.securitySchemes[0].scopes, policy.consentRequestScopes);
    assert.deepEqual(policy._meta.securitySchemes, policy.securitySchemes);
    assert.equal(challenge(policy, tool.requiredScopes), undefined);
    assert.deepEqual(challenge(policy, ['offline_access']), {scopes: tool.requiredScopes});
    assert.deepEqual(challenge(policy, []), {scopes: tool.requiredScopes});
  }
});

test('optional scope requests are unavailable for mutating operations', () => {
  for (const tool of tools.filter(t => t.mutates)) {
    assert.throws(() => prepareToolScopePolicy(tool.name, {credentialRequestScopes: ['offline_access']}), /read-only/);
    const policy = prepareToolScopePolicy(tool.name);
    assert.deepEqual(challenge(policy, ['messages:read', 'offline_access']), {scopes: tool.requiredScopes});
  }
});

test('read credential metadata cannot satisfy send, write or accept requirements', () => {
  const readPolicy = prepareToolScopePolicy('world_inbox', {credentialRequestScopes: ['offline_access']});
  for (const name of ['world_send', 'world_create', 'world_update', 'world_accept']) {
    const writePolicy = prepareToolScopePolicy(name);
    assert.deepEqual(challenge(writePolicy, readPolicy.consentRequestScopes), {scopes: writePolicy.apiRequiredScopes});
  }
});

test('unknown, malformed, duplicate and application scopes in credential options fail closed', () => {
  const invalid = [null, 'offline_access', {}, [1], [''], ['offline_access offline_access'],
    ['offline_access\n'], ['offline_access', 'offline_access'], ['openid'], ['new:scope'],
    ['messages:send'], ['objects:write'], ['objects:accept'], ['world:discover'],
    ['offline_access', 'objects:write']];
  for (const value of invalid) {
    // Explicit null must not silently become an empty request.
    assert.throws(() => prepareToolScopePolicy('world_inbox', {credentialRequestScopes: value}), /invalid/);
  }
});

test('unknown tools and unsupported options cannot replace canonical requirements', () => {
  for (const name of ['world_inbox ', 'world_read', '', null, {}, '__proto__']) {
    assert.throws(() => prepareToolScopePolicy(name), /unknown canonical tool/);
  }
  for (const options of [null, [], false, 'offline_access', {requiredScopes: []},
    {apiRequiredScopes: []}, {mutates: false}, {credentialRequestScopes: [], grant: true}]) {
    assert.throws(() => prepareToolScopePolicy('world_inbox', options), /invalid policy options/);
  }
});

test('returned metadata is deeply frozen and detached from caller arrays and mirrors', () => {
  const requested = ['offline_access'];
  const policy = prepareToolScopePolicy('world_inbox', {credentialRequestScopes: requested});
  requested.push('objects:write');
  assert.deepEqual(policy.credentialRequestScopes, ['offline_access']);
  assert.notEqual(policy.securitySchemes, policy._meta.securitySchemes);
  assert.notEqual(policy.securitySchemes[0].scopes, policy._meta.securitySchemes[0].scopes);
  for (const target of [policy.apiRequiredScopes, policy.credentialRequestScopes,
    policy.consentRequestScopes, policy.securitySchemes, policy.securitySchemes[0].scopes,
    policy._meta.securitySchemes, policy._meta.securitySchemes[0].scopes]) {
    assert.throws(() => target.push('objects:write'), TypeError);
  }
  assert.throws(() => {policy.requiresAuthentication = false;}, TypeError);
  assert.throws(() => {policy._meta.securitySchemes = [];}, TypeError);
  assert.deepEqual(prepareToolScopePolicy('world_inbox').consentRequestScopes, ['messages:read']);
});

test('serialization retains equal metadata mirrors but makes no grant or credential claim', () => {
  const serialized = JSON.parse(JSON.stringify(prepareToolScopePolicy('world_inbox', {
    credentialRequestScopes: ['offline_access'],
  })));
  assert.deepEqual(serialized.securitySchemes, serialized._meta.securitySchemes);
  assert.equal(serialized.access_token, undefined);
  assert.equal(serialized.refresh_token, undefined);
  assert.equal(serialized.grantedScopes, undefined);
});

test('ordinary scope gating still depends on the existing upstream authentication boundary', () => {
  const policy = prepareToolScopePolicy('world_inbox', {credentialRequestScopes: ['offline_access']});
  // The installed SDK deliberately leaves missing auth to the server's gate.
  // This prototype must not be presented as an authentication implementation.
  assert.equal(requireScopes(...policy.apiRequiredScopes)({}), undefined);
  assert.equal(policy.requiresAuthentication, true);
});

test('prototype calls do not alter the authoritative operation contract', () => {
  assert.equal(readFileSync(contractPath, 'utf8'), originalContract);
});

test('sparse credential arrays and explicitly undefined values fail closed', () => {
  for (const scopes of [Array(1), undefined]) {
    assert.throws(() => prepareToolScopePolicy('world_inbox', {credentialRequestScopes: scopes}), /invalid/);
  }
});

test('credential opt-in must be an own data property on a plain configuration record', () => {
  const inherited = Object.create({credentialRequestScopes: ['offline_access']});
  assert.throws(() => prepareToolScopePolicy('world_inbox', inherited), /invalid policy options/);
  let getterCalls = 0;
  const getter = {get credentialRequestScopes() {getterCalls++; return ['offline_access'];}};
  assert.throws(() => prepareToolScopePolicy('world_inbox', getter), /invalid policy options/);
  assert.equal(getterCalls, 0);
  const explicit = Object.create(null);
  explicit.credentialRequestScopes = ['offline_access'];
  assert.deepEqual(prepareToolScopePolicy('world_inbox', explicit).credentialRequestScopes, ['offline_access']);
});

test('caller-controlled array iterator cannot substitute an API permission', () => {
  const scopes = ['offline_access'];
  let iteratorCalls = 0;
  scopes[Symbol.iterator] = function* () {iteratorCalls++; yield 'objects:write';};
  assert.throws(() => prepareToolScopePolicy('world_inbox', {credentialRequestScopes: scopes}), /invalid/);
  assert.equal(iteratorCalls, 0);
});

test('scope-array accessors and nonstandard option keys are rejected without invoking getters', () => {
  const scopes = ['offline_access'];
  let calls = 0;
  Object.defineProperty(scopes, '0', {get() {calls++; return 'offline_access';}});
  assert.throws(() => prepareToolScopePolicy('world_inbox', {credentialRequestScopes: scopes}), /invalid/);
  assert.equal(calls, 0);
  const hidden = {};
  Object.defineProperty(hidden, 'apiRequiredScopes', {value: []});
  assert.throws(() => prepareToolScopePolicy('world_inbox', hidden), /invalid policy options/);
  assert.throws(() => prepareToolScopePolicy('world_inbox', {[Symbol('hidden')]: true}), /invalid policy options/);
});

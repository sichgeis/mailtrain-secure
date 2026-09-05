'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {enforceUnrestrictedIdentity, validateCapability} = require('../../lib/capability-policy');

test('account operations reject all restricted and missing identities', () => {
    for (const user of [undefined, {id: 7, restrictedAccessToken: 'cap'}, {id: 7, restrictedAccessMethod: 'editor'}, {id: 7, restrictedAccessHandler: {}}]) {
        assert.throws(() => enforceUnrestrictedIdentity({user}), /permission/i);
    }
    assert.doesNotThrow(() => enforceUnrestrictedIdentity({user: {id: 7}}));
});

test('capabilities fail closed for absent, empty, wildcard, or malformed permissions', () => {
    for (const handler of [undefined, null, {}, {permissions: {}}, {permissions: {template: true}}, {permissions: {template: {1: ['view']}}}]) {
        assert.throws(() => validateCapability(handler), /permission/i);
    }
    assert.doesNotThrow(() => validateCapability({permissions: {template: {1: new Set(['view'])}}}));
});

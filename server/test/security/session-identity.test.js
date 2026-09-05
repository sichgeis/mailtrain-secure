'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {createIdentity, validIdentity, sessionUser} = require('../../lib/session-identity');

test('sessions have an absolute lifetime and reject legacy or revoked identities', () => {
    const user = {id: 12, auth_version: 3};
    const identity = createIdentity(user, false, 1000);
    assert.equal(validIdentity(identity, user, 1001), true);
    assert.equal(validIdentity(identity, user, 1000 + 12 * 60 * 60 * 1000), false);
    assert.equal(validIdentity(identity, {...user, auth_version: 4}, 1001), false);
    assert.equal(validIdentity(identity, {...user, id: 13}, 1001), false);
    for (const legacy of [12, null, {id: 12, role: 'master'}]) {
        assert.equal(validIdentity(legacy, user, 1001), false);
    }
    assert.equal(validIdentity(createIdentity(user, true, 1000), user, 1000 + 29 * 86400000), true);
    assert.equal(validIdentity(createIdentity(user, true, 1000), user, 1000 + 30 * 86400000), false);
    assert.equal(validIdentity({...identity, issuedAt: 2000}, user, 1001), false);
});

test('external display profiles cannot preserve stale role or namespace authority', () => {
    const current = {id: 12, role: 'nobody', namespace: 3, auth_version: 4};
    const identity = {...createIdentity(current, false), profile: {name: 'Directory Name', email: 'synthetic@example.invalid', role: 'master', namespace: 1}};
    assert.deepEqual(sessionUser(identity, current), {...current, name: 'Directory Name', email: 'synthetic@example.invalid'});
});

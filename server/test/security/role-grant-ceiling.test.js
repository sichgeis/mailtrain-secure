'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
    globalRoleRequiresElevatedAssignment,
    isPermissionSubset,
    isRoleGrantWithinProfile
} = require('../../lib/role-grants');

test('permission grants must be a subset of the grantor permissions', () => {
    assert.equal(isPermissionSubset(['view'], ['view', 'edit']), true);
    assert.equal(isPermissionSubset(['view', 'edit'], ['view']), false);
    assert.equal(isPermissionSubset([], []), true);
});

test('namespace role ceilings include every descendant entity type', () => {
    const grantor = {
        permissions: ['view', 'share', 'createCampaign'],
        children: {
            campaign: ['view', 'edit', 'share'],
            list: ['view']
        }
    };

    assert.equal(isRoleGrantWithinProfile({
        permissions: ['view'],
        children: {
            campaign: ['view', 'edit'],
            list: ['view']
        }
    }, grantor), true);

    assert.equal(isRoleGrantWithinProfile({
        permissions: ['view'],
        children: {
            campaign: ['view', 'edit', 'delete']
        }
    }, grantor), false);
});

test('only privilege-bearing global roles require elevated assignment authority', () => {
    assert.equal(globalRoleRequiresElevatedAssignment({permissions: []}), false);
    assert.equal(globalRoleRequiresElevatedAssignment({permissions: ['setupAutomation']}), true);
    assert.equal(globalRoleRequiresElevatedAssignment({permissions: [], ownNamespaceRole: 'viewer'}), true);
    assert.equal(globalRoleRequiresElevatedAssignment({permissions: [], rootNamespaceRole: 'master'}), true);
    assert.equal(globalRoleRequiresElevatedAssignment({permissions: [], sharedNamespaces: {2: 'viewer'}}), true);
});

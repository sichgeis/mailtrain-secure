'use strict';

const assert = require('node:assert/strict');
const config = require('../../lib/config');
const {assertSafeTestDatabase} = require('../../lib/test-database-safety');
const interoperableErrors = require('../../../shared/interoperable-errors');

assertSafeTestDatabase({
    environment: process.env.NODE_ENV,
    database: config.mysql.database,
    allowDestructiveTests: process.env.ALLOW_DESTRUCTIVE_TESTS
});

async function expectPermissionDenied(action) {
    await assert.rejects(action, err => err instanceof interoperableErrors.PermissionDeniedError);
}

async function run() {
    // Loading models only after the destructive-test guard keeps accidental connections fail-closed.
    // eslint-disable-next-line global-require
    const knex = require('../../lib/knex');
    // eslint-disable-next-line global-require
    const contextHelpers = require('../../lib/context-helpers');
    // eslint-disable-next-line global-require
    const namespaces = require('../../models/namespaces');
    // eslint-disable-next-line global-require
    const shares = require('../../models/shares');
    // eslint-disable-next-line global-require
    const users = require('../../models/users');

    const adminContext = contextHelpers.getAdminContext();

    try {
        const tenantNamespaceId = await namespaces.create(adminContext, {
            name: 'Synthetic RBAC tenant',
            description: 'Security regression fixture',
            namespace: 1
        });

        const attackerId = await users.create(adminContext, {
            username: 'rbac-campaigns-admin',
            name: 'Synthetic Campaigns Admin',
            email: 'rbac-campaigns-admin@example.invalid',
            password: 'Synthetic-RBAC-Password-123!',
            namespace: tenantNamespaceId,
            role: 'campaignsAdmin'
        });
        const controlledUserId = await users.create(adminContext, {
            username: 'rbac-controlled-user',
            name: 'Synthetic Controlled User',
            email: 'rbac-controlled-user@example.invalid',
            password: 'Synthetic-RBAC-Password-123!',
            namespace: tenantNamespaceId,
            role: 'nobody'
        });

        const attacker = await knex('users').where({id: attackerId}).first();
        const attackerContext = {user: attacker};
        const childNamespaceId = await namespaces.create(attackerContext, {
            name: 'Synthetic attacker child',
            description: 'Exploit-chain child namespace',
            namespace: tenantNamespaceId
        });

        await expectPermissionDenied(() => shares.assign(
            attackerContext,
            'namespace',
            childNamespaceId,
            controlledUserId,
            'master'
        ));

        // Simulate an over-privileged legacy share to prove manageUsers alone cannot mint a global master.
        await knex('shares_namespace').insert({
            user: controlledUserId,
            entity: childNamespaceId,
            role: 'master',
            auto: false
        });
        await shares.rebuildPermissions({userId: controlledUserId});

        const controlledUser = await knex('users').where({id: controlledUserId}).first();
        const controlledContext = {user: controlledUser};
        await expectPermissionDenied(() => users.create(controlledContext, {
            username: 'rbac-global-master-attempt',
            name: 'Synthetic Global Master Attempt',
            email: 'rbac-global-master-attempt@example.invalid',
            password: 'Synthetic-RBAC-Password-123!',
            namespace: childNamespaceId,
            role: 'master'
        }));

        const localUserId = await users.create(controlledContext, {
            username: 'rbac-local-user',
            name: 'Synthetic Local User',
            email: 'rbac-local-user@example.invalid',
            password: 'Synthetic-RBAC-Password-123!',
            namespace: childNamespaceId,
            role: 'nobody'
        });
        assert.ok(localUserId > 0);

        await shares.assign(controlledContext, 'namespace', childNamespaceId, localUserId, 'campaignsViewer');
        const assignedRole = await knex('shares_namespace')
            .where({user: localUserId, entity: childNamespaceId, auto: false})
            .select('role')
            .first();
        assert.equal(assignedRole.role, 'campaignsViewer');

        process.stdout.write('Validated RBAC grant ceilings and legitimate namespace administration\n');
    } finally {
        await knex.destroy();
    }
}

run().catch(err => {
    process.stderr.write(`${err.stack || err}\n`);
    process.exitCode = 1;
});

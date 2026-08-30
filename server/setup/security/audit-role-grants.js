'use strict';

const config = require('../../lib/config');
const knex = require('../../lib/knex');
const {globalRoleRequiresElevatedAssignment} = require('../../lib/role-grants');

async function run() {
    const users = await knex('users').select(['id', 'namespace', 'role']);
    const privilegedGlobalAssignments = users
        .filter(user => globalRoleRequiresElevatedAssignment(config.roles.global[user.role]))
        .map(user => ({
            userId: user.id,
            namespaceId: user.namespace,
            role: user.role
        }));

    // Historic rows do not retain the grantor. Every explicit namespace share must therefore be reviewed
    // against the current grantor ceiling instead of guessing provenance or silently deleting access.
    const explicitNamespaceShares = await knex('shares_namespace')
        .where(builder => builder.where({auto: false}).orWhereNull('auto'))
        .select(['user', 'entity', 'role']);

    const report = {
        generatedAt: new Date().toISOString(),
        readOnly: true,
        summary: {
            privilegedGlobalAssignments: privilegedGlobalAssignments.length,
            explicitNamespaceSharesRequiringReview: explicitNamespaceShares.length
        },
        privilegedGlobalAssignments,
        explicitNamespaceSharesRequiringReview: explicitNamespaceShares.map(share => ({
            userId: share.user,
            namespaceId: share.entity,
            role: share.role
        }))
    };

    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

run().then(() => knex.destroy()).catch(async err => {
    process.stderr.write(`${err.stack || err}\n`);
    await knex.destroy();
    process.exitCode = 1;
});

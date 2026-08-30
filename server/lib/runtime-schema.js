'use strict';

async function assertRuntimeSchemaCurrent(migrationSource) {
    const lists = await migrationSource.list();
    const pending = lists[1] || [];
    if (pending.length) {
        const error = new Error('Database migrations are pending; run the migration service before Mailtrain');
        error.code = 'EDBMIGRATIONREQUIRED';
        throw error;
    }
}

module.exports = {assertRuntimeSchemaCurrent};

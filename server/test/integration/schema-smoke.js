'use strict';

const assert = require('node:assert/strict');
const config = require('../../lib/config');
const mysql = require('mysql2');
const {assertSafeTestDatabase} = require('../../lib/test-database-safety');

assertSafeTestDatabase({
    environment: process.env.NODE_ENV,
    database: config.mysql.database,
    allowDestructiveTests: process.env.ALLOW_DESTRUCTIVE_TESTS
});

async function run() {
    // Loading Knex after the destructive-test guard keeps accidental connections fail-closed.
    // eslint-disable-next-line global-require
    const knex = require('../../lib/knex');
    await knex.migrate.latest();

    const connection = mysql.createConnection(config.mysql);
    const query = sql => new Promise((resolve, reject) => {
        connection.query(sql, (err, rows) => err ? reject(err) : resolve(rows));
    });

    try {
        const rows = await query('SHOW TABLES');
        const tableNames = new Set(rows.flatMap(row => Object.values(row)));
        for (const requiredTable of ['settings', 'users', 'namespaces', 'lists', 'campaigns', 'knex_migrations']) {
            assert.ok(tableNames.has(requiredTable), `expected migrated table ${requiredTable}`);
        }

        process.stdout.write(`Validated ${tableNames.size} tables in synthetic database ${config.mysql.database}\n`);
    } finally {
        connection.destroy();
        await knex.destroy();
    }
}

run().catch(err => {
    process.stderr.write(`${err.stack || err}\n`);
    process.exitCode = 1;
});

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

        const columns = await query(`SELECT TABLE_NAME, COLUMN_NAME, COLUMN_TYPE
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA = DATABASE()
              AND ((TABLE_NAME = 'send_configurations' AND COLUMN_NAME = 'mailer_secrets')
                OR (TABLE_NAME = 'settings' AND COLUMN_NAME = 'encrypted_value')
                OR (TABLE_NAME = 'users' AND COLUMN_NAME IN ('access_token_hash', 'reset_token_hash')))`);
        const columnTypes = new Map(columns.map(column => [`${column.TABLE_NAME}.${column.COLUMN_NAME}`, column.COLUMN_TYPE.toLowerCase()]));
        assert.equal(columnTypes.get('send_configurations.mailer_secrets'), 'longtext');
        assert.equal(columnTypes.get('settings.encrypted_value'), 'longtext');
        assert.equal(columnTypes.get('users.access_token_hash'), 'binary(32)');
        assert.equal(columnTypes.get('users.reset_token_hash'), 'binary(32)');

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

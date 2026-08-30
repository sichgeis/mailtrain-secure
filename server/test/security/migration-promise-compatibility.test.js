'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const migration = require('../../setup/knex/migrations/20200824160149_convert_to_utf8mb4');

test('utf8mb4 migration works when modern Knex does not inject a Promise argument', async () => {
    const alteredTables = [];
    const knex = {
        client: {
            database: () => 'mailtrain_test'
        },
        raw(sql, bindings) {
            if (sql.startsWith('SELECT table_name')) {
                return Promise.resolve([[{tableName: 'campaigns'}, {tableName: 'lists'}]]);
            }

            alteredTables.push(bindings[0]);
            return Promise.resolve();
        }
    };

    await migration.up(knex);

    assert.deepEqual(alteredTables, ['campaigns', 'lists']);
});

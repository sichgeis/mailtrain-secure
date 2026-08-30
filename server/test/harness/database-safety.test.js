'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {assertSafeTestDatabase} = require('../../lib/test-database-safety');

test('accepts an explicitly isolated synthetic test database', () => {
    assert.doesNotThrow(() => assertSafeTestDatabase({
        environment: 'test',
        database: 'mailtrain_ci_test',
        allowDestructiveTests: 'YES_I_AM_USING_SYNTHETIC_DATA'
    }));
});

test('rejects production mode and missing destructive-test consent', () => {
    assert.throws(() => assertSafeTestDatabase({
        environment: 'production',
        database: 'mailtrain_ci_test',
        allowDestructiveTests: 'YES_I_AM_USING_SYNTHETIC_DATA'
    }), /NODE_ENV=test/);

    assert.throws(() => assertSafeTestDatabase({
        environment: 'test',
        database: 'mailtrain_ci_test'
    }), /synthetic data/);
});

test('rejects default, production-like, blank, and system database names', () => {
    for (const database of ['', 'mailtrain', 'mailtrain_prod', 'production', 'mysql', 'information_schema', 'performance_schema', 'sys']) {
        assert.throws(() => assertSafeTestDatabase({
            environment: 'test',
            database,
            allowDestructiveTests: 'YES_I_AM_USING_SYNTHETIC_DATA'
        }), /isolated test database/);
    }
});

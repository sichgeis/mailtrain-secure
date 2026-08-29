'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {forwardedEnvironmentVariables} = require('../../lib/fork');

test('workers inherit only the configuration environment needed by the test harness', () => {
    assert.deepEqual(forwardedEnvironmentVariables, ['NODE_CONFIG', 'NODE_CONFIG_DIR', 'NODE_ENV']);
    assert.equal(forwardedEnvironmentVariables.includes('MAILTRAIN_MASTER_KEY'), false);
});

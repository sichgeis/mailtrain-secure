'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const yaml = require('js-yaml');
const {
    applyAdminBootstrap,
    validateAdminPassword
} = require('../../lib/admin-bootstrap');
const {
    assertReportExecutionEnabled,
    isReportExecutionEnabled,
    warnIfUnsafeReportExecutionEnabled
} = require('../../lib/report-execution-policy');

const repositoryRoot = path.resolve(__dirname, '../../..');

test('Docker admin bootstrap rejects missing, weak, and known default passwords', () => {
    for (const password of [undefined, '', 'test', 'password', 'short']) {
        assert.throws(() => validateAdminPassword(password));
    }

    assert.doesNotThrow(() => validateAdminPassword('Synthetic-Admin-Bootstrap-Password-123!'));
});

test('admin credentials are written only for a fresh bootstrap', async () => {
    const updates = [];
    const dependencies = {
        password: 'Synthetic-Admin-Bootstrap-Password-123!',
        accessToken: 'synthetic-bootstrap-token',
        hashPassword: async password => `hashed:${password}`,
        hashAccessToken: async token => ({hash: Buffer.from(`hashed:${token}`), keyId: 'test-key'}),
        updateAdmin: async fields => updates.push(fields)
    };

    assert.equal(await applyAdminBootstrap({...dependencies, existingAdmin: null}), true);
    assert.deepEqual(updates, [{
        password: 'hashed:Synthetic-Admin-Bootstrap-Password-123!',
        access_token: null,
        access_token_hash: Buffer.from('hashed:synthetic-bootstrap-token'),
        access_token_key_id: 'test-key'
    }]);

    updates.length = 0;
    assert.equal(await applyAdminBootstrap({...dependencies, existingAdmin: {id: 1}}), false);
    assert.deepEqual(updates, []);
});

test('production Compose does not publish Mailtrain backend ports', () => {
    const compose = yaml.safeLoad(fs.readFileSync(path.join(repositoryRoot, 'docker-compose.yml'), 'utf8'));
    const mailtrain = compose.services.mailtrain;

    assert.equal(mailtrain.ports, undefined);
    assert.deepEqual(mailtrain.expose.map(String).sort(), ['3000', '3003', '3004']);
});

test('unsafe JavaScript reports require a double explicit opt-in', () => {
    assert.equal(isReportExecutionEnabled(undefined), false);
    assert.equal(isReportExecutionEnabled({enabled: false, unsafeJavaScriptExecution: true}), false);
    assert.equal(isReportExecutionEnabled({enabled: true, unsafeJavaScriptExecution: false}), false);
    assert.equal(isReportExecutionEnabled({enabled: true, unsafeJavaScriptExecution: true}), true);
    assert.throws(() => assertReportExecutionEnabled({enabled: true}));
    assert.doesNotThrow(() => assertReportExecutionEnabled({enabled: true, unsafeJavaScriptExecution: true}));
});

test('unsafe report opt-in emits a high-visibility warning', () => {
    const warnings = [];
    warnIfUnsafeReportExecutionEnabled(
        {enabled: true, unsafeJavaScriptExecution: true},
        message => warnings.push(message)
    );

    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /UNSAFE JAVASCRIPT REPORT EXECUTION IS ENABLED/);
});

test('Docker entrypoint has no admin password fallback and invokes validation', () => {
    const entrypoint = fs.readFileSync(path.join(repositoryRoot, 'docker-entrypoint.sh'), 'utf8');

    assert.doesNotMatch(entrypoint, /ADMIN_PASSWORD=.*test/);
    assert.match(entrypoint, /validate-admin-password\.js/);
});

test('reports are disabled in the default application configuration', () => {
    const defaults = yaml.safeLoad(fs.readFileSync(path.join(repositoryRoot, 'server/config/default.yaml'), 'utf8'));

    assert.equal(defaults.reports.enabled, false);
    assert.equal(defaults.reports.unsafeJavaScriptExecution, false);
});

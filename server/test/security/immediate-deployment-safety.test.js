'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {Readable} = require('node:stream');
const test = require('node:test');
const yaml = require('js-yaml');
const {assertAggregateUploadSize, createAggregateDiskStorage} = require('../../lib/upload-limits');
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

test('campaign uploads and OpenPGP buffering have explicit production bounds', () => {
    const defaults = yaml.safeLoad(fs.readFileSync(path.join(repositoryRoot, 'server/config/default.yaml'), 'utf8'));
    const uploads = fs.readFileSync(path.join(repositoryRoot, 'server/lib/file-helpers.js'), 'utf8');
    const mailers = fs.readFileSync(path.join(repositoryRoot, 'server/lib/mailers.js'), 'utf8');
    assert.ok(defaults.security.uploads.maxFileSizeBytes > 0);
    assert.ok(defaults.security.uploads.maxFiles > 0);
    assert.ok(defaults.security.uploads.maxTotalBytes >= defaults.security.uploads.maxFileSizeBytes);
    assert.ok(Math.ceil(defaults.security.uploads.maxTotalBytes * 4 / 3) + 4 * 1024 * 1024 < defaults.security.openPgp.maxMessageBytes);
    assert.match(uploads, /limits:/);
    assert.match(uploads, /assertAggregateUploadSize/);
    assert.match(mailers, /maxMessageBytes/);

    assert.doesNotThrow(() => assertAggregateUploadSize([{size: 8}, {size: 8}], 16));
    assert.throws(() => assertAggregateUploadSize([{size: 8}, {size: 9}], 16), error => error.status === 413);
});

test('aggregate upload storage aborts before writing beyond the request budget', async () => {
    const destination = fs.mkdtempSync(path.join(os.tmpdir(), 'mailtrain-upload-limit-'));
    const storage = createAggregateDiskStorage({destination, maxTotalBytes: 16});
    const req = {};
    const store = size => new Promise(resolve => storage._handleFile(req, {
        stream: Readable.from([Buffer.alloc(size)]),
        originalname: 'synthetic.bin',
        mimetype: 'application/octet-stream'
    }, (err, file) => resolve({err, file})));

    const first = await store(10);
    assert.equal(first.err, null);
    const second = await store(10);
    assert.equal(second.err.status, 413);
    const bytesOnDisk = fs.readdirSync(destination)
        .reduce((total, filename) => total + fs.statSync(path.join(destination, filename)).size, 0);
    assert.ok(bytesOnDisk <= 16);
    await new Promise(resolve => storage._removeFile(req, first.file, resolve));
    fs.rmSync(destination, {recursive: true, force: true});
});

'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const test = require('node:test');

const {
    SecretEnvelope,
    loadSecretKeyring
} = require('../../lib/secret-envelope');
const {
    hashLookupToken,
    tokenHashMatches
} = require('../../lib/token-hash');
const {
    extractMailerSecrets,
    restoreMailerSecrets,
    migrateRecords
} = require('../../lib/secret-migration');

const KEY_A = crypto.createHash('sha256').update('stage-7-key-a').digest();
const KEY_B = crypto.createHash('sha256').update('stage-7-key-b').digest();

test('AES-256-GCM envelopes are versioned, randomized, authenticated, and row-bound', () => {
    const envelope = new SecretEnvelope({activeKeyId: 'key-a', keys: {'key-a': KEY_A}});
    const aad = 'send_configurations:42:mailer_secrets';
    const first = envelope.encrypt('smtp-password-canary', aad);
    const second = envelope.encrypt('smtp-password-canary', aad);

    assert.match(first, /^mtsec:v1:key-a:/);
    assert.notEqual(first, second);
    assert.equal(envelope.decrypt(first, aad), 'smtp-password-canary');
    assert.throws(() => envelope.decrypt(first, 'send_configurations:43:mailer_secrets'), /authenticate|decrypt/i);

    const tampered = first.slice(0, -1) + (first.endsWith('A') ? 'B' : 'A');
    assert.throws(() => envelope.decrypt(tampered, aad), /authenticate|decrypt|envelope/i);
    assert.throws(() => envelope.decrypt('mtsec:v99:key-a:bad', aad), /version|envelope/i);
});

test('key rotation decrypts old envelopes and rewrites them with the active key id', () => {
    const oldEnvelope = new SecretEnvelope({activeKeyId: 'key-a', keys: {'key-a': KEY_A}});
    const ciphertext = oldEnvelope.encrypt('rotate-me', 'settings:pgpPrivateKey');
    const rotatingEnvelope = new SecretEnvelope({activeKeyId: 'key-b', keys: {'key-a': KEY_A, 'key-b': KEY_B}});

    const rotated = rotatingEnvelope.rotate(ciphertext, 'settings:pgpPrivateKey');
    assert.match(rotated, /^mtsec:v1:key-b:/);
    assert.equal(rotatingEnvelope.decrypt(rotated, 'settings:pgpPrivateKey'), 'rotate-me');
    assert.throws(
        () => new SecretEnvelope({activeKeyId: 'key-b', keys: {'key-b': KEY_B}}).decrypt(ciphertext, 'settings:pgpPrivateKey'),
        /key-a/
    );
});

test('master-key configuration is external, exact-length, and fail-closed', () => {
    const encoded = KEY_A.toString('base64');
    const loaded = loadSecretKeyring({masterKey: encoded, keyId: 'production-2026-01'});
    assert.equal(loaded.activeKeyId, 'production-2026-01');
    assert.deepEqual(loaded.keys['production-2026-01'], KEY_A);

    assert.throws(() => loadSecretKeyring({masterKey: '', keyId: 'key-a'}), /master key/i);
    assert.throws(() => loadSecretKeyring({masterKey: Buffer.alloc(31).toString('base64'), keyId: 'key-a'}), /32 bytes/i);
    assert.throws(() => loadSecretKeyring({masterKey: encoded, keyId: '../unsafe'}), /key id/i);
});

test('bearer and reset lookup hashes are keyed, fixed-width, and domain-separated', () => {
    const token = 'one-time-token-canary';
    const accessHash = hashLookupToken(token, {key: KEY_A, purpose: 'access-token'});
    const resetHash = hashLookupToken(token, {key: KEY_A, purpose: 'reset-token'});

    assert.equal(accessHash.length, 32);
    assert.equal(resetHash.length, 32);
    assert.notDeepEqual(accessHash, resetHash);
    assert.equal(tokenHashMatches(token, accessHash, {key: KEY_A, purpose: 'access-token'}), true);
    assert.equal(tokenHashMatches('wrong', accessHash, {key: KEY_A, purpose: 'access-token'}), false);
    assert.equal(tokenHashMatches(token, Buffer.alloc(31), {key: KEY_A, purpose: 'access-token'}), false);
});

test('mailer secrets leave only non-sensitive settings in plaintext and round-trip exactly', () => {
    const settings = {
        hostname: 'smtp.example.test',
        port: 587,
        user: 'mailer',
        password: 'smtp-password-canary',
        key: 'ses-access-key-canary',
        secret: 'ses-secret-canary',
        region: 'eu-central-1',
        dkimDomain: 'example.test',
        dkimSelector: 'mail',
        dkimPrivateKey: 'dkim-private-key-canary',
        dkimApiKey: 'dkim-api-key-canary'
    };
    const {publicSettings, secrets} = extractMailerSecrets(settings);

    assert.deepEqual(publicSettings, {
        hostname: 'smtp.example.test',
        port: 587,
        region: 'eu-central-1',
        dkimDomain: 'example.test',
        dkimSelector: 'mail'
    });
    assert.deepEqual(restoreMailerSecrets(publicSettings, secrets), settings);
    assert.doesNotMatch(JSON.stringify(publicSettings), /canary/);
});

test('record migration is transactional per record, resumable, idempotent, and supports dry-run', async () => {
    const rows = [
        {id: 1, plaintext: 'first'},
        {id: 2, plaintext: 'second'},
        {id: 3, plaintext: null, envelope: 'already-encrypted'}
    ];
    const writes = [];
    const adapter = {
        async listAfter(lastId, limit) {
            return rows.filter(row => row.id > lastId).slice(0, limit);
        },
        async transactionForRecord(row, transform) {
            writes.push(row.id);
            return transform(row);
        }
    };

    const dryRun = await migrateRecords(adapter, {
        batchSize: 2,
        dryRun: true,
        needsMigration: row => !!row.plaintext,
        migrate: row => ({...row, envelope: `encrypted:${row.plaintext}`, plaintext: null})
    });
    assert.deepEqual(dryRun, {scanned: 3, migrated: 2, skipped: 1, lastId: 3, dryRun: true});
    assert.deepEqual(writes, []);

    const migrated = await migrateRecords(adapter, {
        batchSize: 2,
        needsMigration: row => !!row.plaintext,
        migrate: row => ({...row, envelope: `encrypted:${row.plaintext}`, plaintext: null})
    });
    assert.deepEqual(migrated, {scanned: 3, migrated: 2, skipped: 1, lastId: 3, dryRun: false});
    assert.deepEqual(writes, [1, 2]);
});

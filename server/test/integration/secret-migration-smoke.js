'use strict';

const assert = require('node:assert/strict');
const knex = require('../../lib/knex');
const {lookupCandidates, revealMailerSettings, revealSetting} = require('../../lib/secret-storage');
const users = require('../../models/users');

const FIXTURE = {
    accessToken: 'synthetic-legacy-access-token',
    resetToken: 'synthetic-legacy-reset-token',
    smtpPassword: 'synthetic-legacy-smtp-password',
    pgpPrivateKey: 'synthetic-legacy-pgp-private-key'
};

async function upsertSetting(key, value) {
    const existing = await knex('settings').where({key}).first();
    if (existing) {
        await knex('settings').where({key}).update({value, encrypted_value: null});
    } else {
        await knex('settings').insert({key, value, encrypted_value: null});
    }
}

async function seed() {
    const sendConfiguration = await knex('send_configurations').orderBy('id').first();
    assert.ok(sendConfiguration, 'expected the synthetic system send configuration');
    const publicSettings = {hostname: 'smtp.example.test', port: 587};
    await knex('send_configurations').where({id: sendConfiguration.id}).update({
        mailer_settings: JSON.stringify({...publicSettings, user: 'synthetic-mailer', password: FIXTURE.smtpPassword}),
        mailer_secrets: null
    });
    await upsertSetting('pgpPrivateKey', FIXTURE.pgpPrivateKey);
    await knex('users').where({id: 1}).update({
        access_token: FIXTURE.accessToken,
        access_token_hash: null,
        access_token_key_id: null,
        reset_token: FIXTURE.resetToken,
        reset_token_hash: null,
        reset_token_key_id: null,
        reset_expire: new Date(Date.now() + 60 * 60 * 1000)
    });
}

function matchesCandidate(token, purpose, keyId, storedHash) {
    return lookupCandidates(token, purpose).some(candidate =>
        candidate.keyId === keyId && Buffer.from(storedHash).equals(candidate.hash)
    );
}

async function verify() {
    const sendConfiguration = await knex('send_configurations').orderBy('id').first();
    const plaintextMailerSettings = JSON.parse(sendConfiguration.mailer_settings);
    assert.deepEqual(plaintextMailerSettings, {hostname: 'smtp.example.test', port: 587});
    assert.equal(revealMailerSettings(plaintextMailerSettings, sendConfiguration.mailer_secrets, sendConfiguration.cid).password, FIXTURE.smtpPassword);

    const pgpSetting = await knex('settings').where({key: 'pgpPrivateKey'}).first();
    assert.equal(pgpSetting.value, '');
    assert.equal(revealSetting(pgpSetting.key, pgpSetting.value, pgpSetting.encrypted_value), FIXTURE.pgpPrivateKey);

    const user = await knex('users').where({id: 1}).first();
    assert.equal(user.access_token, null);
    assert.equal(user.reset_token, null);
    assert.equal(matchesCandidate(FIXTURE.accessToken, 'access-token', user.access_token_key_id, user.access_token_hash), true);
    assert.equal(matchesCandidate(FIXTURE.resetToken, 'reset-token', user.reset_token_key_id, user.reset_token_hash), true);
}

async function verifyCompatibility() {
    const user = await users.getByAccessToken(FIXTURE.accessToken);
    assert.equal(user.id, 1);
    assert.equal(await users.isPasswordResetTokenValid('admin', FIXTURE.resetToken), true);

    const migrated = await knex('users').where({id: 1}).first();
    assert.equal(migrated.access_token, null);
    assert.equal(migrated.reset_token, null);
    assert.equal(matchesCandidate(FIXTURE.accessToken, 'access-token', migrated.access_token_key_id, migrated.access_token_hash), true);
    assert.equal(matchesCandidate(FIXTURE.resetToken, 'reset-token', migrated.reset_token_key_id, migrated.reset_token_hash), true);
}

async function main() {
    if (process.argv[2] === 'seed') {
        await seed();
    } else if (process.argv[2] === 'compatibility') {
        await verifyCompatibility();
    } else if (process.argv[2] === 'verify') {
        await verify();
    } else {
        throw new Error('Usage: secret-migration-smoke.js <seed|compatibility|verify>');
    }
    process.stdout.write(`Secret migration ${process.argv[2]} check passed\n`);
}

main().then(() => knex.destroy()).then(() => process.exit(0)).catch(err => {
    process.stderr.write(`Secret migration integration check failed: ${err.name || 'error'}\n`);
    knex.destroy().finally(() => process.exit(1));
});

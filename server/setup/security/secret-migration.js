'use strict';

// Deliberately sequential: every secret record is an independent transaction
// so an interruption is resumable without exposing a partially converted row.
/* eslint-disable no-await-in-loop */

const knex = require('../../lib/knex');
const {
    getStorage,
    lookupHash,
    protectMailerSettings,
    protectSetting
} = require('../../lib/secret-storage');
const {extractMailerSecrets} = require('../../lib/secret-migration');

const SECRET_SETTING_KEYS = ['pgpPrivateKey', 'pgpPassphrase'];

async function transactionRows(table, rows, handler, {dryRun}) {
    let migrated = 0;
    for (const source of rows) {
        if (!await handler(source, null, true)) {
            continue;
        }
        migrated += 1;
        if (!dryRun) {
            await knex.transaction(async tx => {
                const row = await tx(table).where({id: source.id}).forUpdate().first();
                await handler(row, tx, false);
            });
        }
    }
    return migrated;
}

async function migrate({dryRun = false} = {}) {
    getStorage({required: true});
    const result = {dryRun, sendConfigurations: 0, settings: 0, accessTokens: 0, resetTokens: 0};

    const sendRows = await knex('send_configurations').select(['id', 'cid', 'mailer_settings', 'mailer_secrets']).orderBy('id');
    result.sendConfigurations = await transactionRows('send_configurations', sendRows, async (row, tx, classifyOnly) => {
        const parsed = JSON.parse(row.mailer_settings);
        const needsMigration = !row.mailer_secrets && Object.keys(extractMailerSecrets(parsed).secrets).length > 0;
        if (!needsMigration || classifyOnly) {
            return needsMigration;
        }
        const protectedData = protectMailerSettings(parsed, row.cid);
        await tx('send_configurations').where({id: row.id}).update({
            mailer_settings: JSON.stringify(protectedData.mailerSettings),
            mailer_secrets: protectedData.mailerSecrets
        });
        return true;
    }, {dryRun});

    const settingRows = await knex('settings').select(['key', 'value', 'encrypted_value']).whereIn('key', SECRET_SETTING_KEYS);
    for (const source of settingRows) {
        if (!source.value || source.encrypted_value) {
            continue;
        }
        result.settings += 1;
        if (!dryRun) {
            await knex.transaction(async tx => {
                const row = await tx('settings').where({key: source.key}).forUpdate().first();
                if (row.value && !row.encrypted_value) {
                    const protectedData = protectSetting(row.key, row.value);
                    await tx('settings').where({key: row.key}).update({
                        value: protectedData.value,
                        encrypted_value: protectedData.encryptedValue
                    });
                }
            });
        }
    }

    const userRows = await knex('users').select(['id', 'access_token', 'access_token_hash', 'access_token_key_id', 'reset_token', 'reset_token_hash', 'reset_token_key_id']).orderBy('id');
    for (const source of userRows) {
        for (const tokenType of ['access', 'reset']) {
            const plaintextColumn = `${tokenType}_token`;
            const hashColumn = `${tokenType}_token_hash`;
            const keyIdColumn = `${tokenType}_token_key_id`;
            if (!source[plaintextColumn] || source[hashColumn]) {
                continue;
            }
            result[`${tokenType}Tokens`] += 1;
            if (!dryRun) {
                await knex.transaction(async tx => {
                    const row = await tx('users').where({id: source.id}).select(['id', plaintextColumn, hashColumn, keyIdColumn]).forUpdate().first();
                    if (row[plaintextColumn] && !row[hashColumn]) {
                        await tx('users').where({id: row.id}).update({
                            [plaintextColumn]: null,
                            [hashColumn]: lookupHash(row[plaintextColumn], `${tokenType}-token`),
                            [keyIdColumn]: getStorage({required: true}).keyId
                        });
                    }
                });
            }
        }
    }
    return result;
}

async function verify() {
    const storage = getStorage({required: true});
    const result = {plaintext: 0, encrypted: 0, hashedTokens: 0, invalid: 0};
    const sendRows = await knex('send_configurations').select(['id', 'cid', 'mailer_settings', 'mailer_secrets']);
    for (const row of sendRows) {
        const plaintextSecrets = extractMailerSecrets(JSON.parse(row.mailer_settings)).secrets;
        result.plaintext += Object.keys(plaintextSecrets).length ? 1 : 0;
        if (row.mailer_secrets) {
            try {
                JSON.parse(storage.envelope.decrypt(row.mailer_secrets, `send_configurations:${row.cid}:mailer_secrets`));
                result.encrypted += 1;
            } catch (err) {
                result.invalid += 1;
            }
        }
    }
    const settingRows = await knex('settings').select(['key', 'value', 'encrypted_value']).whereIn('key', SECRET_SETTING_KEYS);
    for (const row of settingRows) {
        result.plaintext += row.value ? 1 : 0;
        if (row.encrypted_value) {
            try {
                storage.envelope.decrypt(row.encrypted_value, `settings:${row.key}`);
                result.encrypted += 1;
            } catch (err) {
                result.invalid += 1;
            }
        }
    }
    const tokenRow = await knex('users').count({count: 'id'}).whereNotNull('access_token_hash').orWhereNotNull('reset_token_hash').first();
    result.hashedTokens = Number(tokenRow.count);
    const plaintextTokenRow = await knex('users').count({count: 'id'}).whereNotNull('access_token').orWhereNotNull('reset_token').first();
    result.plaintext += Number(plaintextTokenRow.count);
    return result;
}

async function rotate() {
    const storage = getStorage({required: true});
    const result = {sendConfigurations: 0, settings: 0};
    const sendRows = await knex('send_configurations').select(['id', 'cid', 'mailer_secrets']).whereNotNull('mailer_secrets').orderBy('id');
    for (const source of sendRows) {
        if (storage.envelope.keyId(source.mailer_secrets) === storage.keyId) {
            continue;
        }
        await knex.transaction(async tx => {
            const row = await tx('send_configurations').where({id: source.id}).select(['id', 'cid', 'mailer_secrets']).forUpdate().first();
            if (row.mailer_secrets && storage.envelope.keyId(row.mailer_secrets) !== storage.keyId) {
                const aad = `send_configurations:${row.cid}:mailer_secrets`;
                await tx('send_configurations').where({id: row.id}).update({mailer_secrets: storage.envelope.rotate(row.mailer_secrets, aad)});
                result.sendConfigurations += 1;
            }
        });
    }
    const settingRows = await knex('settings').select(['key', 'encrypted_value']).whereNotNull('encrypted_value').whereIn('key', SECRET_SETTING_KEYS);
    for (const source of settingRows) {
        if (storage.envelope.keyId(source.encrypted_value) === storage.keyId) {
            continue;
        }
        await knex.transaction(async tx => {
            const row = await tx('settings').where({key: source.key}).select(['key', 'encrypted_value']).forUpdate().first();
            if (row.encrypted_value && storage.envelope.keyId(row.encrypted_value) !== storage.keyId) {
                const aad = `settings:${row.key}`;
                await tx('settings').where({key: row.key}).update({encrypted_value: storage.envelope.rotate(row.encrypted_value, aad)});
                result.settings += 1;
            }
        });
    }
    return result;
}

async function main() {
    const command = process.argv[2];
    let result;
    if (command === 'dry-run') {
        result = await migrate({dryRun: true});
    } else if (command === 'migrate') {
        result = await migrate();
    } else if (command === 'verify') {
        result = await verify();
        if (result.plaintext || result.invalid) {
            process.exitCode = 2;
        }
    } else if (command === 'rotate') {
        result = await rotate();
        const verification = await verify();
        result = {...result, verification};
    } else {
        throw new Error('Usage: secret-migration.js <dry-run|migrate|verify|rotate>');
    }
    process.stdout.write(`${JSON.stringify(result)}\n`);
}

if (require.main === module) {
    main().then(() => knex.destroy()).catch(err => {
        process.stderr.write(`Secret migration failed: ${err.code || err.name || 'error'}\n`);
        knex.destroy().finally(() => process.exit(1));
    });
}

module.exports = {migrate, rotate, verify};

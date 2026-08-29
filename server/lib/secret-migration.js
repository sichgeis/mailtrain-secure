'use strict';

/* eslint-disable no-await-in-loop, no-constant-condition */

const MAILER_SECRET_KEYS = new Set([
    'user',
    'password',
    'key',
    'secret',
    'dkimApiKey',
    'dkimPrivateKey'
]);

function extractMailerSecrets(settings = {}) {
    const publicSettings = {};
    const secrets = {};
    for (const [key, value] of Object.entries(settings)) {
        (MAILER_SECRET_KEYS.has(key) ? secrets : publicSettings)[key] = value;
    }
    return {publicSettings, secrets};
}

function restoreMailerSecrets(publicSettings = {}, secrets = {}) {
    return {...publicSettings, ...secrets};
}

async function migrateRecords(adapter, {
    batchSize = 100,
    dryRun = false,
    needsMigration,
    migrate
}) {
    if (!adapter || typeof adapter.listAfter !== 'function' || typeof adapter.transactionForRecord !== 'function' ||
        !Number.isSafeInteger(batchSize) || batchSize < 1 || typeof needsMigration !== 'function' || typeof migrate !== 'function') {
        throw new Error('Secret migration configuration is invalid');
    }
    const result = {scanned: 0, migrated: 0, skipped: 0, lastId: 0, dryRun: !!dryRun};
    while (true) {
        const rows = await adapter.listAfter(result.lastId, batchSize);
        if (!Array.isArray(rows) || rows.length === 0) {
            break;
        }
        for (const row of rows) {
            if (!Number.isSafeInteger(row.id) || row.id <= result.lastId) {
                throw new Error('Secret migration rows must be strictly ordered by integer id');
            }
            result.lastId = row.id;
            result.scanned += 1;
            if (!needsMigration(row)) {
                result.skipped += 1;
            } else {
                result.migrated += 1;
                if (!dryRun) {
                    await adapter.transactionForRecord(row, migrate);
                }
            }
        }
        if (rows.length < batchSize) {
            break;
        }
    }
    return result;
}

module.exports = {extractMailerSecrets, migrateRecords, restoreMailerSecrets};

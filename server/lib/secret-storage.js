'use strict';

const crypto = require('crypto');
const fs = require('fs');
const config = require('./config');
const log = require('./log');
const {SecretEnvelope, loadSecretKeyring} = require('./secret-envelope');
const {hashLookupToken} = require('./token-hash');
const {extractMailerSecrets, restoreMailerSecrets} = require('./secret-migration');

let cached;
let warned = false;
const SECRET_ENVIRONMENT_VARIABLES = [
    'MAILTRAIN_MASTER_KEY',
    'MAILTRAIN_MASTER_KEY_FILE',
    'MAILTRAIN_MASTER_KEY_ID',
    'MAILTRAIN_PREVIOUS_MASTER_KEYS',
    'MAILTRAIN_PREVIOUS_MASTER_KEYS_FILE',
    'MAILTRAIN_ALLOW_PLAINTEXT_SECRETS'
];

function readSecretFile(filename, label) {
    if (!filename) {
        return undefined;
    }
    const stat = fs.statSync(filename);
    if (!stat.isFile() || stat.size < 1 || stat.size > 65536) {
        throw new Error(`${label} file must be a non-empty regular file no larger than 64 KiB`);
    }
    return fs.readFileSync(filename, 'utf8').trim();
}

function bool(value, fallback = false) {
    if (value === undefined || value === null || value === '') {
        return fallback;
    }
    return value === true || String(value).toLowerCase() === 'true';
}

function settings() {
    const configured = config.security && config.security.secrets || {};
    let previousKeys = {};
    const previousKeysJson = readSecretFile(
        process.env.MAILTRAIN_PREVIOUS_MASTER_KEYS_FILE,
        'Previous master keys'
    ) || process.env.MAILTRAIN_PREVIOUS_MASTER_KEYS;
    if (previousKeysJson) {
        try {
            previousKeys = JSON.parse(previousKeysJson);
        } catch (err) {
            throw new Error('Previous master keys must be a JSON object');
        }
    }
    return {
        masterKey: readSecretFile(process.env.MAILTRAIN_MASTER_KEY_FILE, 'Master key') ||
            process.env.MAILTRAIN_MASTER_KEY || configured.masterKey,
        keyId: process.env.MAILTRAIN_MASTER_KEY_ID || configured.keyId,
        previousKeys,
        allowPlaintextCompatibility: bool(
            process.env.MAILTRAIN_ALLOW_PLAINTEXT_SECRETS,
            configured.allowPlaintextCompatibility
        )
    };
}

function getStorage({required = false} = {}) {
    if (cached) {
        return cached;
    }
    const options = settings();
    if (!options.masterKey && !options.keyId) {
        if (required || !options.allowPlaintextCompatibility) {
            throw new Error('MAILTRAIN_MASTER_KEY and MAILTRAIN_MASTER_KEY_ID are required');
        }
        return null;
    }
    if (!options.masterKey || !options.keyId) {
        throw new Error('MAILTRAIN_MASTER_KEY and MAILTRAIN_MASTER_KEY_ID must be configured together');
    }
    const keyring = loadSecretKeyring(options);
    const lookupKeys = {};
    for (const [keyId, key] of Object.entries(keyring.keys)) {
        lookupKeys[keyId] = Buffer.from(crypto.hkdfSync(
            'sha256', key, Buffer.from('mailtrain-secret-storage-v1'), Buffer.from('lookup-token-hmac-key'), 32
        ));
    }
    cached = {
        envelope: new SecretEnvelope(keyring),
        keyId: keyring.activeKeyId,
        lookupKeys
    };
    return cached;
}

function warnPlaintextCompatibility() {
    if (!warned) {
        warned = true;
        log.warn('Secrets', 'Temporary plaintext secret compatibility is active; run the Stage 7 migration and disable it');
    }
}

function allowPlaintext() {
    return settings().allowPlaintextCompatibility;
}

function protectMailerSettings(mailerSettings, identity) {
    const storage = getStorage({required: true});
    const {publicSettings, secrets} = extractMailerSecrets(mailerSettings);
    const mailerSecrets = Object.keys(secrets).length ? storage.envelope.encrypt(
        JSON.stringify(secrets),
        `send_configurations:${identity}:mailer_secrets`
    ) : null;
    return {mailerSettings: publicSettings, mailerSecrets};
}

function revealMailerSettings(mailerSettings, mailerSecrets, identity) {
    if (!mailerSecrets) {
        if (Object.keys(extractMailerSecrets(mailerSettings).secrets).length) {
            if (!allowPlaintext()) {
                throw new Error('Plaintext mailer credentials are disabled');
            }
            warnPlaintextCompatibility();
        }
        return mailerSettings;
    }
    const storage = getStorage({required: true});
    const secrets = JSON.parse(storage.envelope.decrypt(
        mailerSecrets,
        `send_configurations:${identity}:mailer_secrets`
    ));
    return restoreMailerSecrets(mailerSettings, secrets);
}

function protectSetting(key, value) {
    const storage = getStorage({required: true});
    if (value === null || value === undefined || value === '') {
        return {value: '', encryptedValue: null};
    }
    return {
        value: '',
        encryptedValue: storage.envelope.encrypt(String(value), `settings:${key}`)
    };
}

function revealSetting(key, value, encryptedValue) {
    if (encryptedValue) {
        return getStorage({required: true}).envelope.decrypt(encryptedValue, `settings:${key}`);
    }
    if (value && !allowPlaintext()) {
        throw new Error(`Plaintext setting ${key} is disabled`);
    }
    if (value) {
        warnPlaintextCompatibility();
    }
    return value;
}

function lookupHash(token, purpose) {
    const storage = getStorage({required: true});
    return hashLookupToken(token, {key: storage.lookupKeys[storage.keyId], purpose});
}

function lookupCandidates(token, purpose) {
    const storage = getStorage({required: true});
    return Object.entries(storage.lookupKeys).map(([keyId, key]) => ({
        keyId,
        hash: hashLookupToken(token, {key, purpose})
    }));
}

function validateSecretStorage({production = false} = {}) {
    const options = settings();
    if (production || options.masterKey || options.keyId) {
        getStorage({required: !options.allowPlaintextCompatibility});
    }
}

function secretProcessEnvironment() {
    const environment = {};
    for (const variable of SECRET_ENVIRONMENT_VARIABLES) {
        if (process.env[variable] !== undefined) {
            environment[variable] = process.env[variable];
        }
    }
    return environment;
}

module.exports = {
    allowPlaintext,
    getStorage,
    lookupHash,
    lookupCandidates,
    protectMailerSettings,
    protectSetting,
    revealMailerSettings,
    revealSetting,
    secretProcessEnvironment,
    validateSecretStorage
};

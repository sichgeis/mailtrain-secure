'use strict';

const crypto = require('crypto');

const PREFIX = 'mtsec';
const VERSION = 'v1';
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function secretError(message) {
    const error = new Error(message);
    error.code = 'ESECRETCONFIG';
    return error;
}

function decodeKey(value, label = 'Master key') {
    if (typeof value !== 'string' || !value) {
        throw secretError(`${label} is required`);
    }
    const normalized = value.trim();
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) {
        throw secretError(`${label} must be base64 encoded`);
    }
    const key = Buffer.from(normalized, 'base64');
    if (key.length !== 32) {
        throw secretError(`${label} must decode to exactly 32 bytes`);
    }
    return key;
}

function validateKeyId(keyId) {
    if (typeof keyId !== 'string' || !KEY_ID_PATTERN.test(keyId)) {
        throw secretError('Master key id is invalid');
    }
    return keyId;
}

function loadSecretKeyring({masterKey, keyId, previousKeys = {}}) {
    const activeKeyId = validateKeyId(keyId);
    const keys = {[activeKeyId]: decodeKey(masterKey)};
    for (const [previousKeyId, encodedKey] of Object.entries(previousKeys || {})) {
        validateKeyId(previousKeyId);
        if (keys[previousKeyId]) {
            throw secretError(`Duplicate master key id ${previousKeyId}`);
        }
        keys[previousKeyId] = decodeKey(encodedKey, `Master key ${previousKeyId}`);
    }
    return {activeKeyId, keys};
}

function encode(value) {
    return Buffer.from(value).toString('base64url');
}

function decode(value, label) {
    if (!value || !/^[A-Za-z0-9_-]+$/.test(value)) {
        throw secretError(`Invalid ${label} in encrypted envelope`);
    }
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.toString('base64url') !== value) {
        throw secretError(`Invalid ${label} encoding in encrypted envelope`);
    }
    return decoded;
}

class SecretEnvelope {
    constructor({activeKeyId, keys}) {
        this.activeKeyId = validateKeyId(activeKeyId);
        this.keys = {};
        for (const [keyId, key] of Object.entries(keys || {})) {
            validateKeyId(keyId);
            if (!Buffer.isBuffer(key) || key.length !== 32) {
                throw secretError(`Key ${keyId} must contain exactly 32 bytes`);
            }
            this.keys[keyId] = Buffer.from(key);
        }
        if (!this.keys[this.activeKeyId]) {
            throw secretError(`Active master key ${this.activeKeyId} is unavailable`);
        }
    }

    encrypt(plaintext, aad) {
        if (typeof plaintext !== 'string' || typeof aad !== 'string' || !aad) {
            throw secretError('Plaintext and authenticated context must be non-empty strings');
        }
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', this.keys[this.activeKeyId], iv, {authTagLength: 16});
        cipher.setAAD(Buffer.from(aad, 'utf8'));
        const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return [PREFIX, VERSION, this.activeKeyId, encode(iv), encode(tag), encode(ciphertext)].join(':');
    }

    decrypt(envelope, aad) {
        try {
            const parts = String(envelope).split(':');
            if (parts.length !== 6 || parts[0] !== PREFIX) {
                throw secretError('Invalid encrypted envelope');
            }
            if (parts[1] !== VERSION) {
                throw secretError(`Unsupported encrypted envelope version ${parts[1]}`);
            }
            const keyId = validateKeyId(parts[2]);
            const key = this.keys[keyId];
            if (!key) {
                throw secretError(`Master key ${keyId} is unavailable`);
            }
            const iv = decode(parts[3], 'nonce');
            const tag = decode(parts[4], 'authentication tag');
            const ciphertext = decode(parts[5], 'ciphertext');
            if (iv.length !== 12 || tag.length !== 16 || typeof aad !== 'string' || !aad) {
                throw secretError('Invalid encrypted envelope parameters');
            }
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, {authTagLength: 16});
            decipher.setAAD(Buffer.from(aad, 'utf8'));
            decipher.setAuthTag(tag);
            return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
        } catch (err) {
            if (err.code === 'ESECRETCONFIG') {
                throw err;
            }
            const error = secretError('Encrypted secret authentication or decryption failed');
            error.cause = err;
            throw error;
        }
    }

    keyId(envelope) {
        const parts = String(envelope).split(':');
        if (parts.length !== 6 || parts[0] !== PREFIX || parts[1] !== VERSION) {
            throw secretError('Invalid encrypted envelope');
        }
        return validateKeyId(parts[2]);
    }

    rotate(envelope, aad) {
        if (this.keyId(envelope) === this.activeKeyId) {
            return envelope;
        }
        return this.encrypt(this.decrypt(envelope, aad), aad);
    }
}

module.exports = {SecretEnvelope, loadSecretKeyring};

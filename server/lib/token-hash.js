'use strict';

const crypto = require('crypto');

function validateOptions(token, {key, purpose}) {
    if (typeof token !== 'string' || !token || !Buffer.isBuffer(key) || key.length !== 32 || !/^[a-z0-9-]{1,64}$/.test(purpose || '')) {
        throw new Error('Token hashing configuration is invalid');
    }
}

function hashLookupToken(token, options) {
    validateOptions(token, options);
    return crypto.createHmac('sha256', options.key)
        .update(`mailtrain:${options.purpose}:v1\0`, 'utf8')
        .update(token, 'utf8')
        .digest();
}

function tokenHashMatches(token, expected, options) {
    if (!Buffer.isBuffer(expected) || expected.length !== 32) {
        return false;
    }
    const actual = hashLookupToken(token, options);
    return crypto.timingSafeEqual(actual, expected);
}

module.exports = {hashLookupToken, tokenHashMatches};

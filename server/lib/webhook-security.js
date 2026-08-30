'use strict';

const crypto = require('crypto');

const defaultReplayWindowMs = 5 * 60 * 1000;
const awsNotificationFields = ['Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type'];
const awsConfirmationFields = ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'];

function securityError(message, status = 401) {
    const error = new Error(message);
    error.status = status;
    return error;
}

function digest(value) {
    return crypto.createHash('sha256').update(String(value === undefined ? '' : value)).digest();
}

function secureEqual(actual, expected) {
    return crypto.timingSafeEqual(digest(actual), digest(expected));
}

function assertConfigured(value, name) {
    if (typeof value !== 'string' || value.length === 0) {
        throw securityError(`${name} is not configured`, 503);
    }
}

function assertFreshTimestamp(value, {
    now = Date.now,
    maxClockSkewMs = defaultReplayWindowMs,
    maxAgeMs = maxClockSkewMs
} = {}) {
    const timestamp = (typeof value === 'number' && Number.isFinite(value)) || (typeof value === 'string' && /^\d+(?:\.\d+)?$/.test(value))
        ? Number(value) * 1000
        : Date.parse(value);
    const age = now() - timestamp;
    if (!Number.isFinite(timestamp) || age < -maxClockSkewMs || age > maxAgeMs) {
        throw securityError('Webhook timestamp is invalid or outside the accepted window');
    }
}

class ReplayCache {
    constructor({now = Date.now, maxEntries = 10000} = {}) {
        this.now = now;
        this.maxEntries = maxEntries;
        this.entries = new Map();
    }

    _purgeExpired(currentTime) {
        for (const [entryKey, entry] of this.entries) {
            if (entry.expiresAt <= currentTime) {
                this.entries.delete(entryKey);
            }
        }
    }

    reserve(key, ttlMs = defaultReplayWindowMs) {
        const currentTime = this.now();
        this._purgeExpired(currentTime);

        const existing = this.entries.get(key);
        if (existing) {
            if (existing.state === 'completed') {
                return this._reservation(key, existing, true);
            }
            throw securityError('Webhook replay is already processing', 409);
        }
        if (this.entries.size >= this.maxEntries) {
            throw securityError('Webhook replay cache capacity exceeded', 503);
        }

        const entry = {
            leaseId: crypto.randomBytes(16).toString('hex'),
            state: 'processing',
            expiresAt: currentTime + ttlMs
        };
        this.entries.set(key, entry);
        return this._reservation(key, entry, false);
    }

    _reservation(key, entry, completed) {
        const cache = this;
        return {
            completed,
            commit() {
                const current = cache.entries.get(key);
                if (current === entry && current.leaseId === entry.leaseId) {
                    current.state = 'completed';
                }
            },
            rollback() {
                const current = cache.entries.get(key);
                if (current === entry && current.leaseId === entry.leaseId && current.state === 'processing') {
                    cache.entries.delete(key);
                }
            },
            async run(handler) {
                if (completed) {
                    return undefined;
                }
                try {
                    const result = await handler();
                    this.commit();
                    return result;
                } catch (err) {
                    this.rollback();
                    throw err;
                }
            }
        };
    }

    assertUnused(key, ttlMs = defaultReplayWindowMs) {
        const reservation = this.reserve(key, ttlMs);
        if (reservation.completed) {
            throw securityError('Webhook replay detected');
        }
        reservation.commit();
    }
}

function assertBasicAuthorization(header, {username, password}) {
    assertConfigured(username, 'SparkPost webhook username');
    assertConfigured(password, 'SparkPost webhook password');
    if (typeof header !== 'string' || !header.startsWith('Basic ')) {
        throw securityError('Webhook Authorization header is missing or invalid');
    }

    let decoded;
    try {
        decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
    } catch (err) {
        throw securityError('Webhook Authorization header is missing or invalid');
    }
    const separator = decoded.indexOf(':');
    const actualUsername = separator < 0 ? decoded : decoded.slice(0, separator);
    const actualPassword = separator < 0 ? '' : decoded.slice(separator + 1);
    if (!secureEqual(actualUsername, username) || !secureEqual(actualPassword, password)) {
        throw securityError('Webhook Authorization header is missing or invalid');
    }
}

function assertBearerAuthorization(header, expectedToken) {
    assertConfigured(expectedToken, 'Webhook bearer token');
    if (typeof header !== 'string' || !header.startsWith('Bearer ') || !secureEqual(header.slice(7), expectedToken)) {
        throw securityError('Webhook Authorization header is missing or invalid');
    }
}

function assertExpectedFields(body, expectedFields) {
    const allowed = new Set(expectedFields);
    for (const field of Object.keys(body || {})) {
        if (!allowed.has(field)) {
            throw securityError(`Unexpected webhook field: ${field}`, 400);
        }
    }
}

function singleValue(value) {
    return Array.isArray(value) ? value[0] : value;
}

function verifyMailgunSignature(payload, {
    signingKey,
    now = Date.now,
    maxClockSkewMs = defaultReplayWindowMs,
    maxDeliveryAgeMs = maxClockSkewMs,
    replayCache
}) {
    assertConfigured(signingKey, 'Mailgun webhook signing key');
    const timestamp = String(singleValue(payload.timestamp) || '');
    const token = String(singleValue(payload.token) || '');
    const signature = String(singleValue(payload.signature) || '');
    assertFreshTimestamp(timestamp, {now, maxClockSkewMs, maxAgeMs: maxDeliveryAgeMs});
    if (!token || !/^[a-f0-9]{64}$/i.test(signature)) {
        throw securityError('Mailgun webhook signature is invalid');
    }

    const expected = crypto.createHmac('sha256', signingKey).update(timestamp + token).digest('hex');
    if (!secureEqual(signature.toLowerCase(), expected)) {
        throw securityError('Mailgun webhook signature is invalid');
    }
    return replayCache ? replayCache.reserve(`mailgun:${token}`, maxClockSkewMs) : null;
}

function verifySendGridSignature({rawBody, timestamp, signature}, {
    publicKey,
    now = Date.now,
    maxClockSkewMs = defaultReplayWindowMs,
    maxDeliveryAgeMs = maxClockSkewMs,
    replayCache
}) {
    if (!publicKey) {
        throw securityError('SendGrid webhook public key is not configured', 503);
    }
    if (!Buffer.isBuffer(rawBody) || typeof signature !== 'string') {
        throw securityError('SendGrid webhook signature is invalid');
    }
    assertFreshTimestamp(timestamp, {now, maxClockSkewMs, maxAgeMs: maxDeliveryAgeMs});

    let valid = false;
    try {
        valid = crypto.verify('sha256', Buffer.concat([Buffer.from(timestamp), rawBody]), publicKey, Buffer.from(signature, 'base64'));
    } catch (err) {
        valid = false;
    }
    if (!valid) {
        throw securityError('SendGrid webhook signature is invalid');
    }
    return replayCache ? replayCache.reserve(`sendgrid:${signature}`, maxClockSkewMs) : null;
}

function verifyPostalSignature({rawBody, signature, keyId, timestamp}, {
    publicKey,
    keyIds = [],
    now = Date.now,
    maxClockSkewMs = defaultReplayWindowMs,
    maxDeliveryAgeMs = maxClockSkewMs,
    replayCache
}) {
    if (!publicKey) {
        throw securityError('Postal webhook public key is not configured', 503);
    }
    if (!Buffer.isBuffer(rawBody) || typeof signature !== 'string') {
        throw securityError('Postal webhook signature is invalid');
    }
    if (keyIds.length > 0 && !keyIds.some(expected => secureEqual(keyId, expected))) {
        throw securityError('Postal webhook key id is invalid');
    }
    assertFreshTimestamp(timestamp, {now, maxClockSkewMs, maxAgeMs: maxDeliveryAgeMs});

    let valid = false;
    try {
        valid = crypto.verify('sha256', rawBody, publicKey, Buffer.from(signature, 'base64'));
    } catch (err) {
        valid = false;
    }
    if (!valid) {
        throw securityError('Postal webhook signature is invalid');
    }
    return replayCache ? replayCache.reserve(`postal:${signature}`, maxClockSkewMs) : null;
}

function parseAwsTopicArn(topicArn) {
    const match = /^arn:(aws|aws-cn|aws-us-gov):sns:([a-z0-9-]+):\d{12}:[A-Za-z0-9_-]+(?:\.fifo)?$/.exec(topicArn || '');
    if (!match) {
        throw securityError('AWS SNS topic ARN is invalid');
    }
    return {partition: match[1], region: match[2]};
}

function validateAwsSnsUrl(value, label, topicArn, certificate = false) {
    let url;
    try {
        url = new URL(value);
    } catch (err) {
        throw securityError(`AWS SNS ${label} is invalid`);
    }
    const {partition, region} = parseAwsTopicArn(topicArn);
    const suffix = partition === 'aws-cn' ? 'amazonaws.com.cn' : 'amazonaws.com';
    const expectedHost = `sns.${region}.${suffix}`;
    if (url.protocol !== 'https:' || url.hostname !== expectedHost || (url.port && url.port !== '443') || url.username || url.password || url.hash) {
        throw securityError(`AWS SNS ${label} is invalid`);
    }
    if (certificate && (!/^\/SimpleNotificationService-[A-Za-z0-9_-]+\.pem$/.test(url.pathname) || url.search)) {
        throw securityError(`AWS SNS ${label} is invalid`);
    }
    return url;
}

function canonicalizeAwsSnsMessage(message) {
    const fields = message.Type === 'Notification' ? awsNotificationFields : awsConfirmationFields;
    return fields
        .filter(field => message[field] !== undefined)
        .map(field => `${field}\n${message[field]}\n`)
        .join('');
}

async function verifyAwsSnsMessage(message, {
    topicArns,
    fetchCertificate,
    now = Date.now,
    maxClockSkewMs = defaultReplayWindowMs,
    maxDeliveryAgeMs = maxClockSkewMs,
    replayCache
}) {
    if (!message || !['Notification', 'SubscriptionConfirmation', 'UnsubscribeConfirmation'].includes(message.Type)) {
        throw securityError('AWS SNS message type is invalid');
    }
    if (!Array.isArray(topicArns) || !topicArns.some(topicArn => secureEqual(message.TopicArn, topicArn))) {
        throw securityError('AWS SNS topic is not allowed');
    }
    if (!['1', '2'].includes(String(message.SignatureVersion))) {
        throw securityError('AWS SNS signature version is invalid');
    }
    if (typeof fetchCertificate !== 'function') {
        throw securityError('AWS SNS certificate fetcher is not configured', 503);
    }
    assertFreshTimestamp(message.Timestamp, {now, maxClockSkewMs, maxAgeMs: maxDeliveryAgeMs});
    const certUrl = validateAwsSnsUrl(message.SigningCertURL, 'SigningCertURL', message.TopicArn, true);
    const certificate = await fetchCertificate(certUrl.toString());
    const algorithm = String(message.SignatureVersion) === '2' ? 'sha256' : 'sha1';

    let valid = false;
    try {
        valid = crypto.verify(algorithm, Buffer.from(canonicalizeAwsSnsMessage(message)), certificate, Buffer.from(message.Signature || '', 'base64'));
    } catch (err) {
        valid = false;
    }
    if (!valid) {
        throw securityError('AWS SNS signature is invalid');
    }
    return replayCache ? replayCache.reserve(`aws:${message.MessageId}`, maxClockSkewMs) : null;
}

async function confirmAwsSnsSubscription(message, {request, timeout = 5000}) {
    const subscribeUrl = validateAwsSnsUrl(message.SubscribeURL, 'SubscribeURL', message.TopicArn);
    await request({
        uri: subscribeUrl.toString(),
        method: 'GET',
        timeout,
        followRedirect: false,
        simple: true,
        resolveWithFullResponse: true
    });
}

module.exports = {
    ReplayCache,
    assertBasicAuthorization,
    assertBearerAuthorization,
    assertExpectedFields,
    confirmAwsSnsSubscription,
    defaultReplayWindowMs,
    verifyAwsSnsMessage,
    verifyMailgunSignature,
    verifyPostalSignature,
    verifySendGridSignature
};

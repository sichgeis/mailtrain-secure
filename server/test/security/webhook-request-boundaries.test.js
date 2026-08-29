'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const yaml = require('js-yaml');
const {
    ReplayCache,
    assertBasicAuthorization,
    assertBearerAuthorization,
    assertExpectedFields,
    confirmAwsSnsSubscription,
    verifyAwsSnsMessage,
    verifyMailgunSignature,
    verifyPostalSignature,
    verifySendGridSignature
} = require('../../lib/webhook-security');

const repositoryRoot = path.resolve(__dirname, '../../..');
const now = Date.parse('2026-08-29T21:00:00.000Z');

function createAwsMessage(privateKey, overrides = {}) {
    const message = {
        Type: 'Notification',
        Message: JSON.stringify({notificationType: 'Bounce'}),
        MessageId: 'synthetic-sns-message-1',
        Timestamp: new Date(now).toISOString(),
        TopicArn: 'arn:aws:sns:eu-central-1:123456789012:mailtrain-events',
        SigningCertURL: 'https://sns.eu-central-1.amazonaws.com/SimpleNotificationService-test.pem',
        SignatureVersion: '2',
        ...overrides
    };

    const fields = message.Type === 'Notification'
        ? ['Message', 'MessageId', 'Subject', 'Timestamp', 'TopicArn', 'Type']
        : ['Message', 'MessageId', 'SubscribeURL', 'Timestamp', 'Token', 'TopicArn', 'Type'];
    const canonical = fields
        .filter(field => message[field] !== undefined)
        .map(field => `${field}\n${message[field]}\n`)
        .join('');
    message.Signature = crypto.sign('sha256', Buffer.from(canonical), privateKey).toString('base64');
    return message;
}

test('AWS SNS requires a valid signature, allowed topic, fresh timestamp, and one-time message id', async () => {
    const {privateKey, publicKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
    const options = {
        topicArns: ['arn:aws:sns:eu-central-1:123456789012:mailtrain-events'],
        fetchCertificate: async () => publicKey.export({type: 'spki', format: 'pem'}),
        now: () => now,
        replayCache: new ReplayCache({now: () => now})
    };
    const valid = createAwsMessage(privateKey);

    await assert.doesNotReject(() => verifyAwsSnsMessage(valid, options));
    await assert.rejects(() => verifyAwsSnsMessage(valid, options), /replay/i);
    await assert.rejects(() => verifyAwsSnsMessage({...valid, MessageId: 'forged', Signature: valid.Signature}, {...options, replayCache: new ReplayCache()}), /signature/i);
    await assert.rejects(() => verifyAwsSnsMessage(createAwsMessage(privateKey, {TopicArn: 'arn:aws:sns:eu-central-1:123456789012:other'}), {...options, replayCache: new ReplayCache()}), /topic/i);
    await assert.rejects(() => verifyAwsSnsMessage(createAwsMessage(privateKey, {Timestamp: '2026-08-29T20:00:00.000Z'}), {...options, replayCache: new ReplayCache()}), /timestamp/i);
});

test('AWS confirmation permits only signed SNS HTTPS destinations and never follows redirects', async () => {
    const calls = [];
    await assert.doesNotReject(() => confirmAwsSnsSubscription({
        SubscribeURL: 'https://sns.eu-central-1.amazonaws.com/?Action=ConfirmSubscription',
        TopicArn: 'arn:aws:sns:eu-central-1:123456789012:mailtrain-events'
    }, {
        request: async options => calls.push(options)
    }));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].followRedirect, false);
    assert.equal(calls[0].timeout > 0, true);

    await assert.rejects(() => confirmAwsSnsSubscription({
        SubscribeURL: 'http://169.254.169.254/latest/meta-data',
        TopicArn: 'arn:aws:sns:eu-central-1:123456789012:mailtrain-events'
    }, {request: async () => assert.fail('private URL must not be fetched')}), /SubscribeURL/i);
});

test('Mailgun HMAC rejects forged, stale, replayed, and unexpected multipart fields', () => {
    const signingKey = 'synthetic-mailgun-signing-key';
    const timestamp = String(Math.floor(now / 1000));
    const token = 'synthetic-mailgun-token';
    const signature = crypto.createHmac('sha256', signingKey).update(timestamp + token).digest('hex');
    const replayCache = new ReplayCache({now: () => now});
    const options = {signingKey, now: () => now, replayCache};

    assert.doesNotThrow(() => verifyMailgunSignature({timestamp, token, signature}, options));
    assert.throws(() => verifyMailgunSignature({timestamp, token, signature}, options), /replay/i);
    assert.throws(() => verifyMailgunSignature({timestamp, token, signature: '0'.repeat(64)}, {...options, replayCache: new ReplayCache()}), /signature/i);
    assert.throws(() => verifyMailgunSignature({timestamp: String(Number(timestamp) - 3600), token, signature}, {...options, replayCache: new ReplayCache()}), /timestamp/i);
    assert.throws(() => assertExpectedFields({event: 'bounced', attachment: 'unexpected'}, ['event', 'campaign_id', 'timestamp', 'token', 'signature']), /unexpected/i);
});

test('SparkPost Basic credentials use the Authorization header', () => {
    const expected = {username: 'synthetic-user', password: 'synthetic-password'};
    assert.doesNotThrow(() => assertBasicAuthorization(`Basic ${Buffer.from('synthetic-user:synthetic-password').toString('base64')}`, expected));
    assert.throws(() => assertBasicAuthorization(undefined, expected), /authorization/i);
    assert.throws(() => assertBasicAuthorization(`Basic ${Buffer.from('synthetic-user:wrong').toString('base64')}`, expected), /authorization/i);
});

test('SendGrid verifies ECDSA over timestamp plus untouched request bytes', () => {
    const {privateKey, publicKey} = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
    const rawBody = Buffer.from('[{"event":"bounce","campaign_id":"synthetic"}]');
    const timestamp = String(Math.floor(now / 1000));
    const signature = crypto.sign('sha256', Buffer.concat([Buffer.from(timestamp), rawBody]), privateKey).toString('base64');
    const options = {publicKey, now: () => now};

    assert.doesNotThrow(() => verifySendGridSignature({rawBody, timestamp, signature}, options));
    assert.throws(() => verifySendGridSignature({rawBody: Buffer.from('{}'), timestamp, signature}, options), /signature/i);
    assert.throws(() => verifySendGridSignature({rawBody, timestamp: String(Number(timestamp) - 3600), signature}, options), /timestamp/i);
});

test('Postal verifies the RSA-SHA256 body signature and configured key id', () => {
    const {privateKey, publicKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
    const rawBody = Buffer.from('{"event":"MessageBounced"}');
    const signature = crypto.sign('sha256', rawBody, privateKey).toString('base64');
    const options = {publicKey, keyIds: ['synthetic-postal-key']};

    assert.doesNotThrow(() => verifyPostalSignature({rawBody, signature, keyId: 'synthetic-postal-key'}, options));
    assert.throws(() => verifyPostalSignature({rawBody, signature, keyId: 'other-key'}, options), /key id/i);
    assert.throws(() => verifyPostalSignature({rawBody: Buffer.from('{}'), signature, keyId: 'synthetic-postal-key'}, options), /signature/i);
});

test('ZoneMTA bounce and DKIM credentials are accepted only from headers', () => {
    assert.doesNotThrow(() => assertBearerAuthorization('Bearer synthetic-zone-token', 'synthetic-zone-token'));
    assert.throws(() => assertBearerAuthorization(undefined, 'synthetic-zone-token'), /authorization/i);

    const routes = fs.readFileSync(path.join(repositoryRoot, 'server/routes/webhooks.js'), 'utf8');
    assert.doesNotMatch(routes, /uploads\.any\(\)/);
    assert.doesNotMatch(routes, /req\.query\.api_token/);
    assert.match(routes, /authorization/i);
});

test('body parsing and webhook defaults are bounded and fail closed', () => {
    const appBuilder = fs.readFileSync(path.join(repositoryRoot, 'server/app-builder.js'), 'utf8');
    const defaults = yaml.safeLoad(fs.readFileSync(path.join(repositoryRoot, 'server/config/default.yaml'), 'utf8'));

    assert.match(appBuilder, /rawBody/);
    assert.equal(defaults.security.webhooks.aws.enabled, false);
    assert.equal(defaults.security.webhooks.mailgun.maxFieldSize > 0, true);
    assert.equal(defaults.security.webhooks.mailgun.maxFields > 0, true);
    assert.equal(defaults.security.requestTimeoutMs > 0, true);
});

'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {Readable} = require('node:stream');
const test = require('node:test');
const yaml = require('js-yaml');
const {createMailgunUpload} = require('../../lib/mailgun-upload');
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
    await assert.rejects(() => verifyAwsSnsMessage(createAwsMessage(privateKey, {SigningCertURL: 'https://169.254.169.254/certificate.pem'}), {
        ...options,
        replayCache: new ReplayCache(),
        fetchCertificate: async () => assert.fail('private certificate URL must not be fetched')
    }), /SigningCertURL/i);
    await assert.rejects(() => verifyAwsSnsMessage(null, options), /type/i);
});

test('replay reservations retry after failure, deduplicate success, and preserve lease ownership', async () => {
    let now = 1000;
    const cache = new ReplayCache({now: () => now});
    const first = cache.reserve('provider:delivery', 100);
    await assert.rejects(() => first.run(async () => {
        throw new Error('synthetic downstream failure');
    }), /downstream/);

    const retry = cache.reserve('provider:delivery', 100);
    let mutations = 0;
    await retry.run(async () => mutations++);
    const duplicate = cache.reserve('provider:delivery', 100);
    await duplicate.run(async () => mutations++);
    assert.equal(mutations, 1);
    assert.equal(duplicate.completed, true);

    const expired = cache.reserve('provider:lease-race', 100);
    now += 101;
    const replacement = cache.reserve('provider:lease-race', 100);
    expired.rollback();
    assert.throws(() => cache.reserve('provider:lease-race', 100), /processing/i);
    replacement.rollback();
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

test('Mailgun multipart parsing rejects files, oversized fields, and excessive concurrent parts', async () => {
    const boundary = 'mailtrain-security-test-boundary';
    const upload = createMailgunUpload({maxFields: 5, maxFieldSize: 20});
    const parse = parts => {
        const chunks = parts.map(part => {
            const filename = part.filename ? `; filename="${part.filename}"` : '';
            const contentType = part.filename ? 'Content-Type: text/plain\r\n' : '';
            return `--${boundary}\r\nContent-Disposition: form-data; name="${part.name}"${filename}\r\n${contentType}\r\n${part.value}\r\n`;
        });
        const body = Buffer.from(chunks.join('') + `--${boundary}--\r\n`);
        const req = Readable.from([body]);
        req.headers = {
            'content-type': `multipart/form-data; boundary=${boundary}`,
            'content-length': String(body.length)
        };
        req.method = 'POST';
        return new Promise(resolve => upload(req, {}, err => resolve({err, req})));
    };

    assert.equal((await parse([{name: 'event', value: 'bounced'}])).err, undefined);
    assert.equal((await parse([{name: 'attachment', value: 'synthetic', filename: 'synthetic.txt'}])).err.status, 413);

    const oversizedRequests = Array.from({length: 8}, (_, index) => parse([
        {name: 'event', value: `oversized-${index}-${'x'.repeat(32)}`}
    ]));
    assert.deepEqual((await Promise.all(oversizedRequests)).map(result => result.err.status), Array(8).fill(413));

    const excessiveParts = Array.from({length: 6}, (_, index) => ({name: `field-${index}`, value: 'value'}));
    assert.equal((await parse(excessiveParts)).err.status, 413);
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
    const options = {publicKey, now: () => now, replayCache: new ReplayCache({now: () => now})};

    assert.doesNotThrow(() => verifySendGridSignature({rawBody, timestamp, signature}, options));
    assert.throws(() => verifySendGridSignature({rawBody, timestamp, signature}, options), /replay/i);
    assert.throws(() => verifySendGridSignature({rawBody: Buffer.from('{}'), timestamp, signature}, {...options, replayCache: new ReplayCache()}), /signature/i);
    assert.throws(() => verifySendGridSignature({rawBody, timestamp: String(Number(timestamp) - 3600), signature}, {...options, replayCache: new ReplayCache()}), /timestamp/i);
});

test('Postal verifies the RSA-SHA256 body signature and configured key id', () => {
    const {privateKey, publicKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
    const timestamp = now / 1000;
    const rawBody = Buffer.from(`{"event":"MessageBounced","timestamp":${timestamp}}`);
    const signature = crypto.sign('sha256', rawBody, privateKey).toString('base64');
    const options = {publicKey, keyIds: ['synthetic-postal-key'], now: () => now, replayCache: new ReplayCache({now: () => now})};

    assert.doesNotThrow(() => verifyPostalSignature({rawBody, signature, keyId: 'synthetic-postal-key', timestamp}, options));
    assert.throws(() => verifyPostalSignature({rawBody, signature, keyId: 'synthetic-postal-key', timestamp}, options), /replay/i);
    assert.throws(() => verifyPostalSignature({rawBody, signature, keyId: 'other-key', timestamp}, {...options, replayCache: new ReplayCache()}), /key id/i);
    assert.throws(() => verifyPostalSignature({rawBody: Buffer.from('{}'), signature, keyId: 'synthetic-postal-key', timestamp}, {...options, replayCache: new ReplayCache()}), /signature/i);
    assert.throws(() => verifyPostalSignature({rawBody, signature, keyId: 'synthetic-postal-key', timestamp: timestamp - 3600}, {...options, replayCache: new ReplayCache()}), /timestamp/i);
});

test('ZoneMTA bounce and DKIM credentials are accepted only from headers', () => {
    assert.doesNotThrow(() => assertBearerAuthorization('Bearer synthetic-zone-token', 'synthetic-zone-token'));
    assert.throws(() => assertBearerAuthorization(undefined, 'synthetic-zone-token'), /authorization/i);

    const routes = fs.readFileSync(path.join(repositoryRoot, 'server/routes/webhooks.js'), 'utf8');
    assert.doesNotMatch(routes, /uploads\.any\(\)/);
    assert.doesNotMatch(routes, /req\.query\.api_token/);
    assert.match(routes, /authorization/i);

    const builtinZoneMta = fs.readFileSync(path.join(repositoryRoot, 'server/lib/builtin-zone-mta.js'), 'utf8');
    const zoneMtaPlugin = fs.readFileSync(path.join(repositoryRoot, 'zone-mta/plugins/mailtrain-main.js'), 'utf8');
    assert.match(builtinZoneMta, /['"]core\/http-bounce['"]: false/);
    assert.match(builtinZoneMta, /bounceToken/);
    assert.match(zoneMtaPlugin, /Authorization/);
    assert.match(zoneMtaPlugin, /Bearer/);

    const proxy = yaml.safeLoad(fs.readFileSync(path.join(repositoryRoot, 'deploy/netcup/traefik-dynamic.yml'), 'utf8'));
    const internalRouter = proxy.http.routers['mailtrain-zone-mta-internal'];
    assert.match(internalRouter.rule, /PathPrefix\(`\/webhooks\/zone-mta`\)/);
    assert.ok(internalRouter.priority > (proxy.http.routers['mailtrain-trusted'].priority || 0));
    assert.deepEqual(internalRouter.middlewares, ['mailtrain-zone-mta-internal-only']);
    assert.deepEqual(proxy.http.middlewares['mailtrain-zone-mta-internal-only'].ipAllowList.sourceRange, ['127.0.0.0/8', '::1/128']);
});

test('body parsing and webhook defaults are bounded and fail closed', () => {
    const appBuilder = fs.readFileSync(path.join(repositoryRoot, 'server/app-builder.js'), 'utf8');
    const defaults = yaml.safeLoad(fs.readFileSync(path.join(repositoryRoot, 'server/config/default.yaml'), 'utf8'));
    const proxy = yaml.safeLoad(fs.readFileSync(path.join(repositoryRoot, 'deploy/traefik/request-boundaries.yml'), 'utf8'));

    assert.match(appBuilder, /rawBody/);
    assert.equal(defaults.security.webhooks.aws.enabled, false);
    assert.equal(defaults.security.webhooks.mailgun.maxFieldSize > 0, true);
    assert.equal(defaults.security.webhooks.mailgun.maxFields > 0, true);
    assert.equal(defaults.security.requestTimeoutMs > 0, true);
    assert.equal(proxy.http.middlewares['mailtrain-request-limit'].buffering.maxRequestBodyBytes, 2097152);
    assert.equal(proxy.http.middlewares['mailtrain-mailgun-request-limit'].buffering.maxRequestBodyBytes, 65536);
});

'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const { createRequire } = require('node:module');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const test = require('node:test');

const mainPlugin = require('../plugins/mailtrain-main');
const receiverPlugin = require('../plugins/mailtrain-receiver');

test('request-compatible HTTP delivery posts multipart message content', async t => {
    const zoneMtaRequire = createRequire(require.resolve('@zone-eu/zone-mta/lib/sender'));
    const request = zoneMtaRequire('request');
    assert.equal(zoneMtaRequire('request/package.json').name, '@cypress/request');

    let receiveUpload;
    let rejectUpload;
    const received = new Promise((resolve, reject) => {
        receiveUpload = resolve;
        rejectUpload = reject;
    });
    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.once('error', rejectUpload);
        req.once('end', () => {
            receiveUpload({
                body: Buffer.concat(chunks).toString(),
                contentType: req.headers['content-type'],
                method: req.method
            });
            res.writeHead(204);
            res.end();
        });
    });
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    t.after(() => server.close());

    const { port } = server.address();
    const requestCompleted = new Promise((resolve, reject) => {
        request.post({
            url: `http://127.0.0.1:${port}/upload`,
            formData: {
                id: 'message.1',
                message: {
                    value: Buffer.from('Subject: delivery test\r\n\r\nHello'),
                    options: {
                        filename: 'message.eml',
                        contentType: 'message/rfc822'
                    }
                }
            }
        }, (error, response) => {
            if (error) {
                reject(error);
            } else if (response.statusCode !== 204) {
                reject(new Error(`Unexpected response status ${response.statusCode}`));
            } else {
                resolve();
            }
        });
    });

    const [upload] = await Promise.all([received, requestCompleted]);
    assert.equal(upload.method, 'POST');
    assert.match(upload.contentType, /^multipart\/form-data; boundary=/);
    assert.match(upload.body, /name="id"[\s\S]*message\.1/);
    assert.match(upload.body, /filename="message\.eml"/);
    assert.match(upload.body, /Subject: delivery test/);
});

test('maintained ZoneMTA loads the Mailtrain configuration', () => {
    const zoneMtaDirectory = path.resolve(__dirname, '..');
    const result = spawnSync(process.execPath, ['index.js', '--config=config/zonemta.js'], {
        cwd: zoneMtaDirectory,
        encoding: 'utf8',
        env: {
            ...process.env,
            NODE_CONFIG_ONLY: 'true',
            MAILTRAIN_ZONE_MTA_BOUNCE_URL: 'https://mailtrain.example.test/webhooks/zone-mta',
            MAILTRAIN_ZONE_MTA_TOKEN: 'test-only-token'
        },
        timeout: 10_000
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /mailtrain-main/);
    assert.match(result.stdout, /https:\/\/mailtrain\.example\.test\/webhooks\/zone-mta/);
});

function initialize(plugin, config = {}) {
    const hooks = new Map();
    const errors = [];
    const app = {
        config,
        logger: {
            error(...args) {
                errors.push(args);
            }
        },
        addHook(name, handler) {
            hooks.set(name, handler);
        }
    };

    let initialized = false;
    const originalSend = process.send;
    process.send = () => {};
    try {
        plugin.init(app, () => {
            initialized = true;
        });
    } finally {
        process.send = originalSend;
    }

    assert.equal(initialized, true);
    return { errors, hooks };
}

test('main plugin refuses unauthenticated bounce callbacks', () => {
    const { errors, hooks } = initialize(mainPlugin);
    let continued = false;

    hooks.get('queue:bounce')({}, {}, () => {
        continued = true;
    });

    assert.equal(continued, true);
    assert.match(errors[0][1], /not configured/);
});

test('main plugin authenticates internal bounce callbacks with the configured trusted host', async t => {
    let resolveRequest;
    let rejectRequest;
    const receivedRequest = new Promise((resolve, reject) => {
        resolveRequest = resolve;
        rejectRequest = reject;
    });
    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', chunk => chunks.push(chunk));
        req.once('error', rejectRequest);
        req.once('end', () => {
            resolveRequest({
                authorization: req.headers.authorization,
                body: Buffer.concat(chunks).toString(),
                host: req.headers.host
            });
            res.writeHead(200);
            res.end('ok');
        });
    });
    await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, '127.0.0.1', resolve);
    });
    t.after(() => server.close());

    const {port} = server.address();
    const {hooks} = initialize(mainPlugin, {
        bounceHost: 'mail.example.test',
        bounceToken: 'synthetic-bounce-token',
        bounceUrl: `http://127.0.0.1:${port}/webhooks/zone-mta`
    });
    const completed = new Promise(resolve => {
        hooks.get('queue:bounce')({
            category: 'recipient',
            from: 'sender@example.test',
            headers: {getFirst: () => null},
            id: 'message.1',
            response: '550 rejected',
            seq: 1,
            time: Date.now(),
            to: 'recipient@example.test'
        }, {}, resolve);
    });

    const [request] = await Promise.all([receivedRequest, completed]);
    assert.equal(request.host, 'mail.example.test');
    assert.equal(request.authorization, 'Bearer synthetic-bounce-token');
    assert.match(request.body, /message\.1/);
});

test('receiver plugin accepts only the configured SMTP credential pair', () => {
    const { hooks } = initialize(receiverPlugin, {
        username: 'mailer',
        password: 'correct horse battery staple'
    });
    const authenticate = hooks.get('smtp:auth');

    authenticate({ username: 'mailer', password: 'correct horse battery staple' }, {}, error => {
        assert.equal(error, undefined);
    });
    authenticate({ username: 'mailer', password: 'wrong' }, {}, error => {
        assert.equal(error.responseCode, 535);
        assert.equal(error.message, 'Authentication failed');
    });
});

test('receiver plugin consumes the private DKIM header before queueing', () => {
    const { hooks } = initialize(receiverPlugin);
    const values = new Map([
        ['x-mailtrain-dkim', JSON.stringify({ domainName: 'example.test', keySelector: 'mail' })]
    ]);
    const removed = [];
    const envelope = {
        dkim: {},
        headers: {
            getFirst(name) {
                return values.get(name.toLowerCase());
            },
            remove(name) {
                removed.push(name);
            }
        }
    };

    hooks.get('message:headers')(envelope, {}, () => {});

    assert.deepEqual(envelope.dkim.keys, [{ domainName: 'example.test', keySelector: 'mail' }]);
    assert.deepEqual(removed, ['x-mailtrain-dkim']);
});

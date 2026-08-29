'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const {
    createOutboundFetcher,
    isPublicAddress
} = require('../../lib/outbound-fetch');
const {resolvePathWithinBase} = require('../../lib/safe-path');

const repositoryRoot = path.resolve(__dirname, '../../..');
const basePolicy = {
    allowedPorts: [80, 443],
    maxRedirects: 2,
    timeoutMs: 5000,
    maxResponseSize: 1024,
    allowedSubscriberDataOrigins: []
};

function response(statusCode = 200, body = 'ok', headers = {}) {
    return {statusCode, body: Buffer.from(body), headers};
}

test('public-address policy rejects private, loopback, link-local, ULA, multicast, and mapped addresses', () => {
    for (const address of [
        '0.0.0.0', '10.0.0.1', '100.64.0.1', '127.0.0.1', '169.254.169.254',
        '172.16.0.1', '192.168.0.1', '224.0.0.1', '::', '::1', '::ffff:127.0.0.1',
        'fc00::1', 'fd00::1', 'fe80::1', 'ff00::1'
    ]) assert.equal(isPublicAddress(address), false, address);

    assert.equal(isPublicAddress('93.184.216.34'), true);
    assert.equal(isPublicAddress('2606:4700:4700::1111'), true);
});

test('outbound fetch pins a validated public address and permits only HTTP(S) ports 80/443', async () => {
    const calls = [];
    const fetch = createOutboundFetcher(basePolicy, {
        resolveHostname: async () => [{address: '93.184.216.34', family: 4}],
        requestOnce: async options => {
            calls.push(options);
            return response();
        }
    });

    assert.equal((await fetch('https://example.com/news')).body, 'ok');
    assert.equal(calls[0].address, '93.184.216.34');
    await assert.rejects(() => fetch('http://example.com:8080/'), /port/i);
    await assert.rejects(() => fetch('file:///etc/passwd'), /protocol/i);
    await assert.rejects(() => fetch('http://127.0.0.1/'), /public/i);
});

test('every redirect and repeated DNS resolution is revalidated before a connection', async () => {
    let resolution = 0;
    const calls = [];
    const fetch = createOutboundFetcher(basePolicy, {
        resolveHostname: async () => [{address: resolution++ === 0 ? '93.184.216.34' : '127.0.0.1', family: 4}],
        requestOnce: async options => {
            calls.push(options);
            return response(302, '', {location: 'https://example.com/private'});
        }
    });

    await assert.rejects(() => fetch('https://example.com/start'), /public/i);
    assert.equal(calls.length, 1);

    const redirectToMetadata = createOutboundFetcher(basePolicy, {
        resolveHostname: async hostname => [{address: hostname === 'example.com' ? '93.184.216.34' : '169.254.169.254', family: 4}],
        requestOnce: async () => response(302, '', {location: 'http://metadata.invalid/latest'})
    });
    await assert.rejects(() => redirectToMetadata('https://example.com/start'), /public/i);
});

test('redirect count, duration, and response size are bounded', async () => {
    const resolveHostname = async () => [{address: '93.184.216.34', family: 4}];
    const redirecting = createOutboundFetcher({...basePolicy, maxRedirects: 1}, {
        resolveHostname,
        requestOnce: async () => response(302, '', {location: 'https://example.com/again'})
    });
    await assert.rejects(() => redirecting('https://example.com/start'), /redirect/i);

    const oversized = createOutboundFetcher({...basePolicy, maxResponseSize: 4}, {
        resolveHostname,
        requestOnce: async () => response(200, 'oversized')
    });
    await assert.rejects(() => oversized('https://example.com/'), /size/i);

    const timedOut = createOutboundFetcher({...basePolicy, timeoutMs: 10}, {
        resolveHostname,
        requestOnce: async () => {
            const error = new Error('Outbound request timed out');
            error.code = 'ETIMEDOUT';
            throw error;
        }
    });
    await assert.rejects(() => timedOut('https://example.com/'), /timed out/i);
});

test('subscriber form data is transmitted only to an explicitly approved exact origin', async () => {
    const calls = [];
    const dependencies = {
        resolveHostname: async () => [{address: '93.184.216.34', family: 4}],
        requestOnce: async options => {
            calls.push(options);
            return response();
        }
    };
    const blocked = createOutboundFetcher(basePolicy, dependencies);
    await assert.rejects(() => blocked('https://renderer.example/campaign', {
        method: 'POST',
        form: {EMAIL: 'subscriber@example.test'},
        sensitiveData: true
    }), /subscriber data/i);
    assert.equal(calls.length, 0);

    const approved = createOutboundFetcher({
        ...basePolicy,
        allowedSubscriberDataOrigins: ['https://renderer.example']
    }, dependencies);
    await approved('https://renderer.example/campaign', {
        method: 'POST',
        form: {EMAIL: 'subscriber@example.test'},
        sensitiveData: true
    });
    assert.match(calls[0].body.toString(), /subscriber%40example\.test/);

    await assert.rejects(() => approved('https://renderer.example.evil.test/campaign', {
        method: 'POST', form: {EMAIL: 'subscriber@example.test'}, sensitiveData: true
    }), /subscriber data/i);
});

test('fixed-base path resolution rejects traversal encodings, absolute paths, and escaping symlinks', async t => {
    const base = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'mailtrain-safe-path-'));
    const outside = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'mailtrain-safe-path-outside-'));
    t.after(async () => {
        await fs.promises.rm(base, {recursive: true, force: true});
        await fs.promises.rm(outside, {recursive: true, force: true});
    });
    await fs.promises.writeFile(path.join(base, 'image.png'), 'synthetic');
    await fs.promises.writeFile(path.join(outside, 'secret.txt'), 'synthetic-secret');
    await fs.promises.symlink(path.join(outside, 'secret.txt'), path.join(base, 'escape'));

    assert.equal(await resolvePathWithinBase(base, 'image.png'), path.join(base, 'image.png'));
    for (const unsafe of ['../secret.txt', '%2e%2e/secret.txt', '%252e%252e/secret.txt', '/etc/passwd', 'C:\\Windows\\win.ini', 'escape']) {
        await assert.rejects(() => resolvePathWithinBase(base, unsafe), /path/i, unsafe);
    }
});

test('all campaign, RSS, AWS confirmation, preview, and legacy Mosaico boundaries use shared policies', () => {
    const feedcheck = fs.readFileSync(path.join(repositoryRoot, 'server/lib/feedcheck.js'), 'utf8');
    const messageSender = fs.readFileSync(path.join(repositoryRoot, 'server/lib/message-sender.js'), 'utf8');
    const webhooks = fs.readFileSync(path.join(repositoryRoot, 'server/routes/webhooks.js'), 'utf8');
    const mosaico = fs.readFileSync(path.join(repositoryRoot, 'server/routes/sandboxed-mosaico.js'), 'utf8');

    assert.match(feedcheck, /outbound-fetch/);
    assert.match(messageSender, /outbound-fetch/);
    assert.match(webhooks, /outbound-fetch/);
    assert.match(mosaico, /safe-path/);
    assert.doesNotMatch(mosaico, /path\.join\([^\n]+mosaicoLegacyUrlPrefix/);
});

'use strict';

const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {AppType} = require('../../../shared/app');
const {extractAccessToken} = require('../../lib/auth-security');
const {
    createHostCheckMiddleware,
    createOriginCheckMiddleware,
    securityHeaders,
    untrustedContentSecurityPolicy,
    validateOriginSeparation,
    validateProxyTrust
} = require('../../lib/browser-security');
const {sanitizeUntrustedHtml} = require('../../lib/html-sanitizer');
const {redactLogMessage} = require('../../lib/log-redaction');
const {configureRateLimitStore, createRateLimitMiddleware, MemoryRateLimitStore, RedisRateLimitStore} = require('../../lib/rate-limit');
const {accountRateLimiters} = require('../../lib/request-rate-limiters');
const {RestrictedTokenStore} = require('../../lib/restricted-token-store');
const {buildSessionOptions, validateSessionSecurity} = require('../../lib/session-security');

const repositoryRoot = path.resolve(__dirname, '../../..');

function tokenRequest({authorization, accessToken, queryToken} = {}) {
    return {
        get(name) {
            if (name.toLowerCase() === 'authorization') {
                return authorization;
            }
            if (name.toLowerCase() === 'access-token') {
                return accessToken;
            }
        },
        query: queryToken === undefined ? {} : {access_token: queryToken}
    };
}

test('API tokens prefer standard Bearer and legacy header while query tokens fail closed', () => {
    assert.equal(extractAccessToken(tokenRequest({authorization: 'Bearer bearer-secret'}), {}), 'bearer-secret');
    assert.equal(extractAccessToken(tokenRequest({accessToken: 'legacy-header-secret'}), {}), 'legacy-header-secret');
    assert.throws(() => extractAccessToken(tokenRequest({queryToken: 'query-secret'}), {}), /disabled/i);
    assert.throws(() => extractAccessToken(tokenRequest({authorization: 'Bearer bearer-secret', queryToken: 'query-secret'}), {}), /disabled/i);
    assert.throws(() => extractAccessToken(tokenRequest({authorization: 'Basic abc'}), {}), /authorization/i);
    assert.throws(() => extractAccessToken(tokenRequest({authorization: 'Bearer one', accessToken: 'two'}), {}), /conflicting/i);
    assert.throws(() => extractAccessToken(tokenRequest({authorization: 'Bearer same', accessToken: 'same'}), {}), /conflicting/i);
});

test('temporary query-token compatibility is explicit and warns without exposing the token', () => {
    const warnings = [];
    assert.equal(extractAccessToken(tokenRequest({queryToken: 'query-canary-secret'}), {
        legacyQueryTokensEnabled: true,
        warn: message => warnings.push(message)
    }), 'query-canary-secret');
    assert.equal(warnings.length, 1);
    assert.doesNotMatch(warnings[0], /query-canary-secret/);
    assert.match(warnings[0], /deprecated/i);
});

test('session settings use bounded hardened cookies and reject weak production configuration', () => {
    const options = buildSessionOptions({
        secret: '0123456789abcdef0123456789abcdef',
        secure: true,
        maxAgeMs: 12 * 60 * 60 * 1000,
        name: 'mailtrain.sid'
    });
    assert.equal(options.cookie.secure, true);
    assert.equal(options.cookie.httpOnly, true);
    assert.equal(options.cookie.sameSite, 'lax');
    assert.equal(options.cookie.maxAge, 12 * 60 * 60 * 1000);
    assert.equal(options.name, 'mailtrain.sid');

    assert.throws(() => validateSessionSecurity({secret: 'a cat', secure: false, name: 'mailtrain.sid'}, {production: true}), /secret/i);
    assert.throws(() => validateSessionSecurity({secret: 'a'.repeat(64), secure: true, name: '__Host-mailtrain.sid'}, {production: true}), /entropy/i);
    assert.throws(() => validateSessionSecurity({secret: '0123456789abcdef0123456789abcdef', secure: false, name: '__Host-mailtrain.sid'}, {production: true}), /secure/i);
    assert.throws(() => validateSessionSecurity({secret: '0123456789abcdef0123456789abcdef', secure: true, name: 'mailtrain.sid'}, {production: true}), /__Host/i);
});

test('Docker session-secret validation rejects ephemeral or unsafe production input', () => {
    const validator = path.join(repositoryRoot, 'server/setup/validate-session-secret.js');
    const run = overrides => childProcess.spawnSync(process.execPath, [validator], {
        env: {...process.env, WWW_SECRET: '', SESSION_COOKIE_SECURE: 'true', ...overrides},
        encoding: 'utf8'
    });
    assert.notEqual(run({}).status, 0);
    const weak = run({WWW_SECRET: 'weak-secret-canary'});
    assert.notEqual(weak.status, 0);
    assert.doesNotMatch(weak.stderr, /weak-secret-canary/);
    assert.equal(run({WWW_SECRET: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFG'}).status, 0);
    assert.notEqual(run({
        WWW_SECRET: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFG',
        SESSION_COOKIE_SECURE: 'false'
    }).status, 0);
});

test('production origins are distinct HTTPS origins and browser headers are role-specific', () => {
    const origins = {
        trustedUrlBase: 'https://mail.example.test',
        sandboxUrlBase: 'https://sandbox.example.test',
        publicUrlBase: 'https://public.example.test'
    };
    assert.doesNotThrow(() => validateOriginSeparation(origins, {production: true}));
    assert.throws(() => validateOriginSeparation({...origins, sandboxUrlBase: origins.trustedUrlBase}, {production: true}), /distinct/i);
    assert.throws(() => validateOriginSeparation({...origins, publicUrlBase: 'http://public.example.test'}, {production: true}), /HTTPS/i);

    const trusted = securityHeaders(AppType.TRUSTED, {secure: true});
    assert.equal(trusted['strict-transport-security'], 'max-age=31536000; includeSubDomains');
    assert.equal(trusted['x-content-type-options'], 'nosniff');
    assert.equal(trusted['referrer-policy'], 'no-referrer');
    assert.match(trusted['content-security-policy'], /frame-ancestors 'none'/);
    const sandboxCsp = securityHeaders(AppType.SANDBOXED, {secure: true})['content-security-policy'];
    assert.match(sandboxCsp, /sandbox/);
    assert.match(sandboxCsp, /script-src 'self' 'unsafe-inline'/);
    assert.match(securityHeaders(AppType.PUBLIC, {secure: true})['content-security-policy'], /script-src 'self' 'unsafe-inline' https:/);
    assert.match(untrustedContentSecurityPolicy(), /script-src 'none'/);
    assert.match(untrustedContentSecurityPolicy(), /form-action 'none'/);
    assert.throws(() => validateProxyTrust(true, {production: true}), /every proxy/i);
    assert.doesNotThrow(() => validateProxyTrust('loopback, linklocal, uniquelocal', {production: true}));
});

test('host and unsafe-method origin checks reject cross-origin boundary confusion', () => {
    const allowedRequest = {
        method: 'POST',
        get(name) {
            return name === 'host' ? 'mail.example.test' : 'https://mail.example.test';
        }
    };
    let error;
    createHostCheckMiddleware('https://mail.example.test')(allowedRequest, {}, err => {
        error = err;
    });
    assert.equal(error, undefined);
    createOriginCheckMiddleware('https://mail.example.test')(allowedRequest, {}, err => {
        error = err;
    });
    assert.equal(error, undefined);

    createHostCheckMiddleware('https://mail.example.test')({get: () => 'sandbox.example.test'}, {}, err => {
        error = err;
    });
    assert.equal(error.status, 421);
    createOriginCheckMiddleware('https://mail.example.test')({
        method: 'POST',
        get: () => 'https://evil.example.test'
    }, {}, err => {
        error = err;
    });
    assert.equal(error.status, 403);
});

test('stored HTML sanitization removes active content while preserving email layout', () => {
    const dirty = '<table style="color:red;background:url(javascript:alert(1))"><tr><td onclick="alert(1)">Hello <strong>world</strong></td></tr></table>' +
        '<script>alert(1)</script><iframe src="https://evil.test"></iframe><object data="x"></object>' +
        '<svg onload="alert(1)"></svg><a href="javascript:alert(1)">bad</a><img src="data:text/html,x" onerror="x">' +
        '<a href="https://safe.example/path">safe</a>';
    const clean = sanitizeUntrustedHtml(dirty);
    assert.match(clean, /<table/);
    assert.match(clean, /<strong>world<\/strong>/);
    assert.doesNotMatch(clean, /script|iframe|object|svg|onclick|onerror|javascript:|data:text|background:/i);
    assert.match(clean, /href="https:\/\/safe\.example\/path"/);
    assert.match(clean, /rel="noopener noreferrer"/);

    const fullDocument = sanitizeUntrustedHtml('<!doctype html><html><head><style>body{color:red}</style><script>x</script></head><body><table><tr><td>Kept</td></tr></table></body></html>');
    assert.match(fullDocument, /<!DOCTYPE html>/i);
    assert.match(fullDocument, /<\/body><\/html>/i);
    assert.match(fullDocument, /<td>Kept<\/td>/);
    assert.doesNotMatch(fullDocument, /<script|<style/i);
});

test('log redaction removes URL, header, email, form, and reset-token canaries', () => {
    const message = 'POST /api/list?access_token=query-canary&email=user@example.test authorization: Bearer bearer-canary ' +
        'access-token: header-canary /login/reset/admin/reset-path-canary password=pass-canary api_token=dkim-canary ' +
        '/api/lists/encoded%40example.test {"password":"json-pass-canary","email":"json@example.test"}';
    const redacted = redactLogMessage(message);
    for (const canary of ['query-canary', 'user@example.test', 'bearer-canary', 'header-canary', 'reset-path-canary', 'pass-canary', 'dkim-canary', 'encoded%40example.test', 'json-pass-canary', 'json@example.test']) {
        assert.doesNotMatch(redacted, new RegExp(canary), canary);
    }
    assert.match(redacted, /\[REDACTED\]/);
});

test('in-memory throttling enforces boundaries, resets windows, and bounds storage', async () => {
    let now = 1000;
    const store = new MemoryRateLimitStore({maxEntries: 2, now: () => now});
    assert.equal((await store.consume('login:ip:one', {limit: 2, windowMs: 100})).allowed, true);
    assert.equal((await store.consume('login:ip:one', {limit: 2, windowMs: 100})).allowed, true);
    assert.equal((await store.consume('login:ip:one', {limit: 2, windowMs: 100})).allowed, false);
    now += 101;
    assert.equal((await store.consume('login:ip:one', {limit: 2, windowMs: 100})).allowed, true);
    await store.consume('reset:account:two', {limit: 1, windowMs: 100});
    await store.consume('subscribe:list:three', {limit: 1, windowMs: 100});
    assert.ok(store.size <= 2);
});

test('rate-limit middleware returns a generic 429 and Retry-After', async () => {
    const middleware = createRateLimitMiddleware({
        store: {consume: async () => ({allowed: false, remaining: 0, retryAfterMs: 1200})},
        policy: {limit: 2, windowMs: 1000},
        key: () => 'login:test'
    });
    const headers = {};
    const response = {
        setHeader(name, value) {
            headers[name] = value;
        },
        status(status) {
            this.statusCode = status;
            return this;
        },
        json(body) {
            this.body = body;
        }
    };
    await middleware({}, response, assert.fail);
    assert.equal(response.statusCode, 429);
    assert.deepEqual(response.body, {message: 'Too many requests'});
    assert.equal(headers['Retry-After'], '2');
});

test('account throttling has independent per-IP and per-account buckets', async () => {
    const consumed = [];
    configureRateLimitStore({
        async consume(key, policy) {
            consumed.push({key, policy});
            return {allowed: true, remaining: policy.limit - 1, retryAfterMs: policy.windowMs};
        }
    });
    const response = {setHeader() {}};
    const invoke = (middleware, username, ip = '203.0.113.10') => new Promise((resolve, reject) => middleware({
        ip,
        body: {username}
    }, response, error => error ? reject(error) : resolve()));

    await invoke(accountRateLimiters.login[0], 'alice');
    await invoke(accountRateLimiters.login[0], 'bob');
    assert.equal(consumed[0].key, consumed[1].key);
    await invoke(accountRateLimiters.login[1], 'alice');
    await invoke(accountRateLimiters.login[1], 'alice', '198.51.100.25');
    assert.equal(consumed[2].key, consumed[3].key);
    await invoke(accountRateLimiters.login[1], 'bob');
    assert.notEqual(consumed[3].key, consumed[4].key);
});

test('Redis throttling uses one atomic expiring operation and fails closed', async () => {
    const calls = [];
    const redis = {
        eval(script, keyCount, key, windowMs, callback) {
            calls.push({script, keyCount, key, windowMs});
            callback(null, [3, 900]);
        }
    };
    const store = new RedisRateLimitStore(redis, {prefix: 'mailtrain:security:'});
    const result = await store.consume('webhook:mailgun', {limit: 2, windowMs: 1000});
    assert.equal(result.allowed, false);
    assert.equal(calls[0].keyCount, 1);
    assert.match(calls[0].script, /PEXPIRE/);
    await assert.rejects(() => new RedisRateLimitStore({eval(script, count, key, window, callback) {
        callback(new Error('redis unavailable'));
    }}).consume('login', {limit: 1, windowMs: 1000}), /unavailable/i);
});

test('restricted sandbox capability storage expires, bounds, and scopes refreshes', () => {
    let now = 1000;
    const store = new RestrictedTokenStore({ttlMs: 100, maxEntries: 2, maxPerUser: 1, now: () => now});
    store.create({token: 'one', userId: 1, handler: {}});
    assert.throws(() => store.create({token: 'two', userId: 1, handler: {}}), error => error.status === 429);
    assert.equal(store.refresh('one', 2), false);
    assert.equal(store.refresh('one', 1), true);
    store.create({token: 'two', userId: 2, handler: {}});
    assert.throws(() => store.create({token: 'three', userId: 3, handler: {}}), error => error.status === 429);
    now += 101;
    assert.equal(store.get('one'), undefined);
    assert.equal(store.size, 0);
    store.create({token: 'three', userId: 3, handler: {}});
    assert.equal(store.get('three').userId, 3);
});

test('application boundaries wire security helpers and remove trusted-DOM report HTML', () => {
    const passport = fs.readFileSync(path.join(repositoryRoot, 'server/lib/passport.js'), 'utf8');
    const appBuilder = fs.readFileSync(path.join(repositoryRoot, 'server/app-builder.js'), 'utf8');
    const archive = fs.readFileSync(path.join(repositoryRoot, 'server/routes/archive.js'), 'utf8');
    const campaigns = fs.readFileSync(path.join(repositoryRoot, 'server/routes/campaigns.js'), 'utf8');
    const account = fs.readFileSync(path.join(repositoryRoot, 'server/routes/rest/account.js'), 'utf8');
    const subscription = fs.readFileSync(path.join(repositoryRoot, 'server/routes/subscription.js'), 'utf8');
    const webhooks = fs.readFileSync(path.join(repositoryRoot, 'server/routes/webhooks.js'), 'utf8');
    const reportView = fs.readFileSync(path.join(repositoryRoot, 'client/src/reports/ViewAndOutput.js'), 'utf8');
    const users = fs.readFileSync(path.join(repositoryRoot, 'server/models/users.js'), 'utf8');
    const resetView = fs.readFileSync(path.join(repositoryRoot, 'client/src/login/Reset.js'), 'utf8');
    const loginRoot = fs.readFileSync(path.join(repositoryRoot, 'client/src/login/root.js'), 'utf8');
    const dockerEntrypoint = fs.readFileSync(path.join(repositoryRoot, 'docker-entrypoint.sh'), 'utf8');
    const dockerCompose = fs.readFileSync(path.join(repositoryRoot, 'docker-compose.yml'), 'utf8');
    const defaults = fs.readFileSync(path.join(repositoryRoot, 'server/config/default.yaml'), 'utf8');

    assert.match(passport, /extractAccessToken/);
    assert.doesNotMatch(passport, /req\.query\.access_token/);
    assert.match(passport, /regenerate/);
    assert.match(passport, /session\.destroy/);
    assert.match(passport, /csrf\(\{[\s\S]+secure: config\.security\.sessions\.secure[\s\S]+httpOnly: true[\s\S]+sameSite: 'lax'/);
    assert.match(passport, /logoutCas[\s\S]+session\.destroy/);
    assert.match(appBuilder, /AppType\.TRUSTED && config\.cas/);
    assert.match(appBuilder, /passport\.regenerateAuthenticatedSession/);
    assert.match(appBuilder, /redactLogMessage/);
    assert.match(appBuilder, /SecurityHeaders/);
    assert.match(appBuilder, /buildSessionOptions/);
    assert.match(archive, /sanitizeUntrustedHtml/);
    assert.match(campaigns, /sanitizeUntrustedHtml/);
    assert.match(account, /accountRateLimiters/);
    assert.match(account, /\.\.\.accountRateLimiters\.login/);
    assert.match(account, /\.\.\.accountRateLimiters\.passwordReset/);
    assert.match(account, /restrictedAccessToken, passport\.csrfProtection/);
    assert.match(defaults, /loginAccount:[\s\S]+passwordResetAccount:/);
    assert.match(defaults, /restrictedAccessTokens:[\s\S]+maxEntries:[\s\S]+maxPerUser:/);
    assert.match(subscription, /subscriptionRateLimiters/);
    assert.match(webhooks, /webhookRateLimiters/);
    assert.doesNotMatch(reportView, /dangerouslySetInnerHTML/);
    assert.match(reportView, /<iframe[^>]+sandbox/);
    assert.doesNotMatch(users, /login\/reset\/\$\{encodeURIComponent\(user\.username\)\}\/\$\{encodeURIComponent\(resetToken\)\}/);
    assert.match(users, /login\/reset\/[\s\S]+#\$\{encodeURIComponent\(resetToken\)\}/);
    assert.match(resetView, /window\.location\.hash/);
    assert.match(resetView, /window\.history\.replaceState/);
    assert.doesNotMatch(loginRoot, /:resetToken/);
    assert.doesNotMatch(dockerEntrypoint, /WWW_SECRET=.*pwgen/);
    assert.match(dockerEntrypoint, /validate-session-secret/);
    assert.match(dockerCompose, /WWW_SECRET=\$\{WWW_SECRET:\?/);
    assert.match(dockerCompose, /URL_BASE_TRUSTED=\$\{URL_BASE_TRUSTED:\?/);
    assert.match(defaults, /legacyQueryTokens:[\s\S]+enabled: false/);
});

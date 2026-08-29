'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {AppType} = require('../../../shared/app');
const {extractAccessToken} = require('../../lib/auth-security');
const {securityHeaders, validateOriginSeparation} = require('../../lib/browser-security');
const {sanitizeUntrustedHtml} = require('../../lib/html-sanitizer');
const {redactLogMessage} = require('../../lib/log-redaction');
const {MemoryRateLimitStore, RedisRateLimitStore} = require('../../lib/rate-limit');
const {buildSessionOptions, validateSessionSecurity} = require('../../lib/session-security');

const repositoryRoot = path.resolve(__dirname, '../../..');

function tokenRequest({authorization, accessToken, queryToken} = {}) {
    return {
        get(name) {
            if (name.toLowerCase() === 'authorization') return authorization;
            if (name.toLowerCase() === 'access-token') return accessToken;
        },
        query: queryToken === undefined ? {} : {access_token: queryToken}
    };
}

test('API tokens prefer standard Bearer and legacy header while query tokens fail closed', () => {
    assert.equal(extractAccessToken(tokenRequest({authorization: 'Bearer bearer-secret'}), {}), 'bearer-secret');
    assert.equal(extractAccessToken(tokenRequest({accessToken: 'legacy-header-secret'}), {}), 'legacy-header-secret');
    assert.equal(extractAccessToken(tokenRequest({queryToken: 'query-secret'}), {}), undefined);
    assert.throws(() => extractAccessToken(tokenRequest({authorization: 'Basic abc'}), {}), /authorization/i);
    assert.throws(() => extractAccessToken(tokenRequest({authorization: 'Bearer one', accessToken: 'two'}), {}), /conflicting/i);
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

    assert.throws(() => validateSessionSecurity({secret: 'a cat', secure: false}, {production: true}), /secret/i);
    assert.throws(() => validateSessionSecurity({secret: '0123456789abcdef0123456789abcdef', secure: false}, {production: true}), /secure/i);
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
    assert.match(securityHeaders(AppType.SANDBOXED, {secure: true})['content-security-policy'], /sandbox/);
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
});

test('log redaction removes URL, header, email, form, and reset-token canaries', () => {
    const message = 'POST /api/list?access_token=query-canary&email=user@example.test authorization: Bearer bearer-canary ' +
        'access-token: header-canary /login/reset/admin/reset-path-canary password=pass-canary api_token=dkim-canary';
    const redacted = redactLogMessage(message);
    for (const canary of ['query-canary', 'user@example.test', 'bearer-canary', 'header-canary', 'reset-path-canary', 'pass-canary', 'dkim-canary']) {
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

test('application boundaries wire security helpers and remove trusted-DOM report HTML', () => {
    const passport = fs.readFileSync(path.join(repositoryRoot, 'server/lib/passport.js'), 'utf8');
    const appBuilder = fs.readFileSync(path.join(repositoryRoot, 'server/app-builder.js'), 'utf8');
    const archive = fs.readFileSync(path.join(repositoryRoot, 'server/routes/archive.js'), 'utf8');
    const campaigns = fs.readFileSync(path.join(repositoryRoot, 'server/routes/campaigns.js'), 'utf8');
    const account = fs.readFileSync(path.join(repositoryRoot, 'server/routes/rest/account.js'), 'utf8');
    const subscription = fs.readFileSync(path.join(repositoryRoot, 'server/routes/subscription.js'), 'utf8');
    const webhooks = fs.readFileSync(path.join(repositoryRoot, 'server/routes/webhooks.js'), 'utf8');
    const reportView = fs.readFileSync(path.join(repositoryRoot, 'client/src/reports/ViewAndOutput.js'), 'utf8');
    const defaults = fs.readFileSync(path.join(repositoryRoot, 'server/config/default.yaml'), 'utf8');

    assert.match(passport, /extractAccessToken/);
    assert.doesNotMatch(passport, /req\.query\.access_token/);
    assert.match(passport, /regenerate/);
    assert.match(passport, /session\.destroy/);
    assert.match(appBuilder, /redactLogMessage/);
    assert.match(appBuilder, /securityHeaders/);
    assert.match(appBuilder, /buildSessionOptions/);
    assert.match(archive, /sanitizeUntrustedHtml/);
    assert.match(campaigns, /sanitizeUntrustedHtml/);
    assert.match(account, /accountRateLimiters/);
    assert.match(subscription, /subscriptionRateLimiters/);
    assert.match(webhooks, /webhookRateLimiters/);
    assert.doesNotMatch(reportView, /dangerouslySetInnerHTML/);
    assert.match(reportView, /<iframe[^>]+sandbox/);
    assert.match(defaults, /legacyQueryTokens:[\s\S]+enabled: false/);
});

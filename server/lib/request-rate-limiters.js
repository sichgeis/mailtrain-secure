'use strict';

const crypto = require('crypto');
const config = require('./config');
const {createRateLimitMiddleware, getRateLimitStore} = require('./rate-limit');

function digest(value) {
    return crypto.createHmac('sha256', config.www.secret).update(String(value || '').trim().toLowerCase()).digest('hex').slice(0, 24);
}

function clientIp(req) {
    return digest(req.ip || (req.socket && req.socket.remoteAddress) || 'unknown');
}

function limiter(policyName, keyFactory) {
    const policy = config.security.rateLimits[policyName];
    return createRateLimitMiddleware({
        store: {consume: (...args) => getRateLimitStore().consume(...args)},
        policy,
        key: req => `${policyName}:${keyFactory(req)}`
    });
}

const accountRateLimiters = {
    login: [
        limiter('login', req => clientIp(req)),
        limiter('loginAccount', req => digest(req.body && req.body.username))
    ],
    passwordReset: [
        limiter('passwordReset', req => clientIp(req)),
        limiter('passwordResetAccount', req => digest(req.body && (req.body.usernameOrEmail || req.body.username)))
    ],
    restrictedAccessToken: limiter('restrictedAccessToken', req => `${clientIp(req)}:${digest(req.user && req.user.id)}`)
};

const subscriptionRateLimiters = {
    subscribe: limiter('subscription', req => `${clientIp(req)}:${digest(req.params.cid || req.params.lcid)}`),
    mutation: limiter('subscriptionMutation', req => `${clientIp(req)}:${digest(req.params.cid || req.params.lcid)}`)
};

const webhookRateLimiters = {};
for (const provider of ['aws', 'sparkpost', 'sendgrid', 'mailgun', 'zoneMta', 'postal']) {
    webhookRateLimiters[provider] = limiter('webhook', req => `${provider}:${clientIp(req)}`);
}

module.exports = {
    accountRateLimiters,
    digest,
    subscriptionRateLimiters,
    webhookRateLimiters
};

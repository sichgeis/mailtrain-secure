'use strict';

const {AppType} = require('../../shared/app');

function configError(message) {
    const error = new Error(message);
    error.code = 'EHTTPSECURITYCONFIG';
    return error;
}

function normalizedOrigin(value, label) {
    let url;
    try {
        url = new URL(value);
    } catch (err) {
        throw configError(`${label} must be an absolute URL`);
    }
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
        throw configError(`${label} must contain only an HTTP(S) origin`);
    }
    return url.origin;
}

function validateOriginSeparation(www, {production = false} = {}) {
    const origins = [
        normalizedOrigin(www.trustedUrlBase, 'Trusted URL'),
        normalizedOrigin(www.sandboxUrlBase, 'Sandbox URL'),
        normalizedOrigin(www.publicUrlBase, 'Public URL')
    ];
    if (new Set(origins).size !== origins.length) {
        throw configError('Trusted, sandbox, and public origins must be distinct');
    }
    if (production && origins.some(origin => !origin.startsWith('https://'))) {
        throw configError('Production browser origins must use HTTPS');
    }
    return origins;
}

function validateProxyTrust(value, {production = false} = {}) {
    if (production && value === true) {
        throw configError('Production proxy trust cannot trust every proxy');
    }
    if (![false, undefined].includes(value) && typeof value !== 'string' && !Number.isInteger(value)) {
        throw configError('Proxy trust must be false, a hop count, or an explicit address/range expression');
    }
}

function securityHeaders(appType, {
    secure = false,
    trustedOrigin = '\'self\'',
    sandboxOrigin = '\'self\''
} = {}) {
    const headers = {
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    };
    if (secure) {
        headers['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
    }
    if (appType === AppType.SANDBOXED) {
        headers['content-security-policy'] = `sandbox allow-forms allow-modals allow-popups allow-same-origin allow-scripts; default-src 'self' data: blob:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' https: data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors ${trustedOrigin}`;
    } else if (appType === AppType.PUBLIC) {
        headers['content-security-policy'] = 'default-src \'none\'; img-src https: data:; style-src \'unsafe-inline\' https:; font-src https: data:; script-src \'self\' \'unsafe-inline\' https:; connect-src \'self\'; form-action \'self\'; base-uri \'none\'; frame-ancestors \'none\'';
        headers['x-frame-options'] = 'DENY';
    } else {
        headers['content-security-policy'] = `default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-src 'self' ${sandboxOrigin}; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`;
        headers['x-frame-options'] = 'DENY';
    }
    return headers;
}

function untrustedContentSecurityPolicy({frameAncestor = '\'none\''} = {}) {
    const ancestor = frameAncestor === '\'none\'' ? frameAncestor : normalizedOrigin(frameAncestor, 'Frame ancestor');
    return `default-src 'none'; img-src https: data:; style-src 'unsafe-inline' https:; font-src https: data:; script-src 'none'; connect-src 'none'; media-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors ${ancestor}`;
}

function createSecurityHeadersMiddleware(appType, options) {
    const headers = securityHeaders(appType, options);
    return (req, res, next) => {
        for (const [name, value] of Object.entries(headers)) {
            res.setHeader(name, value);
        }
        next();
    };
}

function createOriginCheckMiddleware(expectedOrigin) {
    const normalized = normalizedOrigin(expectedOrigin, 'Expected origin');
    return (req, res, next) => {
        const origin = req.get('origin');
        if (origin && !['GET', 'HEAD', 'OPTIONS'].includes(req.method) && origin !== normalized) {
            const error = new Error('Request origin is not allowed');
            error.status = 403;
            return next(error);
        }
        next();
    };
}

function createHostCheckMiddleware(expectedOrigin) {
    const expectedHost = new URL(normalizedOrigin(expectedOrigin, 'Expected origin')).host.toLowerCase();
    return (req, res, next) => {
        if (String(req.get('host') || '').toLowerCase() !== expectedHost) {
            const error = new Error('Request host is not allowed');
            error.status = 421;
            return next(error);
        }
        next();
    };
}

module.exports = {
    createHostCheckMiddleware,
    createOriginCheckMiddleware,
    createSecurityHeadersMiddleware,
    securityHeaders,
    untrustedContentSecurityPolicy,
    validateOriginSeparation,
    validateProxyTrust
};

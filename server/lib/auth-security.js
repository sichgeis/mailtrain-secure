'use strict';

function authError(message) {
    const error = new Error(message);
    error.status = 403;
    return error;
}

function extractAccessToken(req, {
    legacyQueryTokensEnabled = false,
    warn = () => {}
} = {}) {
    const authorization = String(req.get('authorization') || '').trim();
    let bearer;
    if (authorization) {
        const match = authorization.match(/^Bearer ([^\s,]+)$/i);
        if (!match) {
            throw authError('Authorization header must use a single Bearer token');
        }
        bearer = match[1];
    }

    const legacyHeader = String(req.get('access-token') || '').trim() || undefined;
    let queryToken;
    if (req.query && req.query.access_token !== undefined) {
        if (!legacyQueryTokensEnabled) {
            throw authError('Query-string access tokens are disabled; use Authorization: Bearer');
        }
        queryToken = String(req.query.access_token).trim() || undefined;
        warn('Deprecated query-token authentication was used; migrate to Authorization: Bearer.');
    }

    const supplied = [bearer, legacyHeader, queryToken].filter(Boolean);
    if (supplied.length > 1) {
        throw authError('Conflicting access token credentials were supplied');
    }
    return supplied[0];
}

module.exports = {
    extractAccessToken
};

'use strict';

const {validateSessionSecurity} = require('../lib/session-security');

const secret = process.env.WWW_SECRET || '';
if (!/^[A-Za-z0-9_-]{43,}$/.test(secret)) {
    throw new Error('WWW_SECRET must contain at least 32 random bytes encoded as base64url (43 or more characters)');
}

validateSessionSecurity({
    secret,
    secure: process.env.SESSION_COOKIE_SECURE === 'true',
    name: '__Host-mailtrain.sid'
}, {production: true});

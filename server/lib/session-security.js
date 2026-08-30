'use strict';

function sessionError(message) {
    const error = new Error(message);
    error.code = 'ESESSIONCONFIG';
    return error;
}

function validateSessionSecurity(settings, {production = false} = {}) {
    if (!production) {
        return;
    }
    if (typeof settings.secret !== 'string' || settings.secret.length < 32 || new Set(settings.secret).size < 12 || settings.secret === 'a cat') {
        throw sessionError('Production session secret must contain at least 32 high-entropy characters');
    }
    if (settings.secure !== true) {
        throw sessionError('Production session cookies must be Secure');
    }
    if (typeof settings.name !== 'string' || !settings.name.startsWith('__Host-')) {
        throw sessionError('Production session cookie name must use the __Host- prefix');
    }
}

function buildSessionOptions({
    secret,
    secure,
    maxAgeMs,
    name = 'mailtrain.sid',
    store
}) {
    if (typeof secret !== 'string' || !Number.isInteger(maxAgeMs) || maxAgeMs <= 0) {
        throw sessionError('Session configuration is invalid');
    }
    const options = {
        name,
        secret,
        saveUninitialized: false,
        resave: false,
        rolling: true,
        cookie: {
            secure: secure === true,
            httpOnly: true,
            sameSite: 'lax',
            maxAge: maxAgeMs,
            path: '/'
        }
    };
    if (store) {
        options.store = store;
    }
    return options;
}

module.exports = {
    buildSessionOptions,
    validateSessionSecurity
};

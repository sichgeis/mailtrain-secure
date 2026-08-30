'use strict';

function externalAuthError(adapterName, packageName, cause) {
    const error = new Error(`${adapterName} authentication is enabled, but ${packageName} could not be loaded`);
    error.code = 'EEXTERNALAUTH';
    error.cause = cause;
    return error;
}

function loadExternalAuthAdapter({adapterName, packageName, requireModule = require}) {
    let adapter;
    try {
        adapter = requireModule(packageName);
    } catch (error) {
        throw externalAuthError(adapterName, packageName, error);
    }

    if (!adapter || typeof adapter.Strategy !== 'function') {
        throw externalAuthError(adapterName, packageName, new Error('Strategy export is missing'));
    }
    return adapter.Strategy;
}

module.exports = {loadExternalAuthAdapter};

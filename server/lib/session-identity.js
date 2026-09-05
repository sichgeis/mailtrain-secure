'use strict';

function createIdentity(user, remember, now = Date.now()) {
    return {id: user.id, version: user.auth_version, issuedAt: now, remember: remember === true};
}

function validIdentity(identity, user, now = Date.now()) {
    if (!identity || !user || !Number.isSafeInteger(identity.version) || !Number.isSafeInteger(identity.issuedAt)) return false;
    const lifetime = identity.remember === true ? 30 * 86400000 : 12 * 3600000;
    return identity.id === user.id && identity.version === user.auth_version &&
        identity.issuedAt <= now && now - identity.issuedAt < lifetime;
}

module.exports = {createIdentity, validIdentity};

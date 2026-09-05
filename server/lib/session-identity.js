'use strict';

function createIdentity(user, remember, now = Date.now()) {
    return {id: user.id, version: user.auth_version, issuedAt: now, remember: remember === true};
}

function validIdentity(identity, user, now = Date.now()) {
    if (!identity || !user || !Number.isSafeInteger(identity.version) || !Number.isSafeInteger(identity.issuedAt)) {return false;}
    const lifetime = identity.remember === true ? 30 * 86400000 : 12 * 3600000;
    return identity.id === user.id && identity.version === user.auth_version &&
        identity.issuedAt <= now && now - identity.issuedAt < lifetime;
}

function sessionUser(identity, current) {
    // Directory display attributes are not authorization facts. Preserve the
    // authenticated profile while always using the current database role/namespace.
    const profile = identity.profile || {};
    return {...current,
        name: typeof profile.name === 'string' ? profile.name : current.name,
        email: typeof profile.email === 'string' ? profile.email : current.email};
}

module.exports = {createIdentity, validIdentity, sessionUser};

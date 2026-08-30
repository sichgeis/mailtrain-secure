'use strict';

function firstValue(value) {
    return Array.isArray(value) ? value[0] : value;
}

function normalizeCasProfile(casProfile, {nameTag, mailTag}) {
    const attributes = casProfile && casProfile.attributes ? casProfile.attributes : {};
    const username = casProfile && casProfile.user;

    if (!username) {
        const error = new Error('CAS response did not contain a username.');
        error.code = 'EEXTERNALAUTH';
        throw error;
    }

    return {
        username,
        displayName: firstValue(attributes[nameTag]) || username,
        email: firstValue(attributes[mailTag])
    };
}

function getCasLogoutUrl(casBaseUrl, returnUrl) {
    const logoutUrl = new URL('logout', `${casBaseUrl.replace(/\/+$/, '')}/`);
    if (returnUrl) {
        logoutUrl.searchParams.set('service', returnUrl);
    }
    return logoutUrl.toString();
}

module.exports = {
    getCasLogoutUrl,
    normalizeCasProfile
};

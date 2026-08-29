'use strict';

const passwordValidator = require('../../shared/password-validator')();

function validateAdminPassword(password) {
    if (typeof password !== 'string' || password.length === 0) {
        throw new Error('ADMIN_PASSWORD must be supplied externally');
    }

    const result = passwordValidator.test(password);
    if (result.errors.length > 0) {
        throw new Error('ADMIN_PASSWORD does not meet the Mailtrain password-strength policy');
    }
}

async function applyAdminBootstrap({existingAdmin, password, accessToken, hashPassword, updateAdmin}) {
    validateAdminPassword(password);

    if (existingAdmin) {
        return false;
    }

    const fields = {
        password: await hashPassword(password)
    };
    if (accessToken) {
        fields.access_token = accessToken;
    }

    await updateAdmin(fields);
    return true;
}

module.exports = {
    applyAdminBootstrap,
    validateAdminPassword
};

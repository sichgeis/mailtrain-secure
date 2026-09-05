'use strict';

const knex = require('./knex');

function getRequestContext(req) {
    const context = {
        user: req.user,
        sessionId: req.sessionID,
        sessionIdentity: req.session && req.session.passport && req.session.passport.user
    };

    return context;
}

const adminContext = {
    user: {
        admin: true,
        id: 0,
        username: '',
        name: '',
        email: ''
    }
};

function getAdminContext() {
    return adminContext;
}

module.exports = {
    getRequestContext,
    getAdminContext
};

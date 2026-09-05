'use strict';

const config = require('./config');
const log = require('./log');
const util = require('util');

const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const csrf = require('csurf');
const bodyParser = require('body-parser');

const users = require('../models/users');
const { nodeifyFunction, nodeifyPromise } = require('./nodeify');
const interoperableErrors = require('../../shared/interoperable-errors');
const contextHelpers = require('./context-helpers');
const {extractAccessToken} = require('./auth-security');
const {loadExternalAuthAdapter} = require('./external-auth-adapter');
const {getCasLogoutUrl, normalizeCasProfile} = require('./cas-auth');
const {createIdentity, validIdentity, sessionUser} = require('./session-identity');

let authMode = 'local';

let LdapStrategy;
let ldapStrategyOpts;
if (config.ldap.enabled) {
    const ldapProtocol = config.ldap.secure ? 'ldaps' : 'ldap';
    if (!config.ldap.method || config.ldap.method === 'ldapjs') {
        LdapStrategy = loadExternalAuthAdapter({
            adapterName: 'LDAP',
            packageName: 'passport-ldapjs'
        });
        authMode = 'ldap';
        log.info('LDAP', 'Using the bundled "passport-ldapjs" authentication adapter.');

        ldapStrategyOpts = {
            server: {
                url: ldapProtocol + '://' + config.ldap.host + ':' + config.ldap.port
            },
            base: config.ldap.baseDN,
            search: {
                filter: config.ldap.filter,
                attributes: [config.ldap.uidTag, config.ldap.nameTag, config.ldap.mailTag],
                scope: 'sub'
            },
            uidTag: config.ldap.uidTag,
            bindUser: config.ldap.bindUser,
            bindPassword: config.ldap.bindPassword
        };
    }

    if (!LdapStrategy && (!config.ldap.method || config.ldap.method === 'ldapauth')) {
        LdapStrategy = loadExternalAuthAdapter({
            adapterName: 'LDAP',
            packageName: 'passport-ldapauth'
        });
        authMode = 'ldapauth';
        log.info('LDAP', 'Using the bundled "passport-ldapauth" authentication adapter.');

        ldapStrategyOpts = {
            server: {
                url: ldapProtocol + '://' + config.ldap.host + ':' + config.ldap.port,
                searchBase: config.ldap.baseDN,
                searchFilter: config.ldap.filter,
                searchAttributes: [config.ldap.uidTag, config.ldap.nameTag, config.ldap.mailTag],
                bindDN: config.ldap.bindUser,
                bindCredentials: config.ldap.bindPassword
            },
        };
    }

    if (!LdapStrategy) {
        const error = new Error(`Unsupported LDAP authentication method: ${config.ldap.method}`);
        error.code = 'EEXTERNALAUTH';
        throw error;
    }
}

module.exports.csrfProtection = csrf({
    cookie: {
        key: config.security.sessions.secure ? '__Host-mailtrain.csrf' : '_csrf',
        secure: config.security.sessions.secure,
        httpOnly: true,
        sameSite: 'lax',
        path: '/'
    }
});

module.exports.parseForm = bodyParser.urlencoded({
    extended: false,
    limit: config.www.postSize
});

module.exports.loggedIn = (req, res, next) => {
    if (!req.user) {
        next(new interoperableErrors.NotLoggedInError());
    } else {
        next();
    }
};

module.exports.authByAccessToken = (req, res, next) => {
    let accessToken;
    try {
        accessToken = extractAccessToken(req, {
            legacyQueryTokensEnabled: config.security.legacyQueryTokens.enabled,
            warn: message => log.warn('Security', message)
        });
    } catch (err) {
        return res.status(err.status || 403).json({error: err.message, data: []});
    }

    if (!accessToken) {
        res.status(403);
        res.json({
            error: 'Missing access_token',
            data: []
        });
        return;
    }

    users.getByAccessToken(accessToken).then(user => {
        req.user = user;
        next();
    }).catch(err => {
        if (err instanceof interoperableErrors.PermissionDeniedError) {
            res.status(403);
            res.json({
                error: 'Invalid or expired access_token',
                data: []
            });
        } else {
            res.status(500);
            res.json({
                error: err.message || err,
                data: []
            });
        }
    });
};

module.exports.tryAuthByRestrictedAccessToken = (req, res, next) => {
    const pathComps = req.url.split('/');

    pathComps.shift();
    const restrictedAccessToken = pathComps.shift();
    pathComps.unshift('');

    const url = pathComps.join('/');

    req.url = url;

    users.getByRestrictedAccessToken(restrictedAccessToken, req.sessionStore).then(user => {
        req.user = user;
        next();
    }).catch(err => {
        next();
    });
};


module.exports.setupRegularAuth = app => {
    app.use(passport.initialize());
    app.use(passport.session());
};

function clearSessionCookies(res) {
    const options = {
        httpOnly: true,
        sameSite: 'lax',
        secure: config.security.sessions.secure,
        path: '/'
    };
    res.clearCookie(config.security.sessions.name, options);
    if (config.security.sessions.name !== 'mailtrain.sid') {
        res.clearCookie('mailtrain.sid', options);
    }
}

module.exports.restLogout = (req, res, next) => {
    req.logout(err => {
        if (err) {
            return next(err);
        }
        req.session.destroy(err => {
            if (err) {
                return next(err);
            }
            clearSessionCookies(res);
            res.json();
        });
    });
};

module.exports.restLogin = (req, res, next) => {
    passport.authenticate(authMode, (err, user, info) => {
        if (err) {
            return next(err);
        }

        if (!user) {
            return next(new interoperableErrors.IncorrectPasswordError());
        }

        req.session.regenerate(err => {
            if (err) {
                return next(err);
            }
            req.logIn(user, err => {
                if (err) {
                    return next(err);
                }
                req.session.cookie.maxAge = req.body.remember ?
                    config.security.sessions.rememberMaxAgeMs : config.security.sessions.maxAgeMs;
                if (config.security.sessions.name !== 'mailtrain.sid') {
                    res.clearCookie('mailtrain.sid', {path: '/', secure: config.security.sessions.secure});
                }
                return res.json();
            });
        });
    })(req, res, next);
};

module.exports.regenerateAuthenticatedSession = (req, res, next) => {
    const user = req.user;
    req.session.regenerate(err => {
        if (err) {
            return next(err);
        }
        req.logIn(user, err => {
            if (!err && config.security.sessions.name !== 'mailtrain.sid') {
                res.clearCookie('mailtrain.sid', {path: '/', secure: config.security.sessions.secure});
            }
            next(err);
        });
    });
};
let CasStrategy;
if (config.cas && config.cas.enabled === true) {
    CasStrategy = loadExternalAuthAdapter({
        adapterName: 'CAS',
        packageName: '@coursetable/passport-cas'
    });
    authMode = 'cas';
    log.info('CAS', 'Using the bundled CAS authentication adapter.');
}
if (CasStrategy) {
    log.info('Using CAS auth');
    module.exports.authMethod = 'cas';
    module.exports.isAuthMethodLocal = false;

    const cas = new CasStrategy({
        version: 'CAS2.0',
        ssoBaseURL: config.cas.url.replace(/\/+$/, '')
    }, 
    nodeifyFunction(async casProfile => {
      const profile = normalizeCasProfile(casProfile, config.cas);
      const username = profile.username;
      try {
        const user = await users.getByUsername(username);

        log.info('CAS', 'Existing user authenticated through CAS');
        return {
            id: user.id,
            username: username,
            name: profile.displayName,
            email: profile.email,
            role: user.role
        };
      } catch (err) {
        if (err instanceof interoperableErrors.NotFoundError) {
            const userId = await users.create(contextHelpers.getAdminContext(), {
                username: username,
                role: config.cas.newUserRole,
                namespace: config.cas.newUserNamespaceId,
                name: profile.displayName,
                email: profile.email
            });
            log.info('CAS', 'New user provisioned through CAS');

            return {
                id: userId,
                username: username,
                name: profile.displayName,
                email: profile.email,
                role: config.cas.newUserRole
            };
        } else {
            throw err;
        }
      }
    }));
    passport.use(cas);

    module.exports.authenticateCas = passport.authenticate('cas', { failureRedirect: '/login?cas-login-error' });
    module.exports.logoutCas = function (req, res, next) {
        req.logout(err => {
            if (err) {
                return next(err);
            }
            req.session.destroy(err => {
                if (err) {
                    return next(err);
                }
                clearSessionCookies(res);
                res.redirect(307, getCasLogoutUrl(config.cas.url, config.www.trustedUrlBase+'/?cas-logout-success'));
            });
        });
    };

} else if (LdapStrategy) {
    log.info('Using LDAP auth (passport-%s)', authMode === 'ldap' ? 'ldapjs' : authMode);
    module.exports.authMethod = 'ldap';
    module.exports.isAuthMethodLocal = false;

    passport.use(new LdapStrategy(ldapStrategyOpts, nodeifyFunction(async (profile) => {
        try {
            const user = await users.getByUsername(profile[config.ldap.uidTag]);

            return {
                id: user.id,
                username: profile[config.ldap.uidTag],
                name: profile[config.ldap.nameTag],
                email: profile[config.ldap.mailTag],
                role: user.role
            };

        } catch (err) {
            if (err instanceof interoperableErrors.NotFoundError) {
                const userId = await users.create(contextHelpers.getAdminContext(), {
                    username: profile[config.ldap.uidTag],
                    role: config.ldap.newUserRole,
                    namespace: config.ldap.newUserNamespaceId,
                    name: profile[config.ldap.nameTag],
                    email: profile[config.ldap.mailTag]
                });

                return {
                    id: userId,
                    username: profile[config.ldap.uidTag],
                    name: profile[config.ldap.nameTag],
                    email: profile[config.ldap.mailTag],
                    role: config.ldap.newUserRole
                };
            } else {
                throw err;
            }
        }
    })));


} else {
    log.info('Using local auth');
    module.exports.authMethod = 'local';
    module.exports.isAuthMethodLocal = true;

    passport.use(new LocalStrategy(nodeifyFunction(async (username, password) => {
        return await users.getByUsernameIfPasswordMatch(contextHelpers.getAdminContext(), username, password);
    })));

}

// Every adapter stores a versioned identity, never a stale authorization snapshot.
passport.serializeUser((req, user, done) => {
    nodeifyPromise(users.getById(contextHelpers.getAdminContext(), user.id).then(current => {
        if (user.auth_version !== undefined && user.auth_version !== current.auth_version) {
            throw new interoperableErrors.PermissionDeniedError();
        }
        const identity = createIdentity(current, !!(req.body && req.body.remember));
        if (!module.exports.isAuthMethodLocal) identity.profile = {name: user.name, email: user.email};
        return identity;
    }), done);
});

passport.deserializeUser((identity, done) => {
    if (!identity || !Number.isSafeInteger(identity.id)) return done(null, false);
    users.getById(contextHelpers.getAdminContext(), identity.id).then(user => {
        done(null, validIdentity(identity, user) ? sessionUser(identity, user) : false);
    }).catch(err => {
        if (err instanceof interoperableErrors.PermissionDeniedError) return done(null, false);
        done(err);
    });
});

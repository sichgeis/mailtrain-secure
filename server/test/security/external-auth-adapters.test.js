'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const {loadExternalAuthAdapter} = require('../../lib/external-auth-adapter');
const {getCasLogoutUrl, normalizeCasProfile} = require('../../lib/cas-auth');
const packageJson = require('../../package.json');

const repositoryRoot = path.resolve(__dirname, '..', '..', '..');

test('configured external authentication adapters load or fail closed', () => {
    const Strategy = function Strategy() {};

    assert.equal(loadExternalAuthAdapter({
        adapterName: 'Synthetic LDAP',
        packageName: 'passport-synthetic',
        requireModule: () => ({Strategy})
    }), Strategy);

    assert.throws(() => loadExternalAuthAdapter({
        adapterName: 'Synthetic LDAP',
        packageName: 'passport-synthetic',
        requireModule: () => {
            const error = new Error('missing');
            error.code = 'MODULE_NOT_FOUND';
            throw error;
        }
    }), error => error.code === 'EEXTERNALAUTH' && /passport-synthetic/.test(error.message));
});

test('the immutable server installation contains every supported CAS and LDAP adapter', () => {
    for (const packageName of ['@coursetable/passport-cas', 'passport-ldapauth', 'passport-ldapjs']) {
        assert.equal(typeof packageJson.dependencies[packageName], 'string', `${packageName} must be installed at image build time`);
        assert.equal(typeof loadExternalAuthAdapter({
            adapterName: packageName,
            packageName
        }), 'function', `${packageName} must export a Passport strategy`);
    }
});

test('CAS profiles and logout URLs retain Mailtrain compatibility', () => {
    assert.deepEqual(normalizeCasProfile({
        user: 'alice',
        attributes: {
            display_name: ['Alice Example'],
            mail: ['alice@example.test']
        }
    }, {nameTag: 'display_name', mailTag: 'mail'}), {
        username: 'alice',
        displayName: 'Alice Example',
        email: 'alice@example.test'
    });

    assert.equal(
        getCasLogoutUrl('https://cas.example.test/cas/', 'https://mail.example.test/?cas-logout-success'),
        'https://cas.example.test/cas/logout?service=https%3A%2F%2Fmail.example.test%2F%3Fcas-logout-success'
    );
    assert.throws(
        () => normalizeCasProfile({attributes: {}}, {nameTag: 'name', mailTag: 'mail'}),
        error => error.code === 'EEXTERNALAUTH'
    );

    assert.equal(normalizeCasProfile({
        user: 'alice',
        attributes: {displayname: 'Alice Example'}
    }, {nameTag: 'displayName', mailTag: 'mail'}).displayName, 'Alice Example');
});

test('built-in ZoneMTA config supplies the trusted Host header for its loopback callback', () => {
    const source = fs.readFileSync(path.join(repositoryRoot, 'server', 'lib', 'builtin-zone-mta.js'), 'utf8');

    assert.match(source, /bounceHost:\s*new URL\(config\.www\.trustedUrlBase\)\.host/);
});

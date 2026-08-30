'use strict';

const assert = require('node:assert/strict');
const path = require('node:path');
const test = require('node:test');

const repositoryRoot = path.resolve(__dirname, '..', '..', '..');

test('configured external authentication adapters load or fail closed', () => {
    const {loadExternalAuthAdapter} = require('../../lib/external-auth-adapter');
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
    const packageJson = require(path.join(repositoryRoot, 'server', 'package.json'));

    for (const packageName of ['passport-cas2', 'passport-ldapauth', 'passport-ldapjs']) {
        assert.equal(typeof packageJson.dependencies[packageName], 'string', `${packageName} must be installed at image build time`);
    }
});

test('built-in ZoneMTA config supplies the trusted Host header for its loopback callback', () => {
    const fs = require('node:fs');
    const source = fs.readFileSync(path.join(repositoryRoot, 'server', 'lib', 'builtin-zone-mta.js'), 'utf8');

    assert.match(source, /bounceHost:\s*new URL\(config\.www\.trustedUrlBase\)\.host/);
});

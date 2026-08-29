'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const yaml = require('js-yaml');

const repositoryRoot = path.resolve(__dirname, '../../..');
const deploymentRoot = path.join(repositoryRoot, 'deploy/netcup');

function read(relativePath) {
    return fs.readFileSync(path.join(deploymentRoot, relativePath), 'utf8');
}

test('Netcup Compose exposes only Traefik and isolates every datastore', () => {
    const compose = yaml.safeLoad(read('compose.yml'));
    assert.deepEqual(Object.keys(compose.services).sort(), ['mailtrain', 'mariadb', 'migrate', 'mongo', 'redis', 'traefik']);
    assert.deepEqual(compose.services.traefik.ports, ['80:80', '443:443']);
    for (const [name, service] of Object.entries(compose.services)) {
        if (name !== 'traefik') {
            assert.equal(service.ports, undefined, `${name} must not publish host ports`);
        }
    }
    assert.equal(compose.networks.backend.internal, true);
    assert.equal(compose.services.mariadb.networks.includes('backend'), true);
    assert.equal(compose.services.redis.networks.includes('backend'), true);
    assert.equal(compose.services.mongo.networks.includes('backend'), true);
});

test('trusted, sandbox, and public HTTPS origins have distinct Traefik routers', () => {
    const composeSource = read('compose.yml');
    for (const origin of ['MAILTRAIN_TRUSTED_HOST', 'MAILTRAIN_SANDBOX_HOST', 'MAILTRAIN_PUBLIC_HOST']) {
        assert.match(composeSource, new RegExp(`Host\\(.*\\$\\{${origin}`));
    }
    assert.match(composeSource, /trusted[^\n]*loadbalancer\.server\.port=3000/);
    assert.match(composeSource, /sandbox[^\n]*loadbalancer\.server\.port=3003/);
    assert.match(composeSource, /public[^\n]*loadbalancer\.server\.port=3004/);
    assert.doesNotMatch(read('.env.example'), /example\.(com|org)|CHANGE_ME|password/i);
});

test('containers are least-privilege, bounded, health-checked, and digest-pinned', () => {
    const compose = yaml.safeLoad(read('compose.yml'));
    for (const name of ['traefik', 'mailtrain', 'mariadb', 'redis', 'mongo']) {
        const service = compose.services[name];
        assert.equal(service.read_only, true, `${name} root filesystem must be read-only`);
        assert.deepEqual(service.cap_drop, ['ALL']);
        assert.equal(service.security_opt.includes('no-new-privileges:true'), true);
        assert.ok(service.pids_limit > 0);
        assert.ok(service.mem_limit);
        assert.ok(service.cpus);
        assert.ok(service.healthcheck);
        assert.match(service.image, /^\$\{[A-Z_]+_IMAGE:\?/);
    }
    assert.match(read('validate-env.sh'), /@sha256:\[0-9a-f\]\{64\}/);
});

test('datastore credentials, TLS, and database duties are separated', () => {
    const composeSource = read('compose.yml');
    const bootstrap = read('mariadb-init.sh');
    const entrypoint = read('mailtrain-entrypoint.sh');
    assert.match(composeSource, /redis_password/);
    assert.match(composeSource, /mongo_password/);
    assert.match(composeSource, /db_ca/);
    assert.match(entrypoint, /ssl:/);
    assert.match(entrypoint, /rejectUnauthorized: true/);
    for (const principal of ['MAILTRAIN_DB_MIGRATION_USER', 'MAILTRAIN_DB_RUNTIME_USER', 'MAILTRAIN_DB_REPORT_USER']) {
        assert.match(bootstrap, new RegExp(principal));
    }
    assert.match(bootstrap, /GRANT SELECT ON/);
    assert.match(bootstrap, /GRANT SELECT, INSERT, UPDATE, DELETE ON/);
    assert.match(bootstrap, /GRANT ALL PRIVILEGES ON/);
});

test('production images install at build time and run Mailtrain as non-root', () => {
    const dockerfile = fs.readFileSync(path.join(repositoryRoot, 'Dockerfile'), 'utf8');
    const legacyEntrypoint = fs.readFileSync(path.join(repositoryRoot, 'docker-entrypoint.sh'), 'utf8');
    const productionEntrypoint = read('mailtrain-entrypoint.sh');
    assert.match(dockerfile, /FROM node:24-alpine/);
    assert.match(dockerfile, /npm ci/);
    assert.match(dockerfile, /USER mailtrain/);
    assert.doesNotMatch(legacyEntrypoint, /npm install/);
    assert.doesNotMatch(productionEntrypoint, /npm install|apk add|apt-get/);
});

test('operator runbook requires backup restore and firewall validation before cutover', () => {
    const runbook = read('README.md');
    for (const requirement of ['backup', 'restore', 'firewall', 'rollback', 'three distinct', 'no production migration']) {
        assert.match(runbook.toLowerCase(), new RegExp(requirement));
    }
});

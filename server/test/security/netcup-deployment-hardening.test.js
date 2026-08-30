'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const childProcess = require('node:child_process');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const yaml = require('js-yaml');
const {assertRuntimeSchemaCurrent} = require('../../lib/runtime-schema');
const {validateSessionSecurity} = require('../../lib/session-security');

const repositoryRoot = path.resolve(__dirname, '../../..');
const deploymentRoot = path.join(repositoryRoot, 'deploy/netcup');

function read(relativePath) {
    return fs.readFileSync(path.join(deploymentRoot, relativePath), 'utf8');
}

test('Netcup Compose exposes only Traefik and isolates every datastore', () => {
    const compose = yaml.safeLoad(read('compose.yml'));
    assert.deepEqual(Object.keys(compose.services).sort(), ['files-init', 'mailtrain', 'mariadb', 'migrate', 'mongo', 'redis', 'secret-migrate', 'traefik']);
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
    assert.deepEqual(compose.services.traefik.networks, ['edge', 'proxy']);
    assert.deepEqual(compose.services.mariadb.networks, ['backend']);
    assert.deepEqual(compose.services.redis.networks, ['backend']);
    assert.deepEqual(compose.services.mongo.networks, ['backend']);
    assert.deepEqual(compose.services.migrate.profiles, ['migration']);
    assert.deepEqual(compose.services.mailtrain.profiles, ['runtime']);
    assert.equal(compose.services.mailtrain.depends_on.migrate, undefined);
    assert.doesNotMatch(read('compose.yml'), /docker\.sock|privileged:|network_mode:\s*host|pid:\s*host|ipc:\s*host/);
});

test('trusted, sandbox, and public HTTPS origins have distinct Traefik routers', () => {
    const routes = read('traefik-dynamic.yml');
    assert.match(routes, /Host\(`__TRUSTED_HOST__`\)/);
    assert.match(routes, /Host\(`__SANDBOX_HOST__`\)/);
    assert.match(routes, /Host\(`__PUBLIC_HOST__`\)/);
    assert.match(routes, /mailtrain-trusted:[\s\S]*?http:\/\/mailtrain:3000/);
    assert.match(routes, /mailtrain-sandbox:[\s\S]*?http:\/\/mailtrain:3003/);
    assert.match(routes, /mailtrain-public:[\s\S]*?http:\/\/mailtrain:3004/);
    assert.doesNotMatch(read('.env.example'), /example\.(com|org)|CHANGE_ME|password/i);
});

test('containers are least-privilege, bounded, health-checked, and digest-pinned', () => {
    const compose = yaml.safeLoad(read('compose.yml'));
    for (const name of ['traefik', 'mailtrain', 'migrate', 'secret-migrate', 'mariadb', 'redis', 'mongo']) {
        const service = compose.services[name];
        assert.equal(service.read_only, true, `${name} root filesystem must be read-only`);
        assert.deepEqual(service.cap_drop, ['ALL']);
        assert.equal(service.security_opt.includes('no-new-privileges:true'), true);
        assert.ok(service.pids_limit > 0);
        assert.ok(service.mem_limit);
        assert.ok(service.cpus);
        if (!['migrate', 'secret-migrate'].includes(name)) {
            assert.ok(service.healthcheck);
        }
        assert.match(service.image, /^\$\{[A-Z_]+_IMAGE:\?/);
    }
    assert.match(read('validate-env.sh'), /@sha256:\[0-9a-f\]\{64\}/);

    const filesInit = compose.services['files-init'];
    assert.deepEqual(filesInit.profiles, ['maintenance']);
    assert.equal(filesInit.user, '0:0');
    assert.equal(filesInit.read_only, true);
    assert.deepEqual(filesInit.cap_drop, ['ALL']);
    assert.deepEqual(filesInit.cap_add, ['CHOWN', 'DAC_OVERRIDE', 'FOWNER']);
    assert.deepEqual(filesInit.security_opt, ['no-new-privileges:true']);
    assert.deepEqual(filesInit.volumes, ['mailtrain-files:/app/server/files']);
    assert.equal(filesInit.network_mode, 'none');
    assert.ok(filesInit.pids_limit > 0 && filesInit.mem_limit && filesInit.cpus);
});

test('application health check authenticates to every runtime dependency', () => {
    const healthcheck = read('healthcheck.js');
    assert.match(healthcheck, /mysql2\/promise/);
    assert.match(healthcheck, /\['AUTH', configuration\.redis\.password\]/);
    assert.match(healthcheck, /MongoClient\.connect/);
    assert.match(healthcheck, /command\(\{ping: 1\}\)/);
    assert.match(healthcheck, /port: 3000/);
    assert.doesNotMatch(healthcheck, /console\.(?:log|error)|error\.message|error\.stack/);
});

test('runtime refuses pending migrations when startup DDL is disabled', async () => {
    await assert.rejects(
        () => assertRuntimeSchemaCurrent({list: async () => [[], [{file: 'pending.js'}]]}),
        error => error.code === 'EDBMIGRATIONREQUIRED'
    );
    await assertRuntimeSchemaCurrent({list: async () => [[], []]});
});

test('datastore credentials, TLS, and database duties are separated', () => {
    const composeSource = read('compose.yml');
    const bootstrap = read('mariadb-init.sh');
    const entrypoint = `${read('mailtrain-entrypoint.sh')}\n${read('render-config.js')}`;
    assert.match(composeSource, /redis_secret/);
    assert.match(composeSource, /mongo_secret/);
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

test('rendered app configuration enables production-safe session cookies', () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'mailtrain-render-config-'));
    const secretFile = path.join(directory, 'secret');
    const caFile = path.join(directory, 'db-ca');
    fs.writeFileSync(secretFile, '0123456789abcdef0123456789abcdef');
    fs.writeFileSync(caFile, 'synthetic-ca');
    const result = childProcess.spawnSync(process.execPath, [path.join(deploymentRoot, 'render-config.js')], {
        env: {
            ...process.env,
            MAILTRAIN_MODE: 'app',
            MAILTRAIN_DB_HOST: 'database',
            MAILTRAIN_DB_NAME: 'mailtrain',
            MAILTRAIN_DB_USER: 'mailtrain',
            MAILTRAIN_DB_SECRET_FILE: secretFile,
            MAILTRAIN_DB_CA_FILE: caFile,
            MAILTRAIN_SESSION_SECRET_FILE: secretFile,
            MAILTRAIN_REDIS_SECRET_FILE: secretFile,
            MAILTRAIN_MONGO_SECRET_FILE: secretFile,
            MAILTRAIN_MONGO_USER: 'mailtrain',
            MAILTRAIN_TRUSTED_HOST: 'trusted.example.test',
            MAILTRAIN_SANDBOX_HOST: 'sandbox.example.test',
            MAILTRAIN_PUBLIC_HOST: 'public.example.test',
            MAILTRAIN_CONFIG_OUTPUT_DIR: directory
        },
        encoding: 'utf8'
    });
    assert.equal(result.status, 0, result.stderr);
    const rendered = JSON.parse(fs.readFileSync(path.join(directory, 'production.json')));
    validateSessionSecurity({secret: rendered.www.secret, ...rendered.security.sessions}, {production: true});
    fs.rmSync(directory, {recursive: true, force: true});
});

test('Netcup upgrade path runs secret migration dry-run, migrate, and verify before runtime', () => {
    const compose = yaml.safeLoad(read('compose.yml'));
    assert.deepEqual(compose.services['secret-migrate'].profiles, ['migration']);
    assert.equal(compose.services['secret-migrate'].environment.MAILTRAIN_MODE, 'secrets');
    const runbook = read('README.md');
    for (const mode of ['dry-run', 'migrate', 'verify']) {
        assert.match(runbook, new RegExp(`secret-migrate ${mode}`));
    }
    assert.match(read('mailtrain-entrypoint.sh'), /security\/secret-migration\.js/);
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
    const gitignore = fs.readFileSync(path.join(repositoryRoot, '.gitignore'), 'utf8');
    for (const requirement of ['backup', 'restore', 'firewall', 'rollback', 'three distinct', 'no production migration']) {
        assert.match(runbook.toLowerCase(), new RegExp(requirement));
    }
    assert.match(gitignore, /deploy\/netcup\/\.env/);
    assert.match(gitignore, /deploy\/netcup\/secrets\//);
    assert.match(runbook, /--profile migration run --rm migrate/);
    assert.match(runbook, /--profile maintenance run --rm files-init/);
    assert.match(runbook, /credential rotation/i);
});

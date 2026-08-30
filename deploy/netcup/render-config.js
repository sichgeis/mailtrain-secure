'use strict';

const fs = require('fs');
const path = require('path');

function required(name) {
    const value = process.env[name];
    if (!value) {
        throw new Error(`${name} is required`);
    }
    return value;
}

function secret(filenameVariable) {
    const filename = required(filenameVariable);
    const stat = fs.statSync(filename);
    if (!stat.isFile() || stat.size < 1 || stat.size > 65536) {
        throw new Error(`${filenameVariable} must identify a bounded, non-empty regular file`);
    }
    return fs.readFileSync(filename, 'utf8').trim();
}

function hostname(name) {
    const value = required(name).toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(value)) {
        throw new Error(`${name} must be a DNS hostname`);
    }
    return value;
}

const mode = required('MAILTRAIN_MODE');
const configuration = {
    mysql: {
        host: required('MAILTRAIN_DB_HOST'),
        port: 3306,
        database: required('MAILTRAIN_DB_NAME'),
        user: required('MAILTRAIN_DB_USER'),
        password: secret('MAILTRAIN_DB_SECRET_FILE'),
        ssl: {
            ca: fs.readFileSync('/run/secrets/db_ca', 'utf8'),
            rejectUnauthorized: true
        }
    },
    security: {
        database: {runMigrationsAtStartup: false}
    },
    reports: {enabled: false, unsafeJavaScriptExecution: false}
};

if (mode === 'app') {
    const trustedHost = hostname('MAILTRAIN_TRUSTED_HOST');
    const sandboxHost = hostname('MAILTRAIN_SANDBOX_HOST');
    const publicHost = hostname('MAILTRAIN_PUBLIC_HOST');
    if (new Set([trustedHost, sandboxHost, publicHost]).size !== 3) {
        throw new Error('Trusted, sandbox, and public hostnames must be distinct');
    }
    const redisPassword = secret('MAILTRAIN_REDIS_SECRET_FILE');
    const mongoPassword = encodeURIComponent(secret('MAILTRAIN_MONGO_SECRET_FILE'));
    const mongoUser = encodeURIComponent(required('MAILTRAIN_MONGO_USER'));
    configuration.www = {
        host: '0.0.0.0',
        proxy: 1,
        secret: secret('MAILTRAIN_SESSION_SECRET_FILE'),
        trustedPort: 3000,
        sandboxPort: 3003,
        publicPort: 3004,
        trustedUrlBase: `https://${trustedHost}`,
        sandboxUrlBase: `https://${sandboxHost}`,
        publicUrlBase: `https://${publicHost}`
    };
    configuration.redis = {enabled: true, host: 'redis', port: 6379, db: 5, password: redisPassword};
    configuration.builtinZoneMTA = {
        enabled: true,
        mongo: `mongodb://${mongoUser}:${mongoPassword}@mongo:27017/zone-mta?authSource=zone-mta`,
        redis: `redis://:${encodeURIComponent(redisPassword)}@redis:6379/2`
    };
}

const outputDirectory = '/run/mailtrain-config';
fs.mkdirSync(outputDirectory, {recursive: true, mode: 0o700});
const output = path.join(outputDirectory, 'production.json');
fs.writeFileSync(output, `${JSON.stringify(configuration)}\n`, {mode: 0o600});

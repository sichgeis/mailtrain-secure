'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { fork } = require('node:child_process');
const test = require('node:test');
const nodemailer = require('nodemailer');

const enabled = process.env.ZONE_MTA_INTEGRATION === '1';

test('ZoneMTA starts against Mongo and Redis and authenticates an SMTP client', { skip: !enabled, timeout: 45_000 }, async t => {
    const root = path.resolve(__dirname, '..');
    const tempDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'mailtrain-zonemta-'));
    const configPath = path.join(tempDirectory, 'zonemta.json');
    const port = Number(process.env.ZONE_MTA_SMTP_PORT || 2526);
    const username = 'mailtrain-integration';
    const password = 'synthetic-integration-password';
    const config = {
        name: 'Mailtrain ZoneMTA integration',
        ident: 'mailtrain-integration',
        log: { level: 'error' },
        dbs: {
            mongo: process.env.ZONE_MTA_MONGO_URL || 'mongodb://127.0.0.1:27017/zone-mta-integration',
            redis: process.env.ZONE_MTA_REDIS_URL || 'redis://127.0.0.1:6379/15',
            sender: 'zone-mta-integration'
        },
        api: { maildrop: false },
        smtpInterfaces: {
            feeder: {
                enabled: true,
                processes: 1,
                maxSize: 1_048_576,
                host: '127.0.0.1',
                port,
                authentication: true,
                maxRecipients: 1,
                starttls: false,
                secure: false
            }
        },
        plugins: {
            'core/email-bounce': false,
            'core/http-bounce': false,
            'mailtrain-main': {
                enabled: ['main'],
                bounceUrl: 'http://127.0.0.1:1/webhooks/zone-mta',
                bounceToken: 'synthetic-bounce-token'
            },
            'mailtrain-receiver': {
                enabled: ['receiver'],
                username,
                password
            }
        },
        pools: { default: { address: '0.0.0.0', name: 'mailtrain-integration' } },
        zones: {
            default: {
                preferIPv6: false,
                ignoreIPv6: true,
                processes: 1,
                connections: 1,
                pool: 'default'
            }
        }
    };
    await fs.writeFile(configPath, JSON.stringify(config));

    const child = fork(path.join(root, 'index.js'), [`--config=${configPath}`], {
        cwd: root,
        silent: true,
        env: { ...process.env, NODE_ENV: 'test' }
    });
    let output = '';
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { output += chunk; });
    t.after(async () => {
        if (child.connected) {
            child.send('exit');
        }
        await Promise.race([
            new Promise(resolve => child.once('exit', resolve)),
            new Promise(resolve => setTimeout(() => {
                child.kill('SIGTERM');
                resolve();
            }, 5_000))
        ]);
        await fs.rm(tempDirectory, { recursive: true, force: true });
    });

    await new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`ZoneMTA did not start:\n${output}`)), 25_000);
        child.once('error', reject);
        child.once('exit', code => reject(new Error(`ZoneMTA exited with ${code}:\n${output}`)));
        child.on('message', message => {
            if (message && message.type === 'zone-mta-started') {
                clearTimeout(timer);
                resolve();
            }
        });
    });

    const transport = nodemailer.createTransport({
        host: '127.0.0.1',
        port,
        secure: false,
        ignoreTLS: true,
        auth: { user: username, pass: password }
    });
    assert.equal(await transport.verify(), true, output);
    transport.close();
});

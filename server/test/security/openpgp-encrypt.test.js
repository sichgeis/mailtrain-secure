'use strict';

const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const test = require('node:test');
const openpgp = require('openpgp');

const { OpenPgpTransform } = require('../../lib/openpgp-encrypt');

async function transformMessage(options, source) {
    const chunks = [];
    const transform = new OpenPgpTransform(options);
    transform.on('data', chunk => chunks.push(chunk));
    await new Promise((resolve, reject) => {
        transform.once('end', resolve);
        transform.once('error', reject);
        Readable.from([Buffer.from(source)]).pipe(transform);
    });
    return Buffer.concat(chunks).toString();
}

test('local OpenPGP adapter signs mail with the maintained OpenPGP API', async () => {
    const passphrase = 'synthetic-test-passphrase';
    const { privateKey } = await openpgp.generateKey({
        type: 'ecc',
        curve: 'curve25519Legacy',
        userIDs: [{ name: 'Mailtrain Test', email: 'mailtrain@example.test' }],
        passphrase
    });
    const source = [
        'From: mailtrain@example.test',
        'To: recipient@example.test',
        'Subject: OpenPGP regression',
        'Content-Type: text/plain; charset=utf-8',
        '',
        'Synthetic message body'
    ].join('\r\n');

    const result = await transformMessage({ signingKey: privateKey, passphrase }, source);

    assert.match(result, /Subject: OpenPGP regression/);
    assert.match(result, /Content-Type: multipart\/signed;/);
    assert.match(result, /-----BEGIN PGP SIGNATURE-----/);
    assert.match(result, /Synthetic message body/);
});

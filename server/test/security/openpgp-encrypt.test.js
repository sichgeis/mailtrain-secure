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

test('local OpenPGP adapter encrypts MIME content that the recipient can decrypt', async () => {
    const passphrase = 'synthetic-test-passphrase';
    const { privateKey, publicKey } = await openpgp.generateKey({
        type: 'ecc',
        curve: 'curve25519Legacy',
        userIDs: [{ name: 'Mailtrain Recipient', email: 'recipient@example.test' }],
        passphrase
    });
    const source = [
        'From: sender@example.test',
        'To: recipient@example.test',
        'Subject: Encrypted regression',
        'Content-Type: text/plain; charset=utf-8',
        'Content-Transfer-Encoding: 8bit',
        '',
        'Synthetic café message'
    ].join('\r\n');

    const result = await transformMessage({ encryptionKeys: [publicKey], shouldSign: false }, source);
    const armoredMessage = result.match(/-----BEGIN PGP MESSAGE-----[\s\S]+?-----END PGP MESSAGE-----/)[0];
    const encryptedMessage = await openpgp.readMessage({ armoredMessage });
    const decryptedKey = await openpgp.decryptKey({
        privateKey: await openpgp.readPrivateKey({ armoredKey: privateKey }),
        passphrase
    });
    const decrypted = await openpgp.decrypt({ message: encryptedMessage, decryptionKeys: decryptedKey });

    assert.match(result, /Content-Type: multipart\/encrypted;/);
    assert.match(decrypted.data, /Content-Transfer-Encoding: 8bit/);
    assert.match(decrypted.data, /Synthetic café message/);
});

test('local OpenPGP adapter fails closed for an invalid signing-key passphrase', async () => {
    const { privateKey } = await openpgp.generateKey({
        type: 'ecc',
        curve: 'curve25519Legacy',
        userIDs: [{ name: 'Mailtrain Test', email: 'mailtrain@example.test' }],
        passphrase: 'correct-passphrase'
    });

    await assert.rejects(
        transformMessage({ signingKey: privateKey, passphrase: 'wrong-passphrase' }, 'Subject: Test\r\n\r\nBody'),
        /passphrase|decrypt/i
    );
});

test('local OpenPGP adapter rejects oversized messages without retaining more chunks', async () => {
    const transform = new OpenPgpTransform({maxMessageBytes: 32});
    const error = await new Promise(resolve => {
        transform.once('error', resolve);
        transform.write(Buffer.alloc(24));
        transform.write(Buffer.alloc(24));
    });
    assert.equal(error.code, 'EPGPMESSAGESIZE');
    assert.ok(transform.length <= 32);
});

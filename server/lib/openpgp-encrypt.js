'use strict';

const crypto = require('crypto');
const { Transform } = require('stream');
const openpgp = require('openpgp');

// Nodemailer stream plugin for OpenPGP/MIME. This is intentionally local so
// Mailtrain can use the maintained OpenPGP API without the abandoned adapter's
// vulnerable, pinned dependency.
class OpenPgpTransform extends Transform {
    constructor(options) {
        super(options);
        this.options = options || {};
        this.chunks = [];
        this.length = 0;
    }

    _transform(chunk, encoding, callback) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
        this.chunks.push(buffer);
        this.length += buffer.length;
        callback();
    }

    _flush(callback) {
        this._transformMessage().then(message => {
            this.push(message);
            callback();
        }).catch(callback);
    }

    async _transformMessage() {
        const source = Buffer.concat(this.chunks, this.length);
        const encryptionKeys = await Promise.all((this.options.encryptionKeys || [])
            .map(armoredKey => openpgp.readKey({ armoredKey: armoredKey.toString() })));
        const shouldSign = this.options.shouldSign !== false;
        let signingKey;

        if (shouldSign && this.options.signingKey) {
            signingKey = await openpgp.readPrivateKey({ armoredKey: this.options.signingKey.toString() });
            if (this.options.passphrase) {
                signingKey = await openpgp.decryptKey({
                    privateKey: signingKey,
                    passphrase: this.options.passphrase
                });
            }
        }

        if (!encryptionKeys.length && (!shouldSign || !signingKey)) {
            return source;
        }

        const { headers, bodyHeaders, body } = splitMessage(source);
        const boundary = `mailtrain_${crypto.randomBytes(18).toString('hex')}`;
        const protectedBody = `${bodyHeaders}\r\n\r\n${body}`;

        if (!encryptionKeys.length) {
            const signature = await openpgp.sign({
                message: await openpgp.createMessage({ text: protectedBody }),
                signingKeys: signingKey,
                detached: true
            });

            return Buffer.from([
                headers,
                'Content-Type: multipart/signed; protocol="application/pgp-signature"; micalg=pgp-sha512;',
                ` boundary="${boundary}"`,
                'Content-Description: OpenPGP signed message',
                '',
                `--${boundary}`,
                protectedBody,
                `--${boundary}`,
                'Content-Type: application/pgp-signature',
                'Content-Disposition: inline; filename=signature.asc',
                '',
                signature,
                `--${boundary}--`,
                ''
            ].join('\r\n'));
        }

        const encryptionOptions = {
            message: await openpgp.createMessage({ text: protectedBody }),
            encryptionKeys
        };
        if (shouldSign && signingKey) {
            encryptionOptions.signingKeys = signingKey;
        }
        const encrypted = await openpgp.encrypt(encryptionOptions);

        return Buffer.from([
            headers,
            'Content-Type: multipart/encrypted; protocol="application/pgp-encrypted";',
            ` boundary="${boundary}"`,
            'Content-Description: OpenPGP encrypted message',
            'Content-Transfer-Encoding: 7bit',
            '',
            'This is an OpenPGP/MIME encrypted message',
            '',
            `--${boundary}`,
            'Content-Type: application/pgp-encrypted',
            'Content-Transfer-Encoding: 7bit',
            '',
            'Version: 1',
            '',
            `--${boundary}`,
            'Content-Type: application/octet-stream; name=encrypted.asc',
            'Content-Disposition: inline; filename=encrypted.asc',
            'Content-Transfer-Encoding: 7bit',
            '',
            encrypted,
            `--${boundary}--`,
            ''
        ].join('\r\n'));
    }
}

function splitMessage(source) {
    const parts = source.toString().split('\r\n\r\n');
    const rawHeaders = parts.shift() || '';
    const headers = [];
    const bodyHeaders = [];
    let target;

    for (const line of rawHeaders.split('\r\n')) {
        if (!/^\s/.test(line) || !target) {
            target = /^(content-type|content-transfer-encoding):/i.test(line) ? bodyHeaders : headers;
            target.push(line);
        } else {
            target[target.length - 1] += `\r\n${line}`;
        }
    }

    return {
        headers: headers.join('\r\n'),
        bodyHeaders: bodyHeaders.join('\r\n'),
        body: parts.join('\r\n\r\n')
    };
}

function openpgpEncrypt(options) {
    return (mail, callback) => {
        const encryptionKeys = mail.data.encryptionKeys;
        if ((!options.signingKey || mail.data.shouldSign === false) &&
            (!Array.isArray(encryptionKeys) || !encryptionKeys.length)) {
            return setImmediate(callback);
        }

        mail.message.transform(() => new OpenPgpTransform({
            signingKey: options.signingKey,
            passphrase: options.passphrase,
            encryptionKeys,
            shouldSign: mail.data.shouldSign
        }));
        setImmediate(callback);
    };
}

module.exports = { OpenPgpTransform, openpgpEncrypt };

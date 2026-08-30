'use strict';

const assert = require('node:assert/strict');
const {once} = require('node:events');
const {Writable} = require('node:stream');
const test = require('node:test');

const {formatCacheWriteFailure} = require('../../lib/file-cache-write-logging');

test('Node auto-destroys a Writable after successful finalization', async () => {
    const events = [];
    const writable = new Writable({
        write(chunk, encoding, callback) {
            callback();
        },
        final(callback) {
            events.push('final');
            callback();
        },
        destroy(err, callback) {
            events.push(`destroy:${err ? 'error' : 'normal'}`);
            callback(err);
        }
    });

    writable.end('cached response');
    await once(writable, 'close');

    assert.deepEqual(events, ['final', 'destroy:normal']);
});

test('cache-write failures are useful but redact credentials and subscriber data', () => {
    const error = new Error('insert failed for https://public.example/files/template/file/1/person@example.org?access_token=secret-value');
    error.code = 'ER_SYNTHETIC_CACHE_WRITE';

    const message = formatCacheWriteFailure('mosaico-images', error);

    assert.match(message, /mosaico-images/);
    assert.match(message, /ER_SYNTHETIC_CACHE_WRITE/);
    assert.match(message, /\[REDACTED\]/);
    assert.doesNotMatch(message, /person@example\.org|secret-value/);
});

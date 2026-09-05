'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const {cleanupUploadFiles} = require('../../lib/upload-cleanup');

test('upload cleanup removes temporary files but cannot remove durable paths', async () => {
    const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'mailtrain-upload-test-'));
    const temporary = path.join(directory, 'temporary');
    const outside = path.join(directory, 'durable', 'image');
    await fs.mkdir(path.dirname(outside));
    await fs.writeFile(temporary, 'synthetic');
    await fs.writeFile(outside, 'synthetic');
    try {
        await cleanupUploadFiles([{path: temporary}, {path: outside}], directory);
        await assert.rejects(fs.stat(temporary), {code: 'ENOENT'});
        assert.equal(await fs.readFile(outside, 'utf8'), 'synthetic');
        await cleanupUploadFiles([{path: temporary}], directory);
    } finally {
        await fs.rm(directory, {recursive: true});
    }
});

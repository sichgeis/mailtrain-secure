'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {inspectCacheEntry, shouldPersistCacheWrite} = require('../../lib/file-cache-integrity');

test('zero-byte cache responses are never eligible for persistence', () => {
    assert.equal(shouldPersistCacheWrite(0), false);
    assert.equal(shouldPersistCacheWrite(-1), false);
    assert.equal(shouldPersistCacheWrite(Number.NaN), false);
    assert.equal(shouldPersistCacheWrite(1), true);
});

test('cache-entry inspection accepts only matching non-empty regular files', async t => {
    const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailtrain-cache-integrity-'));
    t.after(() => fs.rm(cacheDir, {recursive: true, force: true}));

    const cacheFile = path.join(cacheDir, '41');
    await fs.writeFile(cacheFile, 'cached response');

    assert.deepEqual(await inspectCacheEntry({size: 15}, cacheFile), {valid: true});
    assert.deepEqual(await inspectCacheEntry({size: 0}, cacheFile), {valid: false, reason: 'empty'});
    assert.deepEqual(await inspectCacheEntry({size: 14}, cacheFile), {valid: false, reason: 'size-mismatch'});

    await fs.truncate(cacheFile, 0);
    assert.deepEqual(await inspectCacheEntry({size: 15}, cacheFile), {valid: false, reason: 'empty'});

    await fs.unlink(cacheFile);
    assert.deepEqual(await inspectCacheEntry({size: 15}, cacheFile), {valid: false, reason: 'missing'});
});

test('cache-entry inspection rejects symlinks without following them', async t => {
    const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailtrain-cache-integrity-'));
    const durableDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailtrain-cache-durable-'));
    t.after(() => fs.rm(cacheDir, {recursive: true, force: true}));
    t.after(() => fs.rm(durableDir, {recursive: true, force: true}));

    const durableFile = path.join(durableDir, 'original');
    const cacheFile = path.join(cacheDir, '41');
    await fs.writeFile(durableFile, 'must remain');
    await fs.symlink(durableFile, cacheFile);

    assert.deepEqual(await inspectCacheEntry({size: 11}, cacheFile), {valid: false, reason: 'not-regular'});
    assert.equal(await fs.readFile(durableFile, 'utf8'), 'must remain');
});

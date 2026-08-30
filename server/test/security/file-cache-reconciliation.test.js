'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {removeOrphanedCacheFiles} = require('../../lib/file-cache-reconciliation');

test('file-cache reconciliation removes unindexed files and preserves indexed files', async t => {
    const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailtrain-file-cache-'));
    t.after(() => fs.rm(cacheDir, {recursive: true, force: true}));

    await Promise.all([
        fs.writeFile(path.join(cacheDir, '41'), 'indexed'),
        fs.writeFile(path.join(cacheDir, '42'), 'indexed'),
        fs.writeFile(path.join(cacheDir, '1001'), 'orphaned'),
        fs.writeFile(path.join(cacheDir, 'unfinished-cache-file'), 'orphaned'),
        fs.mkdir(path.join(cacheDir, 'unexpected-directory'))
    ]);

    const result = await removeOrphanedCacheFiles(cacheDir, new Set(['41', '42']));

    assert.deepEqual(result, {removed: 2, skippedDirectories: 1, limitReached: false});
    assert.deepEqual((await fs.readdir(cacheDir)).sort(), ['41', '42', 'unexpected-directory']);
});

test('file-cache reconciliation unlinks symlinks instead of following them', async t => {
    const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailtrain-file-cache-'));
    const durableDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailtrain-durable-file-'));
    t.after(() => fs.rm(cacheDir, {recursive: true, force: true}));
    t.after(() => fs.rm(durableDir, {recursive: true, force: true}));

    const durableFile = path.join(durableDir, 'original');
    await fs.writeFile(durableFile, 'must remain');
    await fs.symlink(durableFile, path.join(cacheDir, '41'));

    const result = await removeOrphanedCacheFiles(cacheDir, new Set(['41']));

    assert.deepEqual(result, {removed: 1, skippedDirectories: 0, limitReached: false});
    assert.equal(await fs.readFile(durableFile, 'utf8'), 'must remain');
    await assert.rejects(fs.lstat(path.join(cacheDir, '41')), {code: 'ENOENT'});
});

test('file-cache reconciliation bounds cleanup work per pruning pass', async t => {
    const cacheDir = await fs.mkdtemp(path.join(os.tmpdir(), 'mailtrain-file-cache-'));
    t.after(() => fs.rm(cacheDir, {recursive: true, force: true}));

    await Promise.all([
        fs.writeFile(path.join(cacheDir, '1001'), 'orphaned'),
        fs.writeFile(path.join(cacheDir, '1002'), 'orphaned'),
        fs.writeFile(path.join(cacheDir, '1003'), 'orphaned')
    ]);

    const result = await removeOrphanedCacheFiles(cacheDir, new Set(), 1);

    assert.deepEqual(result, {removed: 1, skippedDirectories: 0, limitReached: true});
    assert.equal((await fs.readdir(cacheDir)).length, 2);
});

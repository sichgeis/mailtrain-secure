'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {ImageWorkPool} = require('../../lib/image-work-pool');

test('image transforms coalesce identical work and bound active and queued jobs', async () => {
    const pool = new ImageWorkPool({concurrency: 1, maxQueued: 1, timeoutMs: 1000});
    let finish;
    let calls = 0;
    const work = () => { calls++; return new Promise(resolve => { finish = resolve; }); };
    const first = pool.run('first', work);
    const duplicate = pool.run('first', work);
    const second = pool.run('second', () => 'second');
    await assert.rejects(pool.run('third', work), {status: 429});
    assert.equal(calls, 1);
    finish('first');
    assert.deepEqual(await Promise.all([first, duplicate, second]), ['first', 'first', 'second']);
    assert.equal(pool.active, 0);
});

test('disconnect cancellation and deadlines abort work without freeing a running slot prematurely', async () => {
    const pool = new ImageWorkPool({concurrency: 1, maxQueued: 1, timeoutMs: 10});
    const aborted = signal => new Promise((resolve, reject) => signal.addEventListener('abort', () => reject(signal.reason), {once: true}));
    await assert.rejects(pool.run('timeout', aborted), {status: 504});
    const controller = new AbortController();
    const pending = pool.run('cancelled', aborted, controller.signal);
    controller.abort();
    await assert.rejects(pending);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(pool.active, 0);
});

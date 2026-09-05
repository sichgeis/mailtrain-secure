const assert = require('node:assert/strict');
const test = require('node:test');
const {acceptEditorMessage, PendingEditorRequests} = require('../../shared/editor-messages');

test('editor messages require exact window, origin, and a valid payload', () => {
    const peer = {};
    const event = {source: peer, origin: 'https://sandbox.example', data: {type: 'rpcResponse', data: {msgId: 1, ret: 'html'}}};
    assert.equal(acceptEditorMessage(event, peer, event.origin), true);
    assert.equal(acceptEditorMessage({...event, source: {}}, peer, event.origin), false);
    assert.equal(acceptEditorMessage({...event, origin: 'https://evil.example'}, peer, event.origin), false);
    for (const data of [null, {}, {type: 'rpcResponse', data: {msgId: -1}}, {type: 'clientHeight', data: Infinity}]) {
        assert.equal(acceptEditorMessage({...event, data}, peer, event.origin), false);
    }
});

test('editor responses are isolated, single use, bounded, and cancellable', async () => {
    const requests = new PendingEditorRequests({maxPending: 1, timeoutMs: 1000});
    const other = new PendingEditorRequests();
    const pending = requests.wait(1);
    await assert.rejects(requests.wait(2), /capacity/);
    assert.equal(other.resolve(1, 'forged'), false);
    assert.equal(requests.resolve(1, 'real'), true);
    assert.equal(requests.resolve(1, 'replay'), false);
    assert.equal(await pending, 'real');
    const cancelled = requests.wait(3);
    requests.close();
    await assert.rejects(cancelled, /closed/);
    const timed = new PendingEditorRequests({timeoutMs: 5});
    await assert.rejects(timed.wait(1), /timed out/);
});

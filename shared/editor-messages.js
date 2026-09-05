'use strict';

function acceptEditorMessage(event, peer, origin) {
    if (!peer || event.source !== peer || event.origin !== new URL(origin).origin) return false;
    const message = event.data;
    if (!message || typeof message !== 'object') return false;
    const data = message.data;
    switch (message.type) {
        case 'initNeeded':
        case 'initAvailable':
            return true;
        case 'clientHeight':
            return Number.isFinite(data) && data >= 0 && data <= 20000;
        case 'accessToken':
            return typeof data === 'string' && data.length > 0 && data.length <= 128;
        case 'init':
            return !!data && typeof data.accessToken === 'string' && data.accessToken.length > 0 &&
                data.accessToken.length <= 128 && !!data.contentProps && typeof data.contentProps === 'object';
        case 'rpcRequest':
        case 'rpcResponse':
            return !!data && Number.isSafeInteger(data.msgId) && data.msgId > 0 &&
                (message.type === 'rpcResponse' || (typeof data.method === 'string' && data.method.length > 0 && data.method.length <= 100));
        default:
            return false;
    }
}

class PendingEditorRequests {
    constructor({maxPending = 100, timeoutMs = 30000} = {}) {
        this.entries = new Map();
        this.maxPending = maxPending;
        this.timeoutMs = timeoutMs;
    }

    wait(id) {
        if (this.entries.size >= this.maxPending || this.entries.has(id)) {
            return Promise.reject(new Error('Editor request capacity exceeded'));
        }
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this.entries.delete(id);
                reject(new Error('Editor request timed out'));
            }, this.timeoutMs);
            this.entries.set(id, {resolve, reject, timer});
        });
    }

    resolve(id, result) {
        const entry = this.entries.get(id);
        if (!entry) return false;
        this.entries.delete(id);
        clearTimeout(entry.timer);
        entry.resolve(result);
        return true;
    }

    close() {
        for (const entry of this.entries.values()) {
            clearTimeout(entry.timer);
            entry.reject(new Error('Editor closed'));
        }
        this.entries.clear();
    }
}

module.exports = {acceptEditorMessage, PendingEditorRequests};

'use strict';
/* global AbortController */

class ImageWorkPool {
    constructor({concurrency = 2, maxQueued = 20, timeoutMs = 30000} = {}) {
        if (![concurrency, maxQueued, timeoutMs].every(n => Number.isSafeInteger(n) && n > 0)) {throw new Error('Invalid image pool limits');}
        Object.assign(this, {concurrency, maxQueued, timeoutMs});
        this.active = 0;
        this.entries = new Map();
        this.queue = [];
    }

    run(key, work, signal) {
        if (signal && signal.aborted) {return Promise.reject(signal.reason);}
        let entry = this.entries.get(key);
        if (!entry) {
            if (this.active >= this.concurrency && this.queue.length >= this.maxQueued) {
                return Promise.reject(Object.assign(new Error('Image transformation capacity exceeded'), {status: 429}));
            }
            entry = {key, work, controller: new AbortController(), clients: new Set()};
            this.entries.set(key, entry);
            this.queue.push(entry);
            entry.timer = setTimeout(() => entry.controller.abort(Object.assign(new Error('Image transformation deadline exceeded'), {status: 504})), this.timeoutMs);
            entry.controller.signal.addEventListener('abort', () => {
                if (!entry.running) {
                    this.queue = this.queue.filter(item => item !== entry);
                    this.finish(entry, entry.controller.signal.reason);
                }
            }, {once: true});
        }
        if (entry.clients.size >= 100) {return Promise.reject(Object.assign(new Error('Too many image waiters'), {status: 429}));}
        const promise = new Promise((resolve, reject) => {
            const client = {resolve, reject};
            client.cleanup = () => { if (signal) {signal.removeEventListener('abort', cancel);} };
            function cancel() {
                client.cleanup();
                entry.clients.delete(client);
                reject(signal.reason);
                if (!entry.clients.size) {entry.controller.abort(signal.reason);}
            }
            entry.clients.add(client);
            if (signal) {signal.addEventListener('abort', cancel, {once: true});}
        });
        this.drain();
        return promise;
    }

    drain() {
        while (this.active < this.concurrency && this.queue.length) {
            const entry = this.queue.shift();
            entry.running = true;
            this.active++;
            Promise.resolve().then(() => {
                entry.controller.signal.throwIfAborted();
                return entry.work(entry.controller.signal);
            }).then(value => this.finish(entry, null, value), err => this.finish(entry, err)).finally(() => {
                this.active--;
                this.drain();
            });
        }
    }

    finish(entry, error, value) {
        clearTimeout(entry.timer);
        this.entries.delete(entry.key);
        for (const client of entry.clients) {
            client.cleanup();
            if (error) {client.reject(error);}
            else {client.resolve(value);}
        }
        entry.clients.clear();
    }
}

module.exports = {ImageWorkPool};

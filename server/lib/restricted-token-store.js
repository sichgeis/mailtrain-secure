'use strict';

class RestrictedTokenStore {
    constructor({ttlMs, maxEntries, maxPerUser, now = Date.now}) {
        if (![ttlMs, maxEntries, maxPerUser].every(value => Number.isInteger(value) && value > 0) || typeof now !== 'function') {
            throw new Error('Restricted token store configuration is invalid');
        }
        this.ttlMs = ttlMs;
        this.maxEntries = maxEntries;
        this.maxPerUser = maxPerUser;
        this.now = now;
        this.entries = new Map();
    }

    get size() {
        this.cleanup();
        return this.entries.size;
    }

    cleanup() {
        const now = this.now();
        for (const [token, entry] of this.entries) {
            if (entry.expires <= now) {
                this.entries.delete(token);
            }
        }
    }

    create(entry) {
        this.cleanup();
        let userTokenCount = 0;
        for (const existing of this.entries.values()) {
            if (existing.userId === entry.userId) {
                userTokenCount += 1;
            }
        }
        if (this.entries.size >= this.maxEntries || userTokenCount >= this.maxPerUser) {
            const error = new Error('Restricted access token capacity exceeded');
            error.status = 429;
            throw error;
        }
        const stored = {...entry, expires: this.now() + this.ttlMs};
        this.entries.set(stored.token, stored);
        return stored;
    }

    refresh(token, userId) {
        this.cleanup();
        const entry = this.entries.get(token);
        if (!entry || entry.userId !== userId) {
            return false;
        }
        entry.expires = this.now() + this.ttlMs;
        return true;
    }

    get(token) {
        this.cleanup();
        return this.entries.get(token);
    }
}

module.exports = {
    RestrictedTokenStore
};

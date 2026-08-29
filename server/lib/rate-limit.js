'use strict';

const redisScript = `
local current = redis.call('INCR', KEYS[1])
if current == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
local ttl = redis.call('PTTL', KEYS[1])
return {current, ttl}
`;

let configuredStore = new MemoryRateLimitStorePlaceholder();

function MemoryRateLimitStorePlaceholder() {
    this.consume = () => Promise.reject(new Error('Rate limit store has not been configured'));
}

class MemoryRateLimitStore {
    constructor({maxEntries = 10000, now = Date.now} = {}) {
        if (!Number.isInteger(maxEntries) || maxEntries <= 0 || typeof now !== 'function') {
            throw new Error('Memory rate-limit store configuration is invalid');
        }
        this.maxEntries = maxEntries;
        this.now = now;
        this.entries = new Map();
    }

    get size() {
        return this.entries.size;
    }

    async consume(key, {limit, windowMs}) {
        const now = this.now();
        let entry = this.entries.get(key);
        for (const [storedKey, storedEntry] of this.entries) {
            if (storedEntry.expiresAt <= now) {
                this.entries.delete(storedKey);
            }
        }
        if (!entry || entry.expiresAt <= now) {
            if (this.entries.size >= this.maxEntries) {
                const earliestExpiry = Math.min(...Array.from(this.entries.values(), item => item.expiresAt));
                return {allowed: false, remaining: 0, retryAfterMs: Math.max(1, earliestExpiry - now)};
            }
            entry = {count: 0, expiresAt: now + windowMs};
        }
        entry.count += 1;
        this.entries.delete(key);
        this.entries.set(key, entry);
        return {
            allowed: entry.count <= limit,
            remaining: Math.max(0, limit - entry.count),
            retryAfterMs: Math.max(0, entry.expiresAt - now)
        };
    }
}

class RedisRateLimitStore {
    constructor(client, {prefix = 'mailtrain:rate-limit:'} = {}) {
        this.client = client;
        this.prefix = prefix;
    }

    async consume(key, {limit, windowMs}) {
        const result = await new Promise((resolve, reject) => {
            this.client.eval(redisScript, 1, `${this.prefix}${key}`, windowMs, (error, value) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(value);
                }
            });
        });
        const count = Number(result[0]);
        return {
            allowed: count <= limit,
            remaining: Math.max(0, limit - count),
            retryAfterMs: Math.max(0, Number(result[1]))
        };
    }
}

function createRateLimitMiddleware({store, policy, key}) {
    if (!store || typeof store.consume !== 'function' || !policy || !Number.isInteger(policy.limit) || policy.limit <= 0 ||
        !Number.isInteger(policy.windowMs) || policy.windowMs <= 0 || typeof key !== 'function') {
        throw new Error('Rate-limit middleware configuration is invalid');
    }
    return async (req, res, next) => {
        try {
            const result = await store.consume(key(req), policy);
            res.setHeader('RateLimit-Limit', String(policy.limit));
            res.setHeader('RateLimit-Remaining', String(result.remaining));
            if (!result.allowed) {
                res.setHeader('Retry-After', String(Math.max(1, Math.ceil(result.retryAfterMs / 1000))));
                return res.status(429).json({message: 'Too many requests'});
            }
            next();
        } catch (err) {
            err.status = 503;
            next(err);
        }
    };
}

function configureRateLimitStore(store) {
    configuredStore = store;
}

function getRateLimitStore() {
    return configuredStore;
}

module.exports = {
    MemoryRateLimitStore,
    RedisRateLimitStore,
    configureRateLimitStore,
    createRateLimitMiddleware,
    getRateLimitStore,
    redisScript
};

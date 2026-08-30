'use strict';

const crypto = require('crypto');

function ledgerError(message, status) {
    const error = new Error(message);
    error.status = status;
    return error;
}

function deliveryHash(key) {
    return crypto.createHash('sha256').update(String(key)).digest();
}

class WebhookDeliveryLedger {
    constructor({knex, now = Date.now, leaseMs = 5 * 60 * 1000, retentionMs = 30 * 24 * 60 * 60 * 1000} = {}) {
        if (!knex || !Number.isSafeInteger(leaseMs) || leaseMs <= 0 || !Number.isSafeInteger(retentionMs) || retentionMs <= leaseMs) {
            throw new Error('Webhook delivery ledger configuration is invalid');
        }
        this.knex = knex;
        this.now = now;
        this.leaseMs = leaseMs;
        this.retentionMs = retentionMs;
    }

    async reserve(provider, key) {
        if (!/^[a-z0-9-]{1,32}$/.test(provider) || !key) {
            throw ledgerError('Webhook delivery identity is invalid', 400);
        }
        const hash = deliveryHash(key);
        const leaseId = crypto.randomBytes(16);
        const now = new Date(this.now());
        const leaseExpiresAt = new Date(now.getTime() + this.leaseMs);

        await this.knex('webhook_deliveries').whereNotNull('expires_at').andWhere('expires_at', '<=', now).del();

        return this.knex.transaction(async tx => {
            await tx('webhook_deliveries').insert({
                provider,
                delivery_hash: hash,
                state: 'processing',
                lease_id: leaseId,
                lease_expires_at: leaseExpiresAt
            }).onConflict(['provider', 'delivery_hash']).ignore();

            const row = await tx('webhook_deliveries').where({provider, delivery_hash: hash}).forUpdate().first();
            if (row.state === 'completed' && row.expires_at && new Date(row.expires_at) > now) {
                return this._reservation({provider, hash, leaseId: null, completed: true});
            }
            if (row.state === 'processing' && row.lease_id && !Buffer.from(row.lease_id).equals(leaseId) &&
                row.lease_expires_at && new Date(row.lease_expires_at) > now) {
                throw ledgerError('Webhook replay is already processing', 409);
            }
            if (!row.lease_id || !Buffer.from(row.lease_id).equals(leaseId)) {
                await tx('webhook_deliveries').where({provider, delivery_hash: hash}).update({
                    state: 'processing',
                    lease_id: leaseId,
                    lease_expires_at: leaseExpiresAt,
                    completed_at: null,
                    expires_at: null
                });
            }
            return this._reservation({provider, hash, leaseId, completed: false});
        });
    }

    _reservation({provider, hash, leaseId, completed}) {
        const ledger = this;
        return {
            completed,
            async commit() {
                if (completed) {
                    return;
                }
                const completedAt = new Date(ledger.now());
                const updated = await ledger.knex('webhook_deliveries').where({
                    provider,
                    delivery_hash: hash,
                    state: 'processing',
                    lease_id: leaseId
                }).update({
                    state: 'completed',
                    lease_id: null,
                    lease_expires_at: null,
                    completed_at: completedAt,
                    expires_at: new Date(completedAt.getTime() + ledger.retentionMs)
                });
                if (updated !== 1) {
                    throw ledgerError('Webhook delivery lease was lost before commit', 503);
                }
            },
            async rollback() {
                if (!completed) {
                    await ledger.knex('webhook_deliveries').where({
                        provider,
                        delivery_hash: hash,
                        state: 'processing',
                        lease_id: leaseId
                    }).del();
                }
            },
            async run(handler) {
                if (completed) {
                    return undefined;
                }
                try {
                    const result = await handler();
                    await this.commit();
                    return result;
                } catch (err) {
                    await this.rollback();
                    throw err;
                }
            }
        };
    }
}

module.exports = {WebhookDeliveryLedger};

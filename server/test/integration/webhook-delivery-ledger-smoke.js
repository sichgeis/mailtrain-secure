'use strict';

const assert = require('node:assert/strict');
const knex = require('../../lib/knex');
const {WebhookDeliveryLedger} = require('../../lib/webhook-delivery-ledger');

async function main() {
    let now = Date.parse('2026-08-30T12:00:00.000Z');
    const options = {knex, now: () => now, leaseMs: 100, retentionMs: 60 * 60 * 1000};
    const firstLedger = new WebhookDeliveryLedger(options);

    const failed = await firstLedger.reserve('postal', 'synthetic-delivery');
    await assert.rejects(() => failed.run(async () => {
        throw new Error('synthetic downstream failure');
    }), /downstream/);

    const retry = await new WebhookDeliveryLedger(options).reserve('postal', 'synthetic-delivery');
    let mutations = 0;
    await retry.run(async () => mutations++);
    const duplicateAfterRestart = await new WebhookDeliveryLedger(options).reserve('postal', 'synthetic-delivery');
    await duplicateAfterRestart.run(async () => mutations++);
    assert.equal(duplicateAfterRestart.completed, true);
    assert.equal(mutations, 1);

    const expired = await firstLedger.reserve('aws', 'synthetic-lease-race');
    now += 101;
    const replacement = await new WebhookDeliveryLedger(options).reserve('aws', 'synthetic-lease-race');
    await expired.rollback();
    await assert.rejects(() => firstLedger.reserve('aws', 'synthetic-lease-race'), /processing/i);
    await replacement.rollback();

    process.stdout.write('Webhook delivery ledger integration check passed\n');
}

main().then(() => knex.destroy()).catch(err => {
    process.stderr.write(`Webhook delivery ledger integration check failed: ${err.name || 'error'}\n`);
    knex.destroy().finally(() => process.exit(1));
});

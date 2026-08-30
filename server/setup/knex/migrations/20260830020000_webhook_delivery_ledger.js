'use strict';

exports.up = async knex => {
    if (!await knex.schema.hasTable('webhook_deliveries')) {
        await knex.raw(`CREATE TABLE \`webhook_deliveries\` (
            \`provider\` VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            \`delivery_hash\` BINARY(32) NOT NULL,
            \`state\` VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
            \`lease_id\` BINARY(16) NULL,
            \`lease_expires_at\` DATETIME(3) NULL,
            \`completed_at\` DATETIME(3) NULL,
            \`expires_at\` DATETIME(3) NULL,
            PRIMARY KEY (\`provider\`, \`delivery_hash\`),
            INDEX \`webhook_deliveries_expiry_idx\` (\`expires_at\`)
        ) ENGINE=InnoDB`);
    }
};

exports.down = async knex => {
    await knex.schema.dropTableIfExists('webhook_deliveries');
};

'use strict';

async function hasIndex(knex, table, index) {
    const result = await knex.raw('SHOW INDEX FROM ?? WHERE Key_name = ?', [table, index]);
    const rows = Array.isArray(result) && Array.isArray(result[0]) ? result[0] : result;
    return rows.length > 0;
}

exports.up = async knex => {
    if (!await knex.schema.hasColumn('send_configurations', 'mailer_secrets')) {
        await knex.schema.table('send_configurations', table => table.text('mailer_secrets', 'longtext').nullable());
    }
    if (!await knex.schema.hasColumn('settings', 'encrypted_value')) {
        await knex.schema.table('settings', table => table.text('encrypted_value', 'longtext').nullable());
    }
    if (!await knex.schema.hasColumn('users', 'access_token_hash')) {
        await knex.raw('ALTER TABLE `users` ADD COLUMN `access_token_hash` BINARY(32) NULL AFTER `access_token`');
    }
    if (!await knex.schema.hasColumn('users', 'access_token_key_id')) {
        await knex.raw('ALTER TABLE `users` ADD COLUMN `access_token_key_id` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER `access_token_hash`');
    }
    if (!await hasIndex(knex, 'users', 'users_access_token_hash_uq')) {
        await knex.raw('CREATE UNIQUE INDEX `users_access_token_hash_uq` ON `users` (`access_token_hash`)');
    }
    if (!await knex.schema.hasColumn('users', 'reset_token_hash')) {
        await knex.raw('ALTER TABLE `users` ADD COLUMN `reset_token_hash` BINARY(32) NULL AFTER `reset_token`');
    }
    if (!await knex.schema.hasColumn('users', 'reset_token_key_id')) {
        await knex.raw('ALTER TABLE `users` ADD COLUMN `reset_token_key_id` VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NULL AFTER `reset_token_hash`');
    }
    if (!await hasIndex(knex, 'users', 'users_reset_token_hash_idx')) {
        await knex.raw('CREATE INDEX `users_reset_token_hash_idx` ON `users` (`reset_token_key_id`, `reset_token_hash`, `reset_expire`)');
    }
};

exports.down = async knex => {
    if (await knex.schema.hasColumn('users', 'reset_token_hash')) {
        await knex.raw('DROP INDEX `users_reset_token_hash_idx` ON `users`');
        await knex.schema.table('users', table => table.dropColumn('reset_token_key_id'));
        await knex.schema.table('users', table => table.dropColumn('reset_token_hash'));
    }
    if (await knex.schema.hasColumn('users', 'access_token_hash')) {
        await knex.raw('DROP INDEX `users_access_token_hash_uq` ON `users`');
        await knex.schema.table('users', table => table.dropColumn('access_token_key_id'));
        await knex.schema.table('users', table => table.dropColumn('access_token_hash'));
    }
    if (await knex.schema.hasColumn('settings', 'encrypted_value')) {
        await knex.schema.table('settings', table => table.dropColumn('encrypted_value'));
    }
    if (await knex.schema.hasColumn('send_configurations', 'mailer_secrets')) {
        await knex.schema.table('send_configurations', table => table.dropColumn('mailer_secrets'));
    }
};

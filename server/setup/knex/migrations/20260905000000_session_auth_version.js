'use strict';

exports.up = knex => knex.schema.table('users', table => {
    table.integer('auth_version').unsigned().notNullable().defaultTo(0);
});

exports.down = knex => knex.schema.table('users', table => {
    table.dropColumn('auth_version');
});

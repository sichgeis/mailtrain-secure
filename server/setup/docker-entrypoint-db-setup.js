'use strict';

const log = require('../lib/log');
const dbcheck = require('../lib/dbcheck');
const knex = require('../lib/knex');
const {getAdminId} = require("../../shared/users");
const bluebird = require('bluebird');
const bcrypt = require('bcrypt-nodejs');
const bcryptHash = bluebird.promisify(bcrypt.hash.bind(bcrypt));
const {applyAdminBootstrap} = require('../lib/admin-bootstrap');
const {getStorage, lookupHash} = require('../lib/secret-storage');

async function init() {
    const hasUsersTable = await knex.schema.hasTable('users');
    const existingAdmin = hasUsersTable ? await knex('users').where({id: getAdminId()}).select('id').first() : null;

    await dbcheck();
    await knex.migrate.latest();

    const bootstrapped = await applyAdminBootstrap({
        existingAdmin,
        password: process.env.ADMIN_PASSWORD,
        accessToken: process.env.ADMIN_ACCESS_TOKEN,
        hashPassword: password => bcryptHash(password, null, null),
        hashAccessToken: token => ({
            hash: lookupHash(token, 'access-token'),
            keyId: getStorage({required: true}).keyId
        }),
        updateAdmin: fields => knex('users').where({id: getAdminId()}).update(fields)
    });
    if (bootstrapped) {
        log.info('Admin', 'Initialized administrator credentials for a fresh database');
    } else {
        log.info('Admin', 'Preserved existing administrator credentials');
    }

    process.exit(0);
}

init().catch(err => {log.error('', err); process.exit(1); });

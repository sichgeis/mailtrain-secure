'use strict';

const fs = require('fs');
const password = fs.readFileSync(process.env.MAILTRAIN_MONGO_SECRET_FILE, 'utf8').trim();
if (!/^[A-Za-z0-9_-]{32,}$/.test(password)) {
    throw new Error('Mongo application secret must be base64url text of at least 32 characters');
}
const target = db.getSiblingDB('zone-mta');
if (!target.getUser(process.env.MAILTRAIN_MONGO_USER)) {
    target.createUser({
        user: process.env.MAILTRAIN_MONGO_USER,
        pwd: password,
        roles: [{role: 'readWrite', db: 'zone-mta'}]
    });
}

'use strict';

const fs = require('fs');
const user = encodeURIComponent(process.env.MAILTRAIN_MONGO_USER);
const password = encodeURIComponent(fs.readFileSync(process.env.MAILTRAIN_MONGO_SECRET_FILE, 'utf8').trim());
const connection = new Mongo(`mongodb://${user}:${password}@127.0.0.1:27017/zone-mta?authSource=zone-mta`);
const result = connection.getDB('zone-mta').runCommand({ping: 1});
quit(result.ok ? 0 : 1);

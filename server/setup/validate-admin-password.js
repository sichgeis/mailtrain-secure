'use strict';

const {validateAdminPassword} = require('../lib/admin-bootstrap');

try {
    validateAdminPassword(process.env.ADMIN_PASSWORD);
} catch (err) {
    process.stderr.write(`Error: ${err.message}\n`);
    process.exitCode = 1;
}

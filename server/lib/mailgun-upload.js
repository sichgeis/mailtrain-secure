'use strict';

const multer = require('multer');

const mailgunFields = ['event', 'campaign_id', 'timestamp', 'token', 'signature'];

function createMailgunUpload({maxFields, maxFieldSize}) {
    const parse = multer({
        limits: {
            fields: maxFields,
            fieldSize: maxFieldSize,
            files: 0,
            parts: maxFields
        }
    }).fields([]);

    return (req, res, next) => parse(req, res, err => {
        if (err) {
            err.status = 413;
        }
        next(err);
    });
}

module.exports = {
    createMailgunUpload,
    mailgunFields
};

'use strict';

const passport = require('./passport');
const config = require('./config');
const fs = require('fs');
const {assertAggregateUploadSize} = require('./upload-limits');
const files = require('../models/files');

const path = require('path');
const uploadedFilesDir = path.join(files.filesDir, 'uploaded');
const {castToInteger} = require('./helpers');

const multer = require('multer')({
    dest: uploadedFilesDir,
    limits: {
        fileSize: config.security.uploads.maxFileSizeBytes,
        files: config.security.uploads.maxFiles,
        fields: 10,
        parts: config.security.uploads.maxFiles + 10
    }
});

function enforceAggregateUploadSize(req, res, next) {
    try {
        assertAggregateUploadSize(req.files, config.security.uploads.maxTotalBytes);
        next();
    } catch (err) {
        Promise.all((req.files || []).map(file => fs.promises.unlink(file.path).catch(() => undefined)))
            .then(() => next(err), next);
    }
}

function installUploadHandler(router, url, replacementBehavior, type, subType, transformResponseFn) {
    router.postAsync(url, passport.loggedIn, multer.array('files[]'), enforceAggregateUploadSize, async (req, res) => {
        return res.json(await files.createFiles(req.context, type || req.params.type, subType || req.params.subType, castToInteger(req.params.entityId), req.files, replacementBehavior, transformResponseFn));
    });
}

module.exports = {
    installUploadHandler,
    uploadedFilesDir
};

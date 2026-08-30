'use strict';

const passport = require('./passport');
const config = require('./config');
const {createAggregateDiskStorage} = require('./upload-limits');
const files = require('../models/files');

const path = require('path');
const uploadedFilesDir = path.join(files.filesDir, 'uploaded');
const {castToInteger} = require('./helpers');

const multer = require('multer')({
    storage: createAggregateDiskStorage({
        destination: uploadedFilesDir,
        maxTotalBytes: config.security.uploads.maxTotalBytes
    }),
    limits: {
        fileSize: config.security.uploads.maxFileSizeBytes,
        files: config.security.uploads.maxFiles,
        fields: 10,
        parts: config.security.uploads.maxFiles + 10
    }
});

function installUploadHandler(router, url, replacementBehavior, type, subType, transformResponseFn) {
    router.postAsync(url, passport.loggedIn, multer.array('files[]'), async (req, res) => {
        return res.json(await files.createFiles(req.context, type || req.params.type, subType || req.params.subType, castToInteger(req.params.entityId), req.files, replacementBehavior, transformResponseFn));
    });
}

module.exports = {
    installUploadHandler,
    uploadedFilesDir
};

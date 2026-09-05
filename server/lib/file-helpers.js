'use strict';

const passport = require('./passport');
const config = require('./config');
const {createAggregateDiskStorage} = require('./upload-limits');
const files = require('../models/files');
const {cleanupUploadFiles} = require('./upload-cleanup');

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
    const authorize = (req, res, next) => {
        Promise.resolve().then(() => files.authorizeUpload(req.context, type || req.params.type, subType || req.params.subType, castToInteger(req.params.entityId))).then(() => next(), next);
    };
    router.postAsync(url, passport.loggedIn, authorize, multer.array('files[]'), async (req, res) => {
        try {
            if (req.aborted) throw Object.assign(new Error('Upload aborted'), {status: 400});
            return res.json(await files.createFiles(req.context, type || req.params.type, subType || req.params.subType, castToInteger(req.params.entityId), req.files, replacementBehavior, transformResponseFn));
        } finally {
            await cleanupUploadFiles(req.files, uploadedFilesDir);
        }
    });
}

module.exports = {
    installUploadHandler,
    uploadedFilesDir
};

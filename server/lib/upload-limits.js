'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const {Transform, pipeline} = require('stream');

const requestBytes = Symbol('mailtrainUploadBytes');

function assertAggregateUploadSize(files, maxTotalBytes) {
    if (!Number.isSafeInteger(maxTotalBytes) || maxTotalBytes <= 0) {
        throw new Error('Aggregate upload limit is invalid');
    }
    const total = (files || []).reduce((sum, file) => sum + Number(file.size || 0), 0);
    if (!Number.isSafeInteger(total) || total > maxTotalBytes) {
        const error = new Error('Uploaded files exceed the configured aggregate size limit');
        error.code = 'LIMIT_TOTAL_FILE_SIZE';
        error.status = 413;
        throw error;
    }
}

function createAggregateDiskStorage({destination, maxTotalBytes}) {
    if (typeof destination !== 'string') {
        throw new Error('Upload destination is invalid');
    }
    fs.mkdirSync(destination, {recursive: true});
    return {
        _handleFile(req, file, callback) {
            req[requestBytes] = req[requestBytes] || 0;
            const filename = crypto.randomBytes(16).toString('hex');
            const filenamePath = path.join(destination, filename);
            file.destination = destination;
            file.filename = filename;
            file.path = filenamePath;
            file.mailtrainCleanupRequested = false;
            const output = fs.createWriteStream(filenamePath, {flags: 'wx', mode: 0o600});
            let fileSize = 0;
            const limiter = new Transform({
                transform(chunk, encoding, done) {
                    try {
                        assertAggregateUploadSize([
                            {size: req[requestBytes]},
                            {size: chunk.length}
                        ], maxTotalBytes);
                        req[requestBytes] += chunk.length;
                        fileSize += chunk.length;
                        return done(null, chunk);
                    } catch (err) {
                        return done(err);
                    }
                }
            });
            pipeline(file.stream, limiter, output, err => {
                if (err || file.mailtrainCleanupRequested) {
                    const completionError = err || Object.assign(new Error('Upload was aborted during storage'), {code: 'EUPLOADABORTED'});
                    fs.unlink(filenamePath, unlinkError => {
                        if (unlinkError && unlinkError.code !== 'ENOENT') {
                            return callback(unlinkError);
                        }
                        return callback(completionError);
                    });
                    return;
                }
                callback(null, {destination, filename, path: filenamePath, size: fileSize});
            });
        },
        _removeFile(req, file, callback) {
            file.mailtrainCleanupRequested = true;
            if (!file.path) {
                callback();
                return;
            }
            fs.unlink(file.path, err => callback(err && err.code !== 'ENOENT' ? err : null));
        }
    };
}

module.exports = {assertAggregateUploadSize, createAggregateDiskStorage};

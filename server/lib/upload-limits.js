'use strict';

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

module.exports = {assertAggregateUploadSize};

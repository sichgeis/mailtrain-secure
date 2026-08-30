'use strict';

const {redactLogMessage} = require('./log-redaction');

function formatCacheWriteFailure(typeId, err) {
    const rawCode = err && typeof err.code === 'string' ? err.code : 'UNKNOWN';
    const code = /^[A-Z0-9_.-]{1,64}$/i.test(rawCode) ? rawCode : 'UNKNOWN';
    const detail = redactLogMessage(err && err.message ? err.message : 'Unknown cache-write failure');
    return `Failed to persist ${typeId} cache entry (${code}): ${detail}`;
}

module.exports = {formatCacheWriteFailure};

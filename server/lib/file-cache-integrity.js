'use strict';

const fs = require('node:fs/promises');

function shouldPersistCacheWrite(size) {
    return Number.isSafeInteger(size) && size > 0;
}

async function inspectCacheEntry(fileEntry, filePath) {
    const indexedSize = Number(fileEntry && fileEntry.size);
    if (!Number.isSafeInteger(indexedSize)) {
        return {valid: false, reason: 'invalid-size'};
    }
    if (indexedSize <= 0) {
        return {valid: false, reason: 'empty'};
    }

    let fileStat;
    try {
        fileStat = await fs.lstat(filePath);
    } catch (err) {
        if (err.code === 'ENOENT') {
            return {valid: false, reason: 'missing'};
        }
        throw err;
    }

    if (!fileStat.isFile()) {
        return {valid: false, reason: 'not-regular'};
    }
    if (fileStat.size <= 0) {
        return {valid: false, reason: 'empty'};
    }
    if (fileStat.size !== indexedSize) {
        return {valid: false, reason: 'size-mismatch'};
    }

    return {valid: true};
}

module.exports = {inspectCacheEntry, shouldPersistCacheWrite};

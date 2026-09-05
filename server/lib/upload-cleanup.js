'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');

async function cleanupUploadFiles(files, directory) {
    await Promise.all((files || []).map(async file => {
        if (!file.path || path.dirname(path.resolve(file.path)) !== path.resolve(directory)) return;
        try {
            await fs.unlink(file.path);
        } catch (err) {
            if (err.code !== 'ENOENT') throw err;
        }
    }));
}

module.exports = {cleanupUploadFiles};

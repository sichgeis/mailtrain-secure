'use strict';

const fs = require('node:fs/promises');
const path = require('node:path');

async function removeOrphanedCacheFiles(cacheDir, indexedFileNames, maxRemovals = 1000) {
    let removed = 0;
    let skippedDirectories = 0;
    let limitReached = false;

    const directory = await fs.opendir(cacheDir);
    for await (const entry of directory) {
        if (entry.isDirectory()) {
            skippedDirectories += 1;
            continue;
        }

        // Cache entries are regular files named after their file_cache row ID.
        // Symlinks are never valid cache entries, even when their name is indexed.
        if (entry.isFile() && indexedFileNames.has(entry.name)) {
            continue;
        }

        try {
            await fs.unlink(path.join(cacheDir, entry.name));
            removed += 1;
            if (removed >= maxRemovals) {
                limitReached = true;
                break;
            }
        } catch (err) {
            if (err.code !== 'ENOENT') {
                throw err;
            }
        }
    }

    return {removed, skippedDirectories, limitReached};
}

module.exports = {removeOrphanedCacheFiles};

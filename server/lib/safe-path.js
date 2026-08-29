'use strict';

const fs = require('fs').promises;
const path = require('path');

function pathError() {
    const error = new Error('Requested path escapes the configured base directory');
    error.status = 400;
    return error;
}

function decodePath(value) {
    let decoded = String(value || '');
    for (let pass = 0; pass < 5; pass++) {
        let next;
        try {
            next = decodeURIComponent(decoded);
        } catch (err) {
            throw pathError();
        }
        if (next === decoded) {
            return decoded;
        }
        decoded = next;
    }
    throw pathError();
}

function isInside(base, target) {
    const relative = path.relative(base, target);
    return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

async function resolvePathWithinBase(basePath, untrustedPath) {
    const decoded = decodePath(untrustedPath);
    if (decoded.includes('\0') || path.posix.isAbsolute(decoded) || path.win32.isAbsolute(decoded)) {
        throw pathError();
    }

    const normalized = decoded.replace(/\\/g, '/');
    if (normalized.split('/').some(segment => segment === '..')) {
        throw pathError();
    }

    const realBase = await fs.realpath(basePath);
    const candidate = path.resolve(realBase, normalized);
    if (!isInside(realBase, candidate)) {
        throw pathError();
    }
    const realTarget = await fs.realpath(candidate);
    if (!isInside(realBase, realTarget)) {
        throw pathError();
    }
    return realTarget;
}

module.exports = {
    resolvePathWithinBase
};

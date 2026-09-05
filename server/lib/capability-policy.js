'use strict';

const {PermissionDeniedError} = require('../../shared/interoperable-errors');

const editorContentTypes = {
    mosaico: ['mosaico', 'mosaicoWithFsTemplate'],
    grapesjs: ['grapesjs'],
    ckeditor4: ['ckeditor4'],
    codeeditor: ['codeeditor']
};

function isEditorContentType(editorType, contentType) {
    return Object.hasOwn(editorContentTypes, editorType) && editorContentTypes[editorType].includes(contentType);
}

function enforceUnrestrictedIdentity(context) {
    const user = context && context.user;
    if (!user || user.restrictedAccessToken || user.restrictedAccessMethod || user.restrictedAccessHandler) {
        throw new PermissionDeniedError();
    }
}

function validateCapability(handler) {
    if (!handler || !handler.permissions || typeof handler.permissions !== 'object') {
        throw new PermissionDeniedError();
    }
    const entities = Object.entries(handler.permissions);
    if (!entities.length || handler.globalPermissions) {
        throw new PermissionDeniedError();
    }
    for (const [, entries] of entities) {
        if (!entries || typeof entries !== 'object' || !Object.keys(entries).length) {
            throw new PermissionDeniedError();
        }
        for (const [id, permissions] of Object.entries(entries)) {
            if (!/^[1-9][0-9]*$/.test(id) || !(permissions instanceof Set) || !permissions.size ||
                [...permissions].some(permission => typeof permission !== 'string' || !permission)) {
                throw new PermissionDeniedError();
            }
        }
    }
}

module.exports = {enforceUnrestrictedIdentity, validateCapability, isEditorContentType};

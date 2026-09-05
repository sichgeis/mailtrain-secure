'use strict';

const {PermissionDeniedError} = require('../../shared/interoperable-errors');

async function editorCapability(editorType, {entityTypeId, entityId}, context) {
    if (!['template', 'campaign'].includes(entityTypeId) || !Number.isSafeInteger(entityId) || entityId < 1) {
        throw new PermissionDeniedError();
    }
    // Load lazily: models register editor capabilities while the app is constructed.
    // eslint-disable-next-line global-require
    const model = entityTypeId === 'template' ? require('../models/templates') : require('../models/campaigns');
    // eslint-disable-next-line global-require
    const shares = require('../models/shares');
    const entity = await model.getById(context, entityId, false);
    const content = entityTypeId === 'template' ? entity : entity.data.sourceCustom;
    if (!content || content.type !== editorType) {
        throw new PermissionDeniedError();
    }
    const operations = new Set(['view']);
    for (const permission of ['viewFiles', 'manageFiles']) {
        // eslint-disable-next-line no-await-in-loop
        if (await shares.checkEntityPermission(context, entityTypeId, entityId, permission)) {
            operations.add(permission);
        }
    }
    const permissions = {[entityTypeId]: {[entityId]: operations}};
    const baseTemplate = content.data && content.data.mosaicoTemplate;
    if (editorType === 'mosaico' && baseTemplate) {
        await shares.enforceEntityPermission(context, 'mosaicoTemplate', baseTemplate, 'view');
        permissions.mosaicoTemplate = {[baseTemplate]: new Set(['view'])};
    }
    return {permissions};
}

module.exports = {editorCapability};

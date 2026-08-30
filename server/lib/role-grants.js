'use strict';

function isPermissionSubset(requestedPermissions = [], availablePermissions = []) {
    const available = availablePermissions instanceof Set ? availablePermissions : new Set(availablePermissions);
    return requestedPermissions.every(permission => available.has(permission));
}

function isRoleGrantWithinProfile(requestedProfile = {}, availableProfile = {}) {
    if (!isPermissionSubset(requestedProfile.permissions, availableProfile.permissions)) {
        return false;
    }

    const requestedChildren = requestedProfile.children || {};
    const availableChildren = availableProfile.children || {};

    for (const entityTypeId of Object.keys(requestedChildren)) {
        if (!isPermissionSubset(requestedChildren[entityTypeId], availableChildren[entityTypeId])) {
            return false;
        }
    }

    return true;
}

function globalRoleRequiresElevatedAssignment(roleSpec = {}) {
    return (roleSpec.permissions || []).length > 0 ||
        Boolean(roleSpec.ownNamespaceRole) ||
        Boolean(roleSpec.rootNamespaceRole) ||
        Object.keys(roleSpec.sharedNamespaces || {}).length > 0;
}

module.exports = {
    globalRoleRequiresElevatedAssignment,
    isPermissionSubset,
    isRoleGrantWithinProfile
};

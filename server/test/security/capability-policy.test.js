'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {enforceUnrestrictedIdentity, validateCapability, isEditorContentType} = require('../../lib/capability-policy');

test('account operations reject all restricted and missing identities', () => {
    for (const user of [undefined, {id: 7, restrictedAccessToken: 'cap'}, {id: 7, restrictedAccessMethod: 'editor'}, {id: 7, restrictedAccessHandler: {}}]) {
        assert.throws(() => enforceUnrestrictedIdentity({user}), /permission/i);
    }
    assert.doesNotThrow(() => enforceUnrestrictedIdentity({user: {id: 7}}));
});

test('editor type mapping permits only each editor and its explicit supported variants', () => {
    const expected = {
        mosaico: ['mosaico', 'mosaicoWithFsTemplate'],
        grapesjs: ['grapesjs'],
        ckeditor4: ['ckeditor4'],
        codeeditor: ['codeeditor']
    };
    for (const editor of [...Object.keys(expected), 'unknown', 'constructor', '__proto__']) {
        for (const content of ['mosaico', 'mosaicoWithFsTemplate', 'grapesjs', 'ckeditor4', 'codeeditor', 'unknown', null]) {
            assert.equal(isEditorContentType(editor, content), Object.hasOwn(expected, editor) && expected[editor].includes(content), `${editor}/${content}`);
        }
    }
});

test('capabilities fail closed for absent, empty, wildcard, or malformed permissions', () => {
    for (const handler of [undefined, null, {}, {permissions: {}}, {permissions: {template: true}}, {permissions: {template: {1: ['view']}}}]) {
        assert.throws(() => validateCapability(handler), /permission/i);
    }
    assert.doesNotThrow(() => validateCapability({permissions: {template: {1: new Set(['view'])}}}));
});
